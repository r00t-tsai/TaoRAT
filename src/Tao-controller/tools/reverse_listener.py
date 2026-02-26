import socket
import threading
import time


class ReverseTCPListener:
    """Robust reverse TCP listener for agent callbacks.

    Improvements over the original
    --------------------------------
    - Port-in-use detection with clear error message (OSError EADDRINUSE).
    - Stale-connection guard: verifies the accepted socket is alive before
      signalling success (sends a 1-byte probe and checks for immediate close).
    - Thread-safe stop(): can be called from any thread at any time without
      racing against _accept_loop.
    - wait_for_connection() returns None cleanly on timeout instead of
      potentially returning a half-open socket.
    - get_local_ip() tries multiple candidates and never raises.
    - All sockets are closed deterministically in finally blocks.
    - _stopped flag prevents log spam if stop() is called before accept fires.
    """

    def __init__(self, port: int, timeout: int = 30, log_fn=None):
        self.port    = port
        self.timeout = timeout
        self._log    = log_fn or print

        self._server_sock: socket.socket | None = None
        self._client_sock: socket.socket | None = None
        self._client_addr = None

        self._connected_event = threading.Event()
        self._stopped_event   = threading.Event()   # set when stop() is called
        self._lock            = threading.Lock()    # guards socket references
        self._thread: threading.Thread | None = None

    # ── Public API ────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Bind, listen, and spawn the accept thread.

        Returns True on success, False if the port is unavailable or another
        error occurs.  A specific error message is logged in either case.
        """
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                srv.bind(("0.0.0.0", self.port))
            except OSError as e:
                # Surface port-in-use as a distinct, actionable message
                if e.errno in (98, 48, 10048):  # EADDRINUSE on Linux/Mac/Win
                    self._log(
                        f"REVERSE: Port {self.port} is already in use — "
                        "close the existing listener or choose a different port"
                    )
                else:
                    self._log(f"REVERSE: Bind failed on port {self.port}: {e}")
                srv.close()
                return False

            srv.listen(1)
            srv.settimeout(self.timeout)

            with self._lock:
                self._server_sock = srv

            self._log(
                f"REVERSE: Listening on 0.0.0.0:{self.port} "
                f"(timeout={self.timeout}s)"
            )
            self._thread = threading.Thread(
                target=self._accept_loop, daemon=True, name=f"ReverseListener-{self.port}"
            )
            self._thread.start()
            return True

        except Exception as e:
            self._log(f"REVERSE: Failed to start listener on port {self.port}: {e}")
            return False

    def wait_for_connection(self) -> "socket.socket | None":
        """Block until an agent connects or the timeout expires.

        Returns the connected socket on success, or None on timeout / stop.
        The caller owns the returned socket and is responsible for closing it.
        """
        # Wait slightly longer than the server timeout so the accept thread
        # always fires first and can log its own message before we give up.
        signalled = self._connected_event.wait(timeout=self.timeout + 3)

        with self._lock:
            sock = self._client_sock

        if not signalled or sock is None:
            self._log(
                f"REVERSE: wait_for_connection timed out — "
                f"no agent called back on port {self.port}"
            )
            return None

        # Final liveness check: make sure the socket didn't close between
        # accept() and now (race between agent connecting and immediately dying).
        if not self._is_socket_alive(sock):
            self._log("REVERSE: Accepted socket is no longer alive — rejecting")
            with self._lock:
                self._client_sock = None
            try:
                sock.close()
            except Exception:
                pass
            return None

        return sock

    def stop(self):
        """Forcefully shut down the listener and any accepted connection."""
        self._stopped_event.set()
        self._close_server()

        with self._lock:
            cli = self._client_sock
            self._client_sock = None

        if cli:
            try:
                cli.shutdown(socket.SHUT_RDWR)
                cli.close()
            except Exception:
                pass

    @staticmethod
    def get_local_ip() -> str:
        """Return the best outbound IP of this machine.

        Tries several well-known external addresses so it works even when
        there is no actual internet access (the UDP connect never sends data).
        Falls back gracefully through hostname resolution and finally 127.0.0.1.
        """
        candidates = [
            ("8.8.8.8",   80),   # Google DNS
            ("1.1.1.1",   80),   # Cloudflare DNS
            ("10.255.255.255", 1),  # RFC1918 probe (LAN preference)
        ]
        for host, port in candidates:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1)
                s.connect((host, port))
                ip = s.getsockname()[0]
                s.close()
                if ip and not ip.startswith("127."):
                    return ip
            except Exception:
                pass

        # Last resort: hostname lookup
        try:
            ip = socket.gethostbyname(socket.gethostname())
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass

        return "127.0.0.1"

    # ── Internal helpers ──────────────────────────────────────────────────

    def _accept_loop(self):
        try:
            with self._lock:
                srv = self._server_sock

            if srv is None or self._stopped_event.is_set():
                return

            cli, addr = srv.accept()   # blocks until connect or timeout

            if self._stopped_event.is_set():
                # stop() was called while we were waiting — discard the socket
                try:
                    cli.close()
                except Exception:
                    pass
                return

            # Configure the accepted socket
            cli.settimeout(None)
            cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            cli.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            if hasattr(socket, "SIO_KEEPALIVE_VALS"):        # Windows
                try:
                    cli.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 10_000, 3_000))
                except Exception:
                    pass

            with self._lock:
                self._client_sock = cli
                self._client_addr = addr

            self._log(
                f"REVERSE: Agent connected from {addr[0]}:{addr[1]} "
                f"on port {self.port}"
            )
            self._connected_event.set()

        except socket.timeout:
            if not self._stopped_event.is_set():
                self._log(
                    f"REVERSE: Timed out after {self.timeout}s — "
                    f"no agent called back on port {self.port}"
                )
        except OSError as e:
            # Raised when _close_server() shuts the socket while accept() waits
            if not self._stopped_event.is_set():
                self._log(f"REVERSE: Accept error on port {self.port}: {e}")
        except Exception as e:
            if not self._stopped_event.is_set():
                self._log(f"REVERSE: Unexpected error in accept loop: {e}")
        finally:
            self._close_server()

    def _close_server(self):
        with self._lock:
            srv = self._server_sock
            self._server_sock = None

        if srv:
            try:
                srv.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                srv.close()
            except Exception:
                pass

    @staticmethod
    def _is_socket_alive(sock: socket.socket) -> bool:
        """Non-destructive liveness probe using MSG_PEEK."""
        try:
            sock.settimeout(0.0)
            data = sock.recv(1, socket.MSG_PEEK)
            sock.settimeout(None)
            # Empty recv with MSG_PEEK means the remote closed gracefully
            return len(data) > 0
        except BlockingIOError:
            # No data available yet but socket is open — this is the good case
            sock.settimeout(None)
            return True
        except Exception:
            sock.settimeout(None)
            return False