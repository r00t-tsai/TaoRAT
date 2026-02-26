import tkinter as tk
from tkinter import ttk, messagebox
import json
import socket
import os
from core.state import JSON_FOLDER

def get_icon_path():
    base_dir = os.environ.get('TAO_BASE_DIR')
    if not base_dir:
        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_file_dir, ".."))
    return os.path.join(base_dir, "ico", "ico.ico")


class AgentSettingsWindow:

    def __init__(self, parent, controller, agent_data):
        self.controller = controller
        self.agent_data = agent_data
        self.is_dns_agent = agent_data.get('dns_ready', False)

        self.window = tk.Toplevel(parent)
        self.window.title(f"Agent Settings - {agent_data.get('device_name')}")
        self.window.geometry("480x500")

        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            try:
                self.window.wm_iconbitmap(icon_path)
            except Exception:
                pass

        self.window.configure(bg="#0D0D0D")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.window.resizable(False, False)

        self._build_ui()

    def _build_ui(self):
        header = tk.Frame(self.window, bg="#2C1E1E", height=50)
        header.pack(fill="x", padx=5, pady=5)
        header.pack_propagate(False)

        mode_label = "Mode 2 — TUNNEL" if self.is_dns_agent else "Mode 1 — HTTP"
        tk.Label(header,
                 text=f"{self.agent_data.get('device_name')} Settings  [{mode_label}]",
                 bg="#2C1E1E", fg="#D9A86C",
                 font=("Arial", 13, "bold")).pack(side="left", padx=10, pady=10)

        bottom_frame = tk.Frame(self.window, bg="#0D0D0D")
        bottom_frame.pack(side="bottom", fill="x", padx=10, pady=10)

        tk.Button(bottom_frame, text="Close",
                  command=self.on_close,
                  bg="#666666", fg="white", font=("Arial", 9),
                  padx=10, pady=2).pack(anchor="center")

        container = tk.Frame(self.window, bg="#0D0D0D")
        container.pack(fill="both", expand=True, padx=5)

        canvas = tk.Canvas(container, bg="#0D0D0D", highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#0D0D0D")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=450)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        if self.is_dns_agent:
            self._build_dns_sections(scrollable_frame)
        else:
            self._build_http_sections(scrollable_frame)

    def _build_dns_sections(self, parent):
        raw_port = self.agent_data.get('dns_port', '53')
        if not str(raw_port).strip():
            raw_port = '53'

        dns_config = {
            'dns_domain':         self.agent_data.get('dns_domain',         'tunnel.local'),
            'dns_port':           raw_port,
            'dns_encryption_key': self.agent_data.get('dns_encryption_key', 'my_secret_dns_key_12345'),
        }

        dns_section = tk.LabelFrame(parent,
                                    text="DNS Configuration ",
                                    bg="#1A1212", fg="#D9A86C",
                                    font=("Arial", 11, "bold"))
        dns_section.pack(fill="x", padx=10, pady=(10, 5))

        port_frame = tk.Frame(dns_section, bg="#1A1212")
        port_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(port_frame, text="Port:", bg="#1A1212", fg="#F2E9E4",
                 font=("Arial", 10), width=15, anchor="w").pack(side="left")
        self.dns_port_var = tk.IntVar(value=int(dns_config['dns_port']))
        tk.Spinbox(port_frame, from_=1, to=65535, textvariable=self.dns_port_var,
                   bg="#0D0D0D", fg="#00FF00", font=("Consolas", 10),
                   width=10).pack(side="left", padx=5)

        domain_frame = tk.Frame(dns_section, bg="#1A1212")
        domain_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(domain_frame, text="Domain:", bg="#1A1212", fg="#F2E9E4",
                 font=("Arial", 10), width=15, anchor="w").pack(side="left")
        self.dns_domain_entry = tk.Entry(domain_frame, bg="#0D0D0D", fg="#00FF00",
                                          font=("Consolas", 10), insertbackground="white")
        self.dns_domain_entry.insert(0, dns_config['dns_domain'])
        self.dns_domain_entry.pack(side="left", fill="x", expand=True, padx=5)

        key_frame = tk.Frame(dns_section, bg="#1A1212")
        key_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(key_frame, text="Encryption Key:", bg="#1A1212", fg="#F2E9E4",
                 font=("Arial", 10), width=15, anchor="w").pack(side="left")
        self.dns_key_entry = tk.Entry(key_frame, bg="#0D0D0D", fg="#00FF00",
                                       font=("Consolas", 10), insertbackground="white",
                                       show="*")
        self.dns_key_entry.insert(0, dns_config['dns_encryption_key'])
        self.dns_key_entry.pack(side="left", fill="x", expand=True, padx=5)

        if self.controller.active_mode == "dns":
            tk.Button(dns_section, text="Update DNS Settings",
                      command=self.update_dns_config,
                      bg="#2196F3", fg="white", font=("Arial", 9, "bold"),
                      padx=15, pady=5).pack(pady=10)
        else:
            tk.Label(dns_section,
                     text="⚠ Must be in TUNNEL Mode to update DNS settings",
                     bg="#1A1212", fg="#FFA500",
                     font=("Arial", 9, "italic")).pack(pady=5)

        poll_section = tk.LabelFrame(parent,
                                      text="Poll & Sleep Settings ",
                                      bg="#1A1212", fg="#D9A86C",
                                      font=("Arial", 11, "bold"))
        poll_section.pack(fill="x", padx=10, pady=(10, 5))

        self._add_spinbox_row(poll_section, "Poll Duration (s):", "poll_duration_var",
                              default=1800, from_=10, to=3600, increment=10,
                              hint="Time to actively poll for commands")
        self._add_spinbox_row(poll_section, "Sleep Duration (s):", "sleep_duration_var",
                              default=180, from_=0, to=7200, increment=30,
                              hint="Time to sleep between poll cycles")
        self._add_spinbox_row(poll_section, "DNS Timeout (s):", "dns_timeout_var",
                              default=3600, from_=60, to=86400, increment=30,
                              hint="TUNNEL Mode timeout before fallback")

        if self.controller.active_mode == "dns":
            tk.Button(poll_section, text="Update Poll Settings",
                      command=self.update_dns_poll_settings,
                      bg="#4CAF50", fg="white", font=("Arial", 9, "bold"),
                      padx=15, pady=5).pack(pady=10)
        else:
            tk.Label(poll_section,
                     text="⚠ Must be in TUNNEL Mode to update poll settings",
                     bg="#1A1212", fg="#FFA500",
                     font=("Arial", 9, "italic")).pack(pady=5)


    def _build_http_sections(self, parent):

        poll_section = tk.LabelFrame(parent,
                                      text="Poll & Sleep Settings ",
                                      bg="#1A1212", fg="#D9A86C",
                                      font=("Arial", 11, "bold"))
        poll_section.pack(fill="x", padx=10, pady=(10, 5))

        self._add_spinbox_row(poll_section, "Poll Duration (s):", "poll_duration_var",
                              default=1800, from_=10, to=3600, increment=10,
                              hint="Time to actively poll for commands")
        self._add_spinbox_row(poll_section, "Sleep Duration (s):", "sleep_duration_var",
                              default=180, from_=0, to=7200, increment=30,
                              hint="Time to sleep between poll cycles")

        if self.controller.controller_state == "connected":
            tk.Button(poll_section, text="Update Poll Settings",
                      command=self.update_http_poll_settings,
                      bg="#4CAF50", fg="white", font=("Arial", 9, "bold"),
                      padx=15, pady=5).pack(pady=10)
        else:
            tk.Label(poll_section,
                     text="⚠ Must be CONNECTED to update poll settings",
                     bg="#1A1212", fg="#FFA500",
                     font=("Arial", 9, "italic")).pack(pady=5)

        creds_section = tk.LabelFrame(parent,
                                       text="JSONBin Credentials ",
                                       bg="#1A1212", fg="#D9A86C",
                                       font=("Arial", 11, "bold"))
        creds_section.pack(fill="x", padx=10, pady=(10, 5))

        bin_frame = tk.Frame(creds_section, bg="#1A1212")
        bin_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(bin_frame, text="Bin ID:", bg="#1A1212", fg="#F2E9E4",
                 font=("Arial", 10), width=15, anchor="w").pack(side="left")
        self.http_bin_entry = tk.Entry(bin_frame, bg="#0D0D0D", fg="#00FF00",
                                        font=("Consolas", 10), insertbackground="white")
        self.http_bin_entry.insert(0, self.agent_data.get('bin_id', ''))
        self.http_bin_entry.pack(side="left", fill="x", expand=True, padx=5)

        api_frame = tk.Frame(creds_section, bg="#1A1212")
        api_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(api_frame, text="API Key:", bg="#1A1212", fg="#F2E9E4",
                 font=("Arial", 10), width=15, anchor="w").pack(side="left")
        self.http_api_entry = tk.Entry(api_frame, bg="#0D0D0D", fg="#00FF00",
                                        font=("Consolas", 10), insertbackground="white",
                                        show="*")
        self.http_api_entry.insert(0, self.agent_data.get('api_key', ''))
        self.http_api_entry.pack(side="left", fill="x", expand=True, padx=5)

        url_frame = tk.Frame(creds_section, bg="#1A1212")
        url_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(url_frame, text="URL:", bg="#1A1212", fg="#F2E9E4",
                 font=("Arial", 10), width=15, anchor="w").pack(side="left")
        self.http_url_entry = tk.Entry(url_frame, bg="#0D0D0D", fg="#00FF00",
                                        font=("Consolas", 10), insertbackground="white")
        self.http_url_entry.insert(0, self.agent_data.get('url', ''))
        self.http_url_entry.pack(side="left", fill="x", expand=True, padx=5)

        if self.controller.controller_state == "connected":
            tk.Button(creds_section, text="Update JSONBin Credentials",
                      command=self.update_http_jsonbin_creds,
                      bg="#2196F3", fg="white", font=("Arial", 9, "bold"),
                      padx=15, pady=5).pack(pady=10)
        else:
            tk.Label(creds_section,
                     text="⚠ Must be CONNECTED to update credentials",
                     bg="#1A1212", fg="#FFA500",
                     font=("Arial", 9, "italic")).pack(pady=5)


    def _add_spinbox_row(self, parent, label, attr_name, default, from_, to, increment, hint=""):
        row = tk.Frame(parent, bg="#1A1212")
        row.pack(fill="x", padx=10, pady=5)
        tk.Label(row, text=label, bg="#1A1212", fg="#F2E9E4",
                 font=("Arial", 10), width=18, anchor="w").pack(side="left")
        var = tk.IntVar(value=default)
        setattr(self, attr_name, var)
        tk.Spinbox(row, from_=from_, to=to, textvariable=var,
                   bg="#0D0D0D", fg="#00FF00", font=("Consolas", 10),
                   width=10, increment=increment).pack(side="left", padx=5)
        if hint:
            tk.Label(row, text=hint, bg="#1A1212", fg="#888888",
                     font=("Arial", 8, "italic")).pack(side="left", padx=10)


    def update_dns_config(self):
        if self.controller.active_mode != "dns":
            messagebox.showerror("Error", "Must be in TUNNEL Mode to update DNS settings")
            return

        if not messagebox.askyesno("Confirm Update",
                                    f"Update DNS configuration for "
                                    f"{self.agent_data.get('device_name')}?"):
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            server_ip = s.getsockname()[0]
            s.close()
        except Exception:
            server_ip = "127.0.0.1"

        dns_config = {
            "server_ip":      server_ip,
            "domain":         self.dns_domain_entry.get().strip(),
            "port":           str(self.dns_port_var.get()),
            "encryption_key": self.dns_key_entry.get().strip(),
        }

        command = f"cmd--update-dns {json.dumps(dns_config, separators=(',', ':'))}"
        self.controller._log_m(
            f"Sending DNS config update to {self.agent_data.get('device_name')}...")

        if self.controller.dns_mode.dns_cmd(command):
            updated = self.agent_data.copy()
            updated['dns_domain']         = dns_config['domain']
            updated['dns_port']           = dns_config['port']
            updated['dns_encryption_key'] = dns_config['encryption_key']
            self.controller.save_agent(updated)
            self.controller._log_m("✓ DNS config updated successfully")
            messagebox.showinfo("Success", "DNS configuration updated")
        else:
            messagebox.showerror("Error", "Failed to send DNS config")

    def update_dns_poll_settings(self):
        if self.controller.active_mode != "dns":
            messagebox.showerror("Error", "Must be in TUNNEL Mode to update poll settings")
            return

        if not messagebox.askyesno("Confirm Update",
                                    f"Update poll settings for "
                                    f"{self.agent_data.get('device_name')}?"):
            return

        settings = {
            "poll_duration":  self.poll_duration_var.get(),
            "sleep_duration": self.sleep_duration_var.get(),
            "dns_timeout":    self.dns_timeout_var.get(),
            "dns_max_retries": 10,
        }

        command = f"cmd--settings {json.dumps(settings, separators=(',', ':'))}"
        self.controller._log_m(
            f"Sending poll settings to {self.agent_data.get('device_name')}...")

        if self.controller.dns_mode.dns_cmd(command):
            self.controller._log_m("SYS: Poll settings updated successfully")
            messagebox.showinfo("Success", "Poll settings updated")
        else:
            messagebox.showerror("Error", "Failed to send poll settings")

    def update_http_poll_settings(self):
        if self.controller.controller_state != "connected":
            messagebox.showerror("Error", "Must be CONNECTED to update poll settings")
            return

        if not messagebox.askyesno("Confirm Update",
                                    f"Update poll settings for "
                                    f"{self.agent_data.get('device_name')}?"):
            return

        settings = {
            "poll_duration":  self.poll_duration_var.get(),
            "sleep_duration": self.sleep_duration_var.get(),
        }

        command = f"cmd--settings {json.dumps(settings, separators=(',', ':'))}"
        self.controller._log_m(
            f"Sending HTTP poll settings to {self.agent_data.get('device_name')}...")

        if self.controller._send_http_cmd(command):
            self.controller._log_m("SYS: HTTP poll settings updated successfully")
            messagebox.showinfo("Success", "Poll settings sent to agent")
        else:
            messagebox.showerror("Error", "Failed to send poll settings")

    def update_http_jsonbin_creds(self):
        if self.controller.controller_state != "connected":
            messagebox.showerror("Error", "Must be CONNECTED to update credentials")
            return

        new_bin = self.http_bin_entry.get().strip()
        new_api = self.http_api_entry.get().strip()
        new_url = self.http_url_entry.get().strip()

        if not new_bin or not new_api or not new_url:
            messagebox.showerror("Validation Error",
                                  "All credential fields (Bin ID, API Key, URL) are required.")
            return

        if not messagebox.askyesno("Confirm Update",
                                    f"Update JSONBin credentials for "
                                    f"{self.agent_data.get('device_name')}?\n\n"
                                    "⚠ The agent will switch to the new endpoint immediately."):
            return

        creds = {"bin_id": new_bin, "api_key": new_api, "url": new_url}
        command = f"cmd--update-jsonbin {json.dumps(creds, separators=(',', ':'))}"
        self.controller._log_m(
            f"Sending JSONBin credential update to {self.agent_data.get('device_name')}...")

        if self.controller._send_http_cmd(command):
            updated = self.agent_data.copy()
            updated['bin_id']  = new_bin
            updated['api_key'] = new_api
            updated['url']     = new_url
            self.controller.save_agent(updated)
            self.controller._log_m("✓ JSONBin credentials update sent")
            messagebox.showinfo("Success",
                                 "Credential update sent.\n"
                                 "The agent will reconnect to the new endpoint.")
        else:
            messagebox.showerror("Error", "Failed to send credential update")

    def on_close(self):
        self.window.destroy()