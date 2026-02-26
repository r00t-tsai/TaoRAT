import tkinter as tk
import os
from tkinter import ttk, messagebox

def get_icon_path():
    base_dir = os.environ.get('TAO_BASE_DIR')
    if not base_dir:
        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_file_dir, ".."))
    
    return os.path.join(base_dir, "ico", "ico.ico")

class AgentSelectorWindow:
    def __init__(self, parent, controller):
        self.controller = controller
        self.window = tk.Toplevel(parent)
        self.window.title("Select Agents")
        self.window.geometry("700x500")
        self.window.resizable(False, False)
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            try:
                self.window.wm_iconbitmap(icon_path)
            except Exception:
                pass
        self.window.configure(bg="#1A1212")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)

        self.selected_agent = None

        self._build_ui()
        self.refresh_agents()

    def _build_ui(self):

        header = tk.Frame(self.window, bg="#2C1E1E", height=50)
        header.pack(fill="x", padx=10, pady=(10, 5))
        header.pack_propagate(False)

        tk.Label(header, text="🌐 Available Agents", 
                bg="#2C1E1E", fg="#D9A86C",
                font=("Arial", 14, "bold")).pack(side="left", padx=10, pady=10)

        tk.Button(header, text="🔄 Refresh", command=self.refresh_agents,
                 bg="#4CAF50", fg="white", font=("Arial", 9, "bold"),
                 padx=10, pady=5).pack(side="right", padx=10)

        list_frame = tk.Frame(self.window, bg="#0D0D0D")
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")

        self.agent_listbox = tk.Listbox(
            list_frame,
            bg="#0D0D0D",
            fg="#F2E9E4",
            font=("Consolas", 10),
            selectmode=tk.SINGLE,
            yscrollcommand=scrollbar.set,
            highlightthickness=0,
            selectbackground="#A63429",
            selectforeground="white"
        )
        self.agent_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.agent_listbox.yview)

        self.agent_listbox.bind('<Double-Button-1>', lambda e: self.connect_selected())

        info_frame = tk.Frame(self.window, bg="#2C1E1E", height=80)
        info_frame.pack(fill="x", padx=10, pady=5)
        info_frame.pack_propagate(False)

        self.info_label = tk.Label(info_frame, 
                                   text="ℹ️ Select an agent and click Connect\nDouble-click to connect quickly",
                                   bg="#2C1E1E", fg="#888888",
                                   font=("Arial", 9), justify="left")
        self.info_label.pack(anchor="w", padx=10, pady=10)

        btn_frame = tk.Frame(self.window, bg="#1A1212")
        btn_frame.pack(fill="x", padx=10, pady=(5, 10))

        self.connect_btn = tk.Button(btn_frame, text="SYS: Connect to Selected Agent",
                                     command=self.connect_selected,
                                     bg="#4CAF50", fg="white",
                                     font=("Arial", 10, "bold"),
                                     padx=20, pady=8, state="disabled")
        self.connect_btn.pack(side="left", padx=5)

        tk.Button(btn_frame, text="Cancel", command=self.on_close,
                 bg="#666666", fg="white", font=("Arial", 10, "bold"),
                 padx=20, pady=8).pack(side="right", padx=5)

        self.agent_listbox.bind('<<ListboxSelect>>', self.on_select)

    def refresh_agents(self):
        self.agent_listbox.delete(0, tk.END)
        agents = self.controller.load_agents()

        if not agents:
            self.agent_listbox.insert(tk.END, "SYS: No agents found. Poll HTTP C2 first.")
            self.info_label.config(text="SYS:️ No agents discovered yet.\nUse HTTP mode to discover agents first.")
            return

        for agent in agents:
            device_name = agent.get('device_name', 'Unknown')
            device_ip = agent.get('device_ip', 'N/A')
            last_seen = agent.get('last_seen', 'Never')
            dns_ready = "SYS: DNS" if agent.get('dns_ready') else "✗ HTTP Only"

            display_text = f"{device_name:20} | IP: {device_ip:15} | {dns_ready:12} | Last: {last_seen}"
            self.agent_listbox.insert(tk.END, display_text)

        self.info_label.config(text=f"ℹ️ {len(agents)} agent(s) available\nSelect one to establish DNS connection")

    def on_select(self, event):

        selection = self.agent_listbox.curselection()
        if selection:
            self.connect_btn.config(state="normal")
        else:
            self.connect_btn.config(state="disabled")

    def connect_selected(self):

        selection = self.agent_listbox.curselection()
        if not selection:
            return

        index = selection[0]
        agents = self.controller.load_agents()

        if index >= len(agents):
            self.controller._log_m("ERROR: Invalid selection")
            return

        self.selected_agent = agents[index]

        self.window.destroy()
        self.controller.connect_to_dns_agent(self.selected_agent)

    def on_close(self):
        self.selected_agent = None
        self.window.destroy()

class DNSConfigWindow:

    def __init__(self, parent, controller, agent_data):
        self.controller = controller
        self.agent_data = agent_data
        self.confirmed = False

        self.window = tk.Toplevel(parent)
        self.window.title("Configure DNS Settings")
        self.window.geometry("500x450")
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            try:
                self.window.wm_iconbitmap(icon_path)
            except Exception:
                pass
        self.window.resizable(False, False)
        self.window.configure(bg="#1A1212")
        self.window.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.window.transient(parent)
        self.window.grab_set()

        self._build_ui()

    def _build_ui(self):

        header = tk.Frame(self.window, bg="#2C1E1E", height=50)
        header.pack(fill="x", padx=10, pady=(10, 5))
        header.pack_propagate(False)

        tk.Label(header, text="DNS Configuration", 
                bg="#2C1E1E", fg="#D9A86C",
                font=("Arial", 14, "bold")).pack(side="left", padx=10, pady=10)

        info_frame = tk.Frame(self.window, bg="#1A1212")
        info_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(info_frame, text=f"Target Agent: {self.agent_data.get('device_name')}", 
                bg="#1A1212", fg="#F2E9E4",
                font=("Arial", 10, "bold")).pack(anchor="w")
        tk.Label(info_frame, text=f"IP: {self.agent_data.get('device_ip')}", 
                bg="#1A1212", fg="#888888",
                font=("Arial", 9)).pack(anchor="w")

        config_frame = tk.LabelFrame(self.window, text=" DNS Settings ", 
                                     bg="#2C1E1E", fg="#D9A86C",
                                     font=("Arial", 10, "bold"))
        config_frame.pack(fill="both", expand=True, padx=10, pady=10)

        port_frame = tk.Frame(config_frame, bg="#2C1E1E")
        port_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(port_frame, text="Port:", bg="#2C1E1E", fg="#F2E9E4",
                font=("Arial", 10), width=15, anchor="w").pack(side="left")

        self.port_var = tk.IntVar(value=53)
        tk.Spinbox(port_frame, from_=1, to=65535, textvariable=self.port_var,
                  bg="#0D0D0D", fg="#00FF00", font=("Consolas", 10),
                  width=10).pack(side="left", padx=5)

        tk.Label(port_frame, text="(Recommended: 53, 5353)", 
                bg="#2C1E1E", fg="#888888",
                font=("Arial", 8, "italic")).pack(side="left", padx=5)

        domain_frame = tk.Frame(config_frame, bg="#2C1E1E")
        domain_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(domain_frame, text="Domain:", bg="#2C1E1E", fg="#F2E9E4",
                font=("Arial", 10), width=15, anchor="w").pack(side="left")

        self.domain_entry = tk.Entry(domain_frame, bg="#0D0D0D", fg="#00FF00",
                                     font=("Consolas", 10), insertbackground="white")
        self.domain_entry.insert(0, "tunnel.local")
        self.domain_entry.pack(side="left", fill="x", expand=True, padx=5)

        protocol_frame = tk.Frame(config_frame, bg="#2C1E1E")
        protocol_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(protocol_frame, text="Protocol:", bg="#2C1E1E", fg="#F2E9E4",
                font=("Arial", 10), width=15, anchor="w").pack(side="left")

        self.protocol_var = tk.StringVar(value="UDP")

        tk.Radiobutton(protocol_frame, text="UDP - This is the current supported Protocol.", variable=self.protocol_var,
                      value="UDP", bg="#2C1E1E", fg="#F2E9E4",
                      selectcolor="#1A1212", activebackground="#2C1E1E",
                      font=("Arial", 9)).pack(side="left", padx=5)

        key_frame = tk.Frame(config_frame, bg="#2C1E1E")
        key_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(key_frame, text="Encryption Key:", bg="#2C1E1E", fg="#F2E9E4",
                font=("Arial", 10), width=15, anchor="w").pack(side="left")

        self.key_entry = tk.Entry(key_frame, bg="#0D0D0D", fg="#00FF00",
                                  font=("Consolas", 10), insertbackground="white",
                                  show="*")
        self.key_entry.insert(0, "my_secret_dns_key_12345")
        self.key_entry.pack(side="left", fill="x", expand=True, padx=5)

        info_label = tk.Label(config_frame, 
                             text="ℹ️ These settings will be sent to the agent\nand saved for this connection",
                             bg="#2C1E1E", fg="#888888",
                             font=("Arial", 9), justify="left")
        info_label.pack(pady=10)

        btn_frame = tk.Frame(self.window, bg="#1A1212")
        btn_frame.pack(fill="x", padx=10, pady=(5, 10))

        tk.Button(btn_frame, text="Confirm & Connect",
                 command=self.on_confirm,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"),
                 padx=20, pady=8).pack(side="left", padx=5)

        tk.Button(btn_frame, text="Cancel",
                 command=self.on_cancel,
                 bg="#666666", fg="white", font=("Arial", 10, "bold"),
                 padx=20, pady=8).pack(side="right", padx=5)

    def on_confirm(self):

        self.confirmed = True

        self.dns_config = {
            'port': str(self.port_var.get()),
            'domain': self.domain_entry.get().strip(),
            'protocol': self.protocol_var.get(),
            'encryption_key': self.key_entry.get().strip()
        }

        self.window.destroy()

    def on_cancel(self):
        self.confirmed = False
        self.window.destroy()