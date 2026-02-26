import os
import json
from datetime import datetime
from core.state import MODE_FILE, JSON_FOLDER, CONFIG_FILE

def c_mode():

    try:

        if os.path.exists(MODE_FILE):
            with open(MODE_FILE, 'r') as f:
                data = json.load(f)

                pass
                return "" 
        return ""
    except Exception as e:
        pass
        return ""

def save_c_mode(mode):
    try:
        os.makedirs(JSON_FOLDER, exist_ok=True)
        mode_data = {
            'mode': mode,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'description': f'Controller last active in {mode.upper()} mode'
        }
        with open(MODE_FILE, 'w') as f:
            json.dump(mode_data, f, indent=4)
        print(f"Mode: {mode} saved")
        return True
    except Exception as e:
        print(f"Mode not saved: {e}")
        return False
        
def lc(self):
    os.makedirs(JSON_FOLDER, exist_ok=True)
    default_config = {"BIN_ID": "", "API_KEY": "", "URL": "", "DEVICE_IP": "N/A", "FERNET_KEY": ""}
    if not os.path.exists(CONFIG_FILE): 
        return default_config.copy()
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception: 
        return default_config.copy()

def sc(self):
    try:
        os.makedirs(JSON_FOLDER, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)
    except IOError as e:
        messagebox.showerror("Registry Error", f"Failed to record config: {e}")

def validate_startup(self):

    config_exists = os.path.exists(CONFIG_FILE)
        
    bin_id = self.config.get("BIN_ID", "").strip()
    api_key = self.config.get("API_KEY", "").strip()
    url = self.config.get("URL", "").strip()
    fernet_key = self.config.get("FERNET_KEY", "").strip()
        
    has_valid_credentials = bool(bin_id and api_key and url and fernet_key)
        
    if not config_exists or not has_valid_credentials:
        return self.show_first_run_wizard()
        
    return True