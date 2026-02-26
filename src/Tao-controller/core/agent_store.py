import os
import json
from datetime import datetime
from core.state import AGENTS_FILE, JSON_FOLDER

def load_agents(self):
    try:
        if os.path.exists(AGENTS_FILE):
            with open(AGENTS_FILE, 'r') as f:
                data = json.load(f)
                
                if not isinstance(data, list):
                    self._log_m("WARNING: agents.json corrupted, resetting...")
                    return []
                
                valid_agents = [agent for agent in data if isinstance(agent, dict)]
                
                if len(valid_agents) != len(data):
                    self._log_m(f"WARNING: Removed {len(data) - len(valid_agents)} invalid entries from agents.json")
                
                return valid_agents
        return []
    except json.JSONDecodeError as e:
        self._log_m(f"ERROR: agents.json is corrupted: {e}")
        if os.path.exists(AGENTS_FILE):
            backup_path = AGENTS_FILE + ".corrupted"
            try:
                import shutil
                shutil.copy(AGENTS_FILE, backup_path)
                self._log_m(f"Corrupted file backed up to: {backup_path}")
            except:
                pass
        return []
    except Exception as e:
        self._log_m(f"Error loading agents: {e}")
        return []

def save_agent(self, agent_data):

    try:

        if not isinstance(agent_data, dict):
            self._log_system(f"ERROR: agent_data must be dict, got {type(agent_data)}")
            return False
        
        agents = self.load_agents()
        
        if not isinstance(agents, list):
            self._log_system("ERROR: Loaded agents is not a list, resetting to empty")
            agents = []
        
        device_name = agent_data.get('device_name', '')
        device_ip = agent_data.get('device_ip', '')
        
        if not device_name or not device_ip:
            self._log_system("ERROR: Agent data missing device_name or device_ip")
            return False
        
        agent_id = device_name + "_" + device_ip
        
        filtered_agents = []
        for agent in agents:
            if isinstance(agent, dict):
                existing_id = agent.get('device_name', '') + "_" + agent.get('device_ip', '')
                if existing_id != agent_id:
                    filtered_agents.append(agent)
        
        agents = filtered_agents
        
        agent_data['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if os.path.exists(STATUS_FILE):
            try:
                with open(STATUS_FILE, 'r') as f:
                    audit_content = f.read()

                    os_match = re.search(r"OS Name:\s+(.*)", audit_content)
                    if os_match:
                        agent_data['os_version'] = os_match.group(1).strip()
            except:
                pass
        
        agents.append(agent_data)
        
        agents = agents[-50:]
        
        os.makedirs(JSON_FOLDER, exist_ok=True)
        with open(AGENTS_FILE, 'w') as f:
            json.dump(agents, f, indent=4)
        
        self._log_system(f"SYS: Agent registered: {agent_data.get('device_name', 'Unknown')}")
        return True
        
    except Exception as e:
        self._log_system(f"Error saving agent: {e}")
        import traceback
        self._log_system(traceback.format_exc())
        return False

def reset_agents_file(self):

    try:
        if os.path.exists(AGENTS_FILE):

            backup_path = AGENTS_FILE + f".backup_{int(time.time())}"
            import shutil
            shutil.copy(AGENTS_FILE, backup_path)
            self._log_m(f"Backed up to: {backup_path}")
        
        with open(AGENTS_FILE, 'w') as f:
            json.dump([], f, indent=4)
        
        self._log_m("SYS: agents.json reset successfully")
        return True
    except Exception as e:
        self._log_m(f"ERROR resetting agents.json: {e}")
        return False