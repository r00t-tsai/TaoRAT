import os
import threading
from enum import IntEnum

BASE_DIR        = os.environ.get('TAO_BASE_DIR', os.path.dirname(os.path.abspath(__file__)))
JSON_FOLDER     = os.path.join(BASE_DIR, "JSON")
OUTPUT_FOLDER   = os.path.join(BASE_DIR, "output")
CONFIG_FILE     = os.path.join(JSON_FOLDER, "config.json")
STATUS_FILE     = os.path.join(OUTPUT_FOLDER, "status.txt")
LOG_FILE        = os.path.join(OUTPUT_FOLDER, "log.txt")
TOOLS_CONFIG    = os.path.join(JSON_FOLDER, "tools_config.json")
MODE_FILE       = os.path.join(JSON_FOLDER, "mode.json")
AGENTS_FILE     = os.path.join(JSON_FOLDER, "agents.json")

class AgentMode(IntEnum):
    HTTP_UNSAVED = 0
    HTTP_SAVED   = 1
    DNS          = 2

class ActiveSession:
    _lock     = threading.Lock()
    _agent_id = None

    @classmethod
    def set(cls, agent_id):
        with cls._lock: cls._agent_id = agent_id

    @classmethod
    def get(cls):
        with cls._lock: return cls._agent_id

    @classmethod
    def is_active(cls, agent_id):
        with cls._lock: return cls._agent_id == agent_id