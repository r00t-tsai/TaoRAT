import threading

class ActiveSession:
    """Singleton that tracks which agent ID currently owns the command channel."""
    _lock  = threading.Lock()
    _agent_id: str | None = None

    @classmethod
    def set(cls, agent_id: str | None):
        with cls._lock:
            cls._agent_id = agent_id

    @classmethod
    def get(cls) -> str | None:
        with cls._lock:
            return cls._agent_id

    @classmethod
    def is_active(cls, agent_id: str) -> bool:
        with cls._lock:
            return cls._agent_id == agent_id