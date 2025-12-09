from typing import List
from dataclasses import dataclass

@dataclass
class StoredMessage:
    client_id: str
    department: str
    course_code: str | None
    role: str
    sender_name: str
    message: str
    sent_at: str
    anomaly_score: float
    flagged: bool
    

class MessageStorage:
    def __init__(self):
        self._messages: List[StoredMessage] = []
        
    def add(self, m: StoredMessage):
        self._messages.append(m)
        
    def all(self) -> List[StoredMessage]:
        return self._messages
    

STORE = MessageStorage()