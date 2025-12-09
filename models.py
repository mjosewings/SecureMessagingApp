from dataclasses import dataclass, asdict
from typing import Optional
import json
from datetime import datetime

@dataclass
class CampusMessage:
    department: str
    role: str
    sender_message: str
    semester: str
    course_code: Optional[str] 
    message: str
    
    
def serialize_campus_message(msg: CampusMessage, client_id: Optional[str] = None) -> str:
    payload = {
        "context": asdict(msg),
        "client_id": client_id,
        "sent_at": datetime.utcnow().isoformat() + "Z"
    }
    return json.dumps(payload, separators=(',', ':'), ensure_ascii=False)