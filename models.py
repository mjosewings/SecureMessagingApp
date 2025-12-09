
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, Index
from server.db import Base

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    client_id   = Column(String, nullable=False, index=True)

    # Campus context
    department  = Column(String, nullable=False, index=True)
    role        = Column(String, nullable=False, index=True)
    sender_name = Column(String, nullable=False, index=True)
    semester    = Column(String, nullable=False, index=True)
    course_code = Column(String, nullable=True, index=True)

    # Content + telemetry
    message       = Column(String, nullable=False)     # body
    sent_at       = Column(String, nullable=False)     # ISO string from client
    anomaly_score = Column(Float,  nullable=False, default=0.0)
    flagged       = Column(Boolean, nullable=False, default=False)

    created_at    = Column(DateTime, default=datetime.utcnow)

    # Composite indexes to accelerate common filters
    __table_args__ = (
        Index("idx_messages_dept_sem_course", "department", "semester", "course_code"),
        Index("idx_messages_flagged", "flagged"),  # quick retrieval of flagged anomalies
        Index("idx_messages_sender", "sender_name"),
    )
