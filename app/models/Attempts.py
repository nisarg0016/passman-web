from sqlalchemy import Column, Integer, String, Text, ForeignKey, TIMESTAMP, func
from sqlalchemy.orm import declarative_base, relationship
from .base import Base

class LoginAttempt(Base):
    """Capture login attempts for anomaly detection"""
    __tablename__ = 'login_attempts'

    id = Column(Integer, primary_key=True)
    username = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean)
    ip_address = Column(String)
    user_agent = Column(String)