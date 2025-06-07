from sqlalchemy import Column, Integer, String, TIMESTAMP, func
from sqlalchemy.orm import declarative_base, relationship
from .base import Base

class User(Base):
    """Define user schema (table) in database"""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    totp_secret = Column(String, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())