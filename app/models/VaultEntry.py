from sqlalchemy import Column, Integer, String, Text, ForeignKey, TIMESTAMP, func
from sqlalchemy.orm import declarative_base, relationship
from .base import Base

class VaultEntry(Base):
    """Define vault entry schema (table) in database"""
    __tablename__ = 'vault_entries'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    site = Column(String, nullable=False)
    site_username = Column(String)
    password_encrypted = Column(Text, nullable=False)
    notes = Column(Text)
    created_at = Column(TIMESTAMP, server_default=func.now())

    user = relationship("User")