from sqlalchemy import Column, Integer, String, Text, ForeignKey, TIMESTAMP, func
from sqlalchemy.orm import declarative_base, relationship
from .base import Base

class VaultEntry(Base):
    """Define vault entry schema (table) in database"""
    __tablename__ = 'vault_entries'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    title = Column(String, nullable=False)
    site = Column(String, nullable=False)
    site_username = Column(String)
    password_encrypted = Column(Text, nullable=False)
    notes = Column(Text)
    category = Column(String, nullable=True)
    favourite = Column(Integer, default=0)
    created_at = Column(TIMESTAMP, server_default=func.now())

    user = relationship("User")

    def __repr__(self):
        return (f"VaultEntry(id={self.id}, user_id={self.user_id}, title='{self.title}', "
                f"site='{self.site}', site_username='{self.site_username}', "
                f"notes='{self.notes}', category='{self.category}', "
                f"favourite={self.favourite}, created_at={self.created_at})")