import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime
from app.db.base import Base

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    role = Column(String, default="ANALYST") # ADMIN, INVESTIGATOR, ANALYST
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
