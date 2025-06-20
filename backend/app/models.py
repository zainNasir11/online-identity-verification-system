from app.database import Base
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    cnic = Column(String(15), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    phone = Column(String(15), nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Integer, default=0)  # 0 for False, 1 for True
    created_at = Column(DateTime, server_default=func.now())