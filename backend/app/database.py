from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

# Use environment variable for DB path
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////app/instance/users.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    # Import models to ensure they are registered with Base
    from app.models import User
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully")