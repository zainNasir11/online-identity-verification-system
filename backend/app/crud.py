from sqlalchemy.orm import Session
from . import models, schemas
from passlib.context import CryptContext
import logging

logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def get_user_by_email(db: Session, email: str):
    try:
        return db.query(models.User).filter(models.User.email == email).first()
    except Exception as e:
        logger.error(f"Error fetching user by email {email}: {str(e)}")
        return None

def get_user(db: Session, user_id: int):
    try:
        return db.query(models.User).filter(models.User.id == user_id).first()
    except Exception as e:
        logger.error(f"Error fetching user by id {user_id}: {str(e)}")
        return None

def update_user(db: Session, user_id: int, user: schemas.UserUpdate):
    try:
        db_user = get_user(db, user_id)
        if not db_user:
            return None
        
        update_data = user.model_dump(exclude_unset=True)
        if 'password' in update_data and update_data['password']:
            db_user.password_hash = get_password_hash(update_data['password'])
            update_data.pop('password')
        if 'is_admin' in update_data:
            db_user.is_admin = 1 if update_data['is_admin'] else 0
            update_data.pop('is_admin')
        for key, value in update_data.items():
            setattr(db_user, key, value)
        db.commit()
        db.refresh(db_user)
        return db_user
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating user {user_id}: {str(e)}")
        return None

def create_user(db: Session, user: schemas.UserCreate):
    try:
        hashed_password = get_password_hash(user.password)
        db_user = models.User(
            name=user.name,
            cnic=user.cnic,
            email=user.email,
            phone=user.phone,
            password_hash=hashed_password,
            is_admin=1 if getattr(user, 'is_admin', False) else 0
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating user {user.email}: {str(e)}")
        return None

def delete_user(db: Session, user_id: int):
    try:
        db_user = db.query(models.User).filter(models.User.id == user_id).first()
        if not db_user:
            return False
        db.delete(db_user)
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        return False
        
def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()