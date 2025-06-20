from pydantic import BaseModel, EmailStr, constr
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    name: str
    cnic: constr(min_length=13, max_length=15)
    phone: constr(min_length=11, max_length=11)
    password: str
    is_admin: bool = False  # Only used by admin-side creation

class UserUpdate(BaseModel):
    name: str | None = None
    email: EmailStr | None = None
    phone: constr(min_length=11, max_length=11) | None = None
    password: str | None = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    name: str
    cnic: str
    email: EmailStr
    phone: str
    is_admin: bool
    created_at: datetime

    class Config:
        from_attributes = True

class User(UserOut):
    pass

class Token(BaseModel):
    access_token: str
    token_type: str