from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Annotated
import logging
from datetime import timedelta

# Local imports
from app import database, schemas, crud, auth
from app.database import get_db as get_db_dependency
from app.auth import get_current_user, authenticate_user, create_access_token, get_current_admin_user
from app.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Online Identity Verification System",
    description="API for user identity verification and authentication",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URLs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 Scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    try:
        database.init_db()
        logger.info(" Database initialized successfully")
        # Hardcoded admin user
        from app.crud import get_user_by_email, create_user
        from app.schemas import UserCreate
        from app.database import SessionLocal
        admin_email = "admin@system.com"
        admin_password = "admin123"
        admin_cnic = "1111111111111"
        admin_phone = "03000000000"
        admin_name = "Admin"
        db = SessionLocal()
        try:
            admin_user = get_user_by_email(db, admin_email)
            if not admin_user:
                admin_schema = UserCreate(
                    name=admin_name,
                    cnic=admin_cnic,
                    email=admin_email,
                    phone=admin_phone,
                    password=admin_password,
                    is_admin=True
                )
                create_user(db, admin_schema)
                logger.info("Hardcoded admin user created.")
            else:
                logger.info("Hardcoded admin user already exists.")
        finally:
            db.close()
    except Exception as e:
        logger.error(f" Error initializing database or admin user: {str(e)}")
        raise

# Health check endpoint
@app.get("/health", include_in_schema=False)
async def health_check(db: Session = Depends(get_db_dependency)):
    try:
        # Test database connection
        db.execute("SELECT 1")
        return {
            "status": "healthy",
            "database": "connected",
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection failed"
        )

# User Registration
@app.post("/users/register", response_model=schemas.UserOut)
def register_user(
    user: schemas.UserCreate,
    db: Session = Depends(database.get_db)  # Use context manager directly
):
    try:
        db_user = crud.get_user_by_email(db, email=user.email)
        if db_user:
            logger.warning(f"Registration attempt with existing email: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )
        # Prevent normal registration from setting is_admin
        user.is_admin = False
        created_user = crud.create_user(db, user)
        if not created_user:
            logger.error(f"User creation failed for {user.email}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User creation failed"
            )
        logger.info(f"✅ New user registered: {user.email}")
        return created_user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Registration failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to an internal error"
        )

# ADMIN: Create user
@app.post("/admin/users", response_model=schemas.UserOut)
def admin_create_user(
    user: schemas.UserCreate,
    db: Session = Depends(database.get_db),
    admin: schemas.UserOut = Depends(get_current_admin_user)
):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    created_user = crud.create_user(db, user)
    if not created_user:
        raise HTTPException(status_code=500, detail="User creation failed")
    return created_user

# ADMIN: Get all users
@app.get("/admin/users", response_model=list[schemas.User])
def admin_read_users(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db), admin: schemas.UserOut = Depends(get_current_admin_user)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users

# ADMIN: Get user by ID
@app.get("/admin/users/{user_id}", response_model=schemas.UserOut)
def admin_read_user(user_id: int, db: Session = Depends(database.get_db), admin: schemas.UserOut = Depends(get_current_admin_user)):
    user = crud.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# ADMIN: Update user
@app.put("/admin/users/{user_id}", response_model=schemas.UserOut)
def admin_update_user(user_id: int, user: schemas.UserUpdate, db: Session = Depends(database.get_db), admin: schemas.UserOut = Depends(get_current_admin_user)):
    updated_user = crud.update_user(db, user_id, user)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
    return updated_user

# ADMIN: Delete user
@app.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_user(user_id: int, db: Session = Depends(database.get_db), admin: schemas.UserOut = Depends(get_current_admin_user)):
    success = crud.delete_user(db, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return None

# Get all users
@app.get("/users/", response_model=list[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users

# User Login
@app.post(
    "/users/login",
    response_model=schemas.Token,
    summary="User login",
    tags=["Authentication"]
)
async def login_user(
    user: schemas.UserLogin,
    db: Session = Depends(get_db_dependency)
):
    try:
        authenticated_user = authenticate_user(db, email=user.email, password=user.password)
        if not authenticated_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(authenticated_user.id)},
            expires_delta=access_token_expires
        )
        
        logger.info(f"User logged in: {user.email}")
        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed for {user.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

# Get User Details
@app.get(
    "/users/{user_id}",
    response_model=schemas.UserOut,
    summary="Get user details",
    tags=["Users"]
)
async def read_user(
    user_id: int,
    db: Session = Depends(get_db_dependency),
    current_user: schemas.UserOut = Depends(get_current_user)
):
    try:
        user = crud.get_user(db, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if user.id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this resource"
            )
            
        return user
        
    except Exception as e:
        logger.error(f"Failed to fetch user {user_id}: {str(e)}")
        raise

@app.put(
    "/users/{user_id}",
    response_model=schemas.UserOut,
    summary="Update user details",
    tags=["Users"]
)
async def update_user(
    user_id: int,
    user: schemas.UserUpdate,
    db: Session = Depends(get_db_dependency),
    current_user: schemas.UserOut = Depends(get_current_user)
):
    try:
        if user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to update this user"
            )
            
        updated_user = crud.update_user(db, user_id, user)
        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
            
        logger.info(f"User updated: {user_id}")
        return updated_user
        
    except Exception as e:
        logger.error(f"Failed to update user {user_id}: {str(e)}")
        raise

# Get user by email
@app.get("/users/email/{email}", response_model=schemas.UserOut)
def read_user_by_email(email: str, db: Session = Depends(get_db_dependency)):
    db_user = crud.get_user_by_email(db, email=email)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

# Delete User
@app.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user",
    tags=["Users"]
)
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db_dependency),
    current_user: schemas.UserOut = Depends(get_current_user)
):
    try:
        if user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to delete this user"
            )
            
        success = crud.delete_user(db, user_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
            
        logger.info(f"User deleted: {user_id}")
        return None
        
    except Exception as e:
        logger.error(f"Failed to delete user {user_id}: {str(e)}")
        raise