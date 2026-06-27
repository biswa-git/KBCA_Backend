from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Optional
from pydantic import BaseModel, Field
from datetime import timedelta, datetime
from jose import jwt, JWTError
import secrets
import string
import os
from urllib.parse import urlencode

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import models
from database import engine, get_db
import auth
from email_utils import send_otp_email, send_password_reset_email, send_registration_confirmation_email
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)

# Disable interactive API docs in production to reduce attack surface
_IS_DEV = os.getenv("ENVIRONMENT", "production").lower() == "development"
app = FastAPI(
    title="KBCA Auth API",
    docs_url="/docs" if _IS_DEV else None,
    redoc_url="/redoc" if _IS_DEV else None,
    openapi_url="/openapi.json" if _IS_DEV else None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

FRONTEND_URL = os.getenv("FRONTEND_URL", "https://www.kbcahyd.co.in")

# Setup CORS to allow requests from the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "http://127.0.0.1:3000", "https://www.kbcahyd.co.in", "https://kbcahyd.co.in"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Pydantic schemas
class UserCreate(BaseModel):
    email: str = Field(..., pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    password: str = Field(min_length=8, max_length=72)
    full_name: str
    phone: Optional[str] = None
    address: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    phone: Optional[str]
    address: Optional[str]
    registration_status: bool = False
    registered_adults: int = 0
    registered_children_6_12: int = 0
    registered_children_under_6: int = 0
    amount_paid: int = 0
    cashfree_transaction_id: Optional[str] = None

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class VerifyOTP(BaseModel):
    email: str = Field(..., pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    otp: str = Field(min_length=6, max_length=6)

class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

class MeetupRegistrationConfirmation(BaseModel):
    adults: int = Field(..., ge=0)
    children_6_12: int = Field(..., ge=0)
    children_under_6: int = Field(..., ge=0)
    amount_paid: float = Field(..., ge=0)
    cashfree_transaction_id: Optional[str] = None

class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=32, max_length=50)
    new_password: str = Field(min_length=8, max_length=72)

@app.post("/register")
@limiter.limit("5/minute")
def register(request: Request, user: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    
    if db_user and db_user.is_verified:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists. Please log in instead.",
        )
    
    otp = ''.join(secrets.choice(string.digits) for _ in range(6))
    otp_expires = datetime.utcnow() + timedelta(minutes=10)
    hashed_password = auth.get_password_hash(user.password)
    hashed_otp = auth.get_password_hash(otp)

    if db_user and not db_user.is_verified:
        db_user.full_name = user.full_name
        db_user.phone = user.phone
        db_user.address = user.address
        db_user.hashed_password = hashed_password
        db_user.otp_code = hashed_otp
        db_user.otp_expires_at = otp_expires
    else:
        new_user = models.User(
            email=user.email,
            full_name=user.full_name,
            phone=user.phone,
            address=user.address,
            hashed_password=hashed_password,
            otp_code=hashed_otp,
            otp_expires_at=otp_expires
        )
        db.add(new_user)
    
    db.commit()
    
    background_tasks.add_task(send_otp_email, user.email, otp)
    
    return {"message": "If the email is not verified, an OTP has been sent.", "email": user.email}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

@app.post("/meetup-registration")
def meetup_registration(
    request: Request,
    payload: MeetupRegistrationConfirmation,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    logger.info(f"📝 Meetup Registration Request from {current_user.email}")
    logger.info(f"   Payload: {payload}")
    logger.info(f"   Transaction ID: {payload.cashfree_transaction_id}")
    
    current_user.registration_status = True
    current_user.registered_adults = payload.adults
    current_user.registered_children_6_12 = payload.children_6_12
    current_user.registered_children_under_6 = payload.children_under_6
    current_user.amount_paid = int(round(payload.amount_paid))
    current_user.cashfree_transaction_id = payload.cashfree_transaction_id
    
    logger.info(f"   Saving Transaction ID to DB: {current_user.cashfree_transaction_id}")
    
    db.commit()
    
    logger.info(f"✅ Registration saved for {current_user.email}")
    logger.info(f"   Confirmed Transaction ID in DB: {current_user.cashfree_transaction_id}")

    background_tasks.add_task(
        send_registration_confirmation_email,
        current_user.email,
        current_user.full_name or current_user.email,
        payload.adults,
        payload.children_6_12,
        payload.children_under_6,
        payload.amount_paid,
    )

    return {"message": "Registration confirmed and email queued."}

@app.post("/verify-otp", response_model=Token)
@limiter.limit("10/minute")
def verify_otp(request: Request, verify_data: VerifyOTP, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == verify_data.email).first()
    # Generic error message to prevent email enumeration
    if not user or not user.otp_code or user.is_verified:
        raise HTTPException(status_code=400, detail="Invalid verification request")
    if not auth.verify_password(verify_data.otp, user.otp_code):
        raise HTTPException(status_code=400, detail="Invalid verification request")
    if not user.otp_expires_at or user.otp_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid verification request")
    
    # Verify successful
    user.is_verified = True
    user.otp_code = None
    user.otp_expires_at = None
    db.commit()
    
    return auth.create_token_pair(user.email)

@app.post("/login", response_model=Token)
@limiter.limit("10/minute")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified. Please register to get an OTP.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return auth.create_token_pair(user.email)

@app.post("/refresh", response_model=Token)
@limiter.limit("10/minute")
def refresh_token(request: Request, refresh_data: RefreshTokenRequest, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(refresh_data.refresh_token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")
        if email is None or token_type != "refresh":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception

    return auth.create_token_pair(user.email)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

@app.get("/me", response_model=UserResponse)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

@app.post("/forgot-password")
@limiter.limit("3/minute")
def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Initiate password reset — always returns 200 to prevent email enumeration."""
    user = db.query(models.User).filter(models.User.email == payload.email).first()

    if user and user.is_verified:
        raw_token = secrets.token_urlsafe(32)
        hashed_token = auth.get_password_hash(raw_token)
        token_expires = datetime.utcnow() + timedelta(minutes=15)

        user.reset_token = hashed_token
        user.reset_token_expires_at = token_expires
        db.commit()

        reset_link = f"{FRONTEND_URL.rstrip('/')}/reset-password?{urlencode({'token': raw_token})}"
        background_tasks.add_task(send_password_reset_email, user.email, reset_link, raw_token)

    return {"message": "If that email is registered, a password reset link has been sent."}


@app.post("/reset-password")
@limiter.limit("10/minute")
def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db)
):
    """Validate reset token and update password."""
    # Scan only users with a pending reset token for timing attack mitigation
    users_with_token = db.query(models.User).filter(
        models.User.reset_token.isnot(None),
        models.User.reset_token_expires_at > datetime.utcnow()
    ).all()

    if not users_with_token:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")

    matched_user = None
    for u in users_with_token:
        if auth.verify_password(payload.token, u.reset_token):
            matched_user = u
            break

    if not matched_user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")

    matched_user.hashed_password = auth.get_password_hash(payload.new_password)
    matched_user.reset_token = None
    matched_user.reset_token_expires_at = None
    db.commit()

    return {"message": "Password updated successfully. You can now log in."}


@app.api_route("/health", methods=["GET", "HEAD"])
def health_check():
    return {"status": "ok"}

@app.api_route("/keep-alive", methods=["GET", "HEAD"])
def keep_alive(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "message": "Database is alive"}
    except Exception:
        raise HTTPException(status_code=500, detail="Database connection failed")
