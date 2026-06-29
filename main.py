from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Optional
from pydantic import BaseModel, Field
from datetime import timedelta, datetime, timezone
import jwt
from jwt import InvalidTokenError
import logging
import secrets
import string
import os
from urllib.parse import urlencode
import httpx
from dotenv import load_dotenv

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import models
from database import engine, get_db
import auth
from email_utils import send_otp_email, send_password_reset_email, send_registration_confirmation_email

load_dotenv()

logger = logging.getLogger(__name__)


def _rate_limit_key(request: Request) -> str:
    if os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true":
        forwarded_for = request.headers.get("x-forwarded-for", "")
        first_forwarded_ip = forwarded_for.split(",", 1)[0].strip()
        if first_forwarded_ip:
            return first_forwarded_ip
    return get_remote_address(request)


limiter = Limiter(
    key_func=_rate_limit_key,
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI"),
)


def _normalize_datetime(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)

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
ALLOWED_RETURN_URLS = {"https://www.kbcahyd.co.in", "https://kbcahyd.co.in", "http://localhost:5173", "http://localhost:3000"}
ADULT_RATE = 250
CHILD_6_12_RATE = 150
MAX_ATTENDEES_PER_REGISTRATION = 20


def _cashfree_base_url() -> str:
    configured_url = os.getenv("CASHFREE_BASE_URL")
    if configured_url:
        return configured_url.rstrip("/")
    if os.getenv("CASHFREE_ENV", "sandbox").lower() == "production":
        return "https://api.cashfree.com/pg"
    return "https://sandbox.cashfree.com/pg"


def _cashfree_headers() -> dict[str, str]:
    cashfree_app_id = os.getenv("CASHFREE_APP_ID")
    cashfree_secret = os.getenv("CASHFREE_SECRET")
    cashfree_api_version = os.getenv("CASHFREE_API_VERSION", "2023-08-01")

    if not cashfree_app_id or not cashfree_secret:
        raise HTTPException(status_code=500, detail="Cashfree credentials are not configured.")

    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-client-id": cashfree_app_id,
        "x-client-secret": cashfree_secret,
        "x-api-version": cashfree_api_version,
    }


def _registration_amount(adults: int, children_6_12: int) -> int:
    return adults * ADULT_RATE + children_6_12 * CHILD_6_12_RATE


def _validate_attendee_count(adults: int, children_6_12: int, children_under_6: int):
    if adults + children_6_12 + children_under_6 > MAX_ATTENDEES_PER_REGISTRATION:
        raise HTTPException(status_code=400, detail="Too many attendees for one registration.")


def _normalize_phone(phone: Optional[str]) -> str:
    normalized = "".join(ch for ch in (phone or "") if ch.isdigit())
    if len(normalized) < 10:
        raise HTTPException(status_code=400, detail="Please add a valid phone number before paying.")
    return normalized[-10:]

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
    model_config = {"from_attributes": True}

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
    adults: int = Field(..., ge=1, le=MAX_ATTENDEES_PER_REGISTRATION)
    children_6_12: int = Field(..., ge=0, le=MAX_ATTENDEES_PER_REGISTRATION)
    children_under_6: int = Field(..., ge=0, le=MAX_ATTENDEES_PER_REGISTRATION)
    cashfree_order_id: Optional[str] = Field(default=None, min_length=3, max_length=100)
    cashfree_transaction_id: Optional[str] = None

class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=32, max_length=50)
    new_password: str = Field(min_length=8, max_length=72)

class CashfreeOrderCreate(BaseModel):
    adults: int = Field(..., ge=1, le=MAX_ATTENDEES_PER_REGISTRATION)
    children_6_12: int = Field(..., ge=0, le=MAX_ATTENDEES_PER_REGISTRATION)
    children_under_6: int = Field(..., ge=0, le=MAX_ATTENDEES_PER_REGISTRATION)
    return_url: Optional[str] = Field(default=None, max_length=2048)

@app.post("/register")
@limiter.limit("5/minute")
def register(request: Request, user: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    
    if db_user and db_user.is_verified:
        return {"message": "If the email is not verified, an OTP has been sent.", "email": user.email}
    
    otp = ''.join(secrets.choice(string.digits) for _ in range(6))
    otp_expires = datetime.now(timezone.utc) + timedelta(minutes=10)
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
    except InvalidTokenError:
        raise credentials_exception
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    token_version = payload.get("pwd")
    if token_version and token_version != auth.get_token_version(user.hashed_password):
        raise credentials_exception
    return user

@app.post("/meetup-registration")
async def meetup_registration(
    request: Request,
    payload: MeetupRegistrationConfirmation,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    _validate_attendee_count(payload.adults, payload.children_6_12, payload.children_under_6)
    expected_amount = _registration_amount(payload.adults, payload.children_6_12)
    order_id = payload.cashfree_order_id or payload.cashfree_transaction_id
    if not order_id:
        raise HTTPException(status_code=400, detail="Payment order ID is required.")

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            response = await client.get(
                f"{_cashfree_base_url()}/orders/{order_id}",
                headers=_cashfree_headers(),
            )
        except httpx.HTTPError:
            raise HTTPException(status_code=502, detail="Unable to verify payment with Cashfree.")

    try:
        order_data = response.json()
    except Exception:
        order_data = {}

    if response.status_code >= 400:
        detail = order_data.get("message") if isinstance(order_data, dict) else None
        raise HTTPException(status_code=400, detail=detail or "Payment order could not be verified.")

    if not isinstance(order_data, dict):
        raise HTTPException(status_code=400, detail="Payment order could not be verified.")

    order_status = str(order_data.get("order_status", "")).upper()
    if order_status != "PAID":
        raise HTTPException(status_code=400, detail="Payment is not complete yet.")

    order_amount = float(order_data.get("order_amount", -1))
    if int(round(order_amount)) != expected_amount:
        raise HTTPException(status_code=400, detail="Payment amount does not match registration.")

    customer_details = order_data.get("customer_details") or {}
    customer_id = str(customer_details.get("customer_id") or "")
    if customer_id != str(current_user.id):
        raise HTTPException(status_code=400, detail="Payment order does not belong to this account.")

    current_user.registration_status = True
    current_user.registered_adults = payload.adults
    current_user.registered_children_6_12 = payload.children_6_12
    current_user.registered_children_under_6 = payload.children_under_6
    current_user.amount_paid = expected_amount
    current_user.cashfree_transaction_id = order_id
    db.commit()
    
    background_tasks.add_task(
        send_registration_confirmation_email,
        current_user.email,
        current_user.full_name or current_user.email,
        payload.adults,
        payload.children_6_12,
        payload.children_under_6,
        expected_amount,
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
    if not user.otp_expires_at or _normalize_datetime(user.otp_expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid verification request")
    
    # Verify successful
    user.is_verified = True
    user.otp_code = None
    user.otp_expires_at = None
    db.commit()
    
    return auth.create_token_pair(user.email, user.hashed_password)

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
    
    return auth.create_token_pair(user.email, user.hashed_password)

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
        token_version: Optional[str] = payload.get("pwd")
        if email is None or token_type != "refresh":
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    if token_version and token_version != auth.get_token_version(user.hashed_password):
        raise credentials_exception

    return auth.create_token_pair(user.email, user.hashed_password)




@app.get("/me", response_model=UserResponse)
@limiter.limit("60/minute")
def read_users_me(request: Request, current_user: models.User = Depends(get_current_user)):
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
        token_expires = datetime.now(timezone.utc) + timedelta(minutes=15)

        user.reset_token = hashed_token
        user.reset_token_expires_at = token_expires
        db.commit()

        reset_link = f"{FRONTEND_URL.rstrip('/')}/reset-password?{urlencode({'token': raw_token})}"
        background_tasks.add_task(send_password_reset_email, user.email, reset_link)

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
    now = datetime.now(timezone.utc)
    users_with_token = db.query(models.User).filter(
        models.User.reset_token.isnot(None),
        models.User.reset_token_expires_at > now
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

@app.post("/cashfree-orders")
@limiter.limit("10/minute")
async def create_cashfree_order(
    request: Request,
    payload: CashfreeOrderCreate,
    current_user: models.User = Depends(get_current_user),
):
    _validate_attendee_count(payload.adults, payload.children_6_12, payload.children_under_6)
    
    # Validate return_url against whitelist
    return_url = payload.return_url or FRONTEND_URL
    if return_url not in ALLOWED_RETURN_URLS:
        raise HTTPException(status_code=400, detail="Invalid return URL.")
    
    amount = _registration_amount(payload.adults, payload.children_6_12)
    order_id = f"kbca_{current_user.id}_{secrets.token_urlsafe(12)}"
    phone = _normalize_phone(current_user.phone)

    cashfree_payload = {
        "order_amount": float(amount),
        "order_currency": "INR",
        "order_id": order_id,
        "customer_details": {
            "customer_id": str(current_user.id),
            "customer_email": current_user.email,
            "customer_phone": phone,
        },
        "order_meta": {
            "return_url": return_url,
        },
        "order_note": f"KBCA meetup registration - {payload.adults} adult(s), {payload.children_6_12} child(ren) 6-12, {payload.children_under_6} child(ren) under 6",
    }

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            response = await client.post(
                f"{_cashfree_base_url()}/orders",
                headers=_cashfree_headers(),
                json=cashfree_payload,
            )
        except httpx.HTTPError:
            raise HTTPException(status_code=502, detail="Unable to create payment order.")
        
        try:
            data = response.json()

            if isinstance(data, dict) and "message" not in data and "error" in data:
                data["message"] = data["error"]
            if response.status_code >= 400:
                raise HTTPException(status_code=400, detail=data.get("message", "Failed to create payment order."))
            return data
        except Exception:
            if response.status_code >= 400:
                raise HTTPException(status_code=400, detail="Failed to create payment order.")
            return response.text
