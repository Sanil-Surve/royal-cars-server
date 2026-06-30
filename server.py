from dotenv import load_dotenv
from pathlib import Path
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Literal

import bcrypt
import jwt
import cloudinary
import cloudinary.uploader
import httpx
import resend
import asyncio
import hmac
import hashlib
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response, UploadFile, File, Form
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field

# ------------- Config -------------
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ["JWT_SECRET"]
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
APP_NAME = os.environ.get("APP_NAME", "royalcars")
# FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://royalrentalcars.in")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")
COOKIE_SECURE = not FRONTEND_URL.startswith("http://")
COOKIE_SAMESITE = "none" if COOKIE_SECURE else "lax"

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 60 * 24  # 1 day for smooth demo
REFRESH_TOKEN_DAYS = 7

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
    secure=True,
)

PAYU_MERCHANT_KEY = os.environ.get("PAYU_MERCHANT_KEY", "")
PAYU_MERCHANT_SALT = os.environ.get("PAYU_MERCHANT_SALT", "")
PAYU_BASE_URL = os.environ.get("PAYU_BASE_URL", "https://secure.payu.in")

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "Royal Cars <booking@royalrentalcars.in>")
if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

app = FastAPI(title="Royal Cars API")
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("royalcars")


# ------------- Auth helpers -------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id, "email": email, "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_DAYS),
        "type": "refresh",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def set_auth_cookies(response: Response, access: str, refresh: str):
    response.set_cookie("access_token", access, httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE, max_age=ACCESS_TOKEN_MINUTES * 60, path="/")
    response.set_cookie("refresh_token", refresh, httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE, max_age=REFRESH_TOKEN_DAYS * 86400, path="/")


def serialize_user(doc: dict) -> dict:
    if not doc:
        return doc
    return {
        "id": doc.get("id") or str(doc.get("_id")),
        "email": doc.get("email"),
        "name": doc.get("name"),
        "phone": doc.get("phone"),
        "role": doc.get("role", "customer"),
        "kyc_status": doc.get("kyc_status", "not_submitted"),
        "created_at": doc.get("created_at"),
    }


async def get_user_by_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            return None
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
        return user
    except jwt.PyJWTError:
        return None


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user.pop("password_hash", None)
    return user


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ------------- Models -------------
class RegisterPayload(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    name: str
    phone: Optional[str] = None


class LoginPayload(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordPayload(BaseModel):
    email: EmailStr


class ResetPasswordPayload(BaseModel):
    token: str
    new_password: str = Field(min_length=6)


class LocationIn(BaseModel):
    name: str
    address: str
    is_active: bool = True


class VehicleIn(BaseModel):
    name: str
    type: str
    fuel_type: str
    image_urls: List[str] = []
    price_per_24hrs: float
    deposit_amount: float
    overtime_rate_per_hour: float = 0
    is_available: bool = True
    location_id: Optional[str] = None
    description: Optional[str] = None
    seats: Optional[int] = 5
    transmission: Optional[str] = "Manual"
    vehicle_number: Optional[str] = None  # Number plate e.g. MH12AB1234


class BookingIn(BaseModel):
    vehicle_id: str
    pickup_location_id: str
    dropoff_location_id: str
    pickup_date: str
    pickup_time: str
    dropoff_date: str
    dropoff_time: str


class KYCVerifyPayload(BaseModel):
    status: Literal["approved", "rejected"]
    notes: Optional[str] = None


class PaymentInitPayload(BaseModel):
    booking_id: str
    payment_type: Literal["full", "partial", "balance"]


class PayAtSitePayload(BaseModel):
    booking_id: str


class PaymentVerifyPayload(BaseModel):
    booking_id: str
    txnid: str


class BookingStatusPayload(BaseModel):
    status: Literal["pending_kyc", "verified", "confirmed", "active", "completed", "cancelled"]


class StartRidePayload(BaseModel):
    odometer_start: float = Field(..., ge=0, description="Starting odometer reading in km")
    fuel_level_start: Optional[str] = Field(None, description="Starting fuel level e.g. 'Full', '3/4', '1/2', '1/4'")
    photo_urls: List[str] = Field(default=[], description="Pickup condition photo URLs")
    odometer_photo_url: Optional[str] = Field(None, description="Odometer photo at start")
    notes: Optional[str] = None


class EndRidePayload(BaseModel):
    odometer_end: float = Field(..., ge=0, description="Ending odometer reading in km")
    fuel_level_end: Optional[str] = Field(None, description="Ending fuel level")
    photo_urls: List[str] = Field(default=[], description="Return condition photo URLs")
    odometer_photo_url: Optional[str] = Field(None, description="Odometer photo at end")
    notes: Optional[str] = None
    extra_charges: float = Field(default=0, ge=0, description="Manual extra charges (damage, cleaning, etc.)")
    extra_charges_reason: Optional[str] = None


# ------------- Email (Resend) -------------
def _format_inr(amount) -> str:
    try:
        return f"₹{int(round(float(amount))):,}"
    except Exception:
        return f"₹{amount}"


def _email_layout(title: str, body_html: str, cta: Optional[dict] = None) -> str:
    cta_html = ""
    if cta:
        cta_html = f"""
        <tr><td style="padding:24px 32px 0 32px;">
          <a href="{cta['url']}" style="display:inline-block;background:#0A192F;color:#ffffff;text-decoration:none;padding:12px 22px;border-radius:6px;font-weight:600;font-family:Helvetica,Arial,sans-serif;font-size:14px;letter-spacing:0.02em;">{cta['label']}</a>
        </td></tr>
        """
    return f"""<!doctype html>
<html><body style="margin:0;padding:0;background:#FAFAFA;font-family:Helvetica,Arial,sans-serif;color:#0A192F;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#FAFAFA;padding:32px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #E2E8F0;border-radius:8px;overflow:hidden;">
        <tr><td style="padding:24px 32px;border-bottom:3px solid #D4AF37;">
          <div style="font-size:24px;font-weight:700;letter-spacing:-0.01em;color:#0A192F;">Royal Cars</div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.2em;color:#64748B;margin-top:2px;">Premium fleet · Navi Mumbai</div>
        </td></tr>
        <tr><td style="padding:32px;">
          <h1 style="margin:0 0 8px 0;font-size:22px;font-weight:700;color:#0A192F;">{title}</h1>
          {body_html}
        </td></tr>
        {cta_html}
        <tr><td style="padding:24px 32px;background:#F8FAFC;border-top:1px solid #E2E8F0;font-size:12px;color:#64748B;">
          Need help? Reply to this email or call us at the pickup location.<br>
          © {datetime.now(timezone.utc).year} Royal Cars · Kharghar · Panvel
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""


def _booking_summary_table(booking: dict, location_name_map: dict) -> str:
    pickup_loc = location_name_map.get(booking.get("pickup_location_id"), "—")
    dropoff_loc = location_name_map.get(booking.get("dropoff_location_id"), "—")
    rows = [
        ("Booking ID", f"#{booking['id'][:8]}"),
        ("Vehicle", booking.get("vehicle_name", "—")),
        ("Pickup", f"{pickup_loc} · {booking.get('pickup_date')} {booking.get('pickup_time')}"),
        ("Drop-off", f"{dropoff_loc} · {booking.get('dropoff_date')} {booking.get('dropoff_time')}"),
        ("Rent", _format_inr(booking.get("rent_amount"))),
        ("Refundable deposit", _format_inr(booking.get("deposit_amount"))),
        ("Total", _format_inr(booking.get("total_amount"))),
    ]
    if booking.get("paid_amount", 0) > 0:
        rows.append(("Paid", _format_inr(booking.get("paid_amount"))))
    if booking.get("balance_amount", 0) > 0:
        rows.append(("Balance due at pickup", _format_inr(booking.get("balance_amount"))))
    table_rows = "".join(
        f'<tr><td style="padding:8px 0;color:#64748B;font-size:13px;">{k}</td>'
        f'<td style="padding:8px 0;text-align:right;font-size:13px;color:#0A192F;font-weight:600;">{v}</td></tr>'
        for k, v in rows
    )
    return f'<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:16px;border-top:1px solid #E2E8F0;">{table_rows}</table>'


async def _send_email(to: str, subject: str, html: str):
    if not RESEND_API_KEY or not to:
        return
    try:
        await asyncio.to_thread(
            resend.Emails.send,
            {"from": SENDER_EMAIL, "to": [to], "subject": subject, "html": html},
        )
        logger.info(f"email sent to {to} | {subject}")
    except Exception as e:
        # never block the request; just log
        logger.warning(f"email send failed for {to}: {e}")


async def send_booking_received_email(user: dict, booking: dict):
    locs = await db.locations.find({"id": {"$in": [booking.get("pickup_location_id"), booking.get("dropoff_location_id")]}}, {"_id": 0, "id": 1, "name": 1}).to_list(10)
    name_map = {l["id"]: l["name"] for l in locs}
    body = f"""
      <p style="margin:0 0 12px 0;font-size:14px;line-height:1.55;color:#334155;">Hi {user.get('name', 'there').split(' ')[0]},</p>
      <p style="margin:0 0 12px 0;font-size:14px;line-height:1.55;color:#334155;">
        We've received your booking request for <b>{booking.get('vehicle_name')}</b>. Your KYC documents will be reviewed by our fleet team and you'll receive a confirmation email once payment is complete.
      </p>
      {_booking_summary_table(booking, name_map)}
    """
    html = _email_layout("Booking received", body, cta={
        "url": f"{FRONTEND_URL}/dashboard",
        "label": "View my bookings",
    })
    await _send_email(user["email"], f"Booking received · {booking.get('vehicle_name')}", html)


async def send_booking_confirmed_email(user: dict, booking: dict, payment_kind: str = "full"):
    locs = await db.locations.find({"id": {"$in": [booking.get("pickup_location_id"), booking.get("dropoff_location_id")]}}, {"_id": 0, "id": 1, "name": 1}).to_list(10)
    name_map = {l["id"]: l["name"] for l in locs}
    blurb = "Your booking is now confirmed and the vehicle is reserved for you."
    if payment_kind == "partial" and booking.get("balance_amount", 0) > 0:
        blurb += f" The remaining balance of {_format_inr(booking['balance_amount'])} will be collected at pickup."
    elif payment_kind == "pay_at_site":
        blurb += f" The total amount of {_format_inr(booking['total_amount'])} will be collected at pickup."
    body = f"""
      <p style="margin:0 0 12px 0;font-size:14px;line-height:1.55;color:#334155;">Hi {user.get('name', 'there').split(' ')[0]},</p>
      <p style="margin:0 0 12px 0;font-size:14px;line-height:1.55;color:#334155;">{blurb}</p>
      {_booking_summary_table(booking, name_map)}
      <p style="margin:18px 0 0 0;font-size:13px;line-height:1.55;color:#64748B;">
        Please carry your original Driving License at pickup. We'll see you at the mall!
      </p>
    """
    html = _email_layout("🎉 Booking confirmed", body, cta={
        "url": f"{FRONTEND_URL}/dashboard",
        "label": "View booking",
    })
    await _send_email(user["email"], f"Booking confirmed · {booking.get('vehicle_name')}", html)


async def _send_ride_started_email(user: dict, booking: dict):
    body = f"""
      <p style="margin:0 0 12px 0;font-size:14px;line-height:1.55;color:#334155;">Hi {user.get('name', 'there').split(' ')[0]},</p>
      <p style="margin:0 0 12px 0;font-size:14px;line-height:1.55;color:#334155;">
        Your ride with <b>{booking.get('vehicle_name')}</b> has started! 🚗
      </p>
      <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:16px;border-top:1px solid #E2E8F0;">
        <tr><td style="padding:8px 0;color:#64748B;font-size:13px;">Booking ID</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#0A192F;font-weight:600;">#{booking['id'][:8]}</td></tr>
        <tr><td style="padding:8px 0;color:#64748B;font-size:13px;">Vehicle</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#0A192F;font-weight:600;">{booking.get('vehicle_name', '—')}</td></tr>
        <tr><td style="padding:8px 0;color:#64748B;font-size:13px;">Odometer</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#0A192F;font-weight:600;">{booking.get('odometer_start', 0)} km</td></tr>
        <tr><td style="padding:8px 0;color:#64748B;font-size:13px;">Started at</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#0A192F;font-weight:600;">{booking.get('ride_started_at', '—')[:16]}</td></tr>
        <tr><td style="padding:8px 0;color:#64748B;font-size:13px;">Scheduled return</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#0A192F;font-weight:600;">{booking.get('dropoff_date')} {booking.get('dropoff_time')}</td></tr>
      </table>
      <p style="margin:18px 0 0 0;font-size:13px;line-height:1.55;color:#64748B;">Drive safe and enjoy your trip! Return the vehicle on time to avoid overtime charges.</p>
    """
    html = _email_layout("🚗 Ride started", body)
    await _send_email(user["email"], f"Ride started · {booking.get('vehicle_name')}", html)


async def _send_ride_ended_email(user: dict, booking: dict):
    overtime_row = ""
    if booking.get("overtime_hours", 0) > 0:
        overtime_row = f"""<tr><td style="padding:8px 0;color:#ef4444;font-size:13px;">Overtime ({booking['overtime_hours']} hrs)</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#ef4444;font-weight:600;">{_format_inr(booking.get('overtime_charge', 0))}</td></tr>"""
    extra_row = ""
    if booking.get("extra_charges", 0) > 0:
        reason = booking.get('extra_charges_reason') or 'Additional charges'
        extra_row = f"""<tr><td style="padding:8px 0;color:#ef4444;font-size:13px;">{reason}</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#ef4444;font-weight:600;">{_format_inr(booking.get('extra_charges', 0))}</td></tr>"""
    body = f"""
      <p style="margin:0 0 12px 0;font-size:14px;line-height:1.55;color:#334155;">Hi {user.get('name', 'there').split(' ')[0]},</p>
      <p style="margin:0 0 12px 0;font-size:14px;line-height:1.55;color:#334155;">Your ride with <b>{booking.get('vehicle_name')}</b> is complete. Here's your trip summary:</p>
      <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:16px;border-top:1px solid #E2E8F0;">
        <tr><td style="padding:8px 0;color:#64748B;font-size:13px;">Booking ID</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#0A192F;font-weight:600;">#{booking['id'][:8]}</td></tr>
        <tr><td style="padding:8px 0;color:#64748B;font-size:13px;">Distance driven</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#0A192F;font-weight:600;">{booking.get('km_driven', 0)} km</td></tr>
        <tr><td style="padding:8px 0;color:#64748B;font-size:13px;">Rent</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#0A192F;font-weight:600;">{_format_inr(booking.get('rent_amount'))}</td></tr>
        <tr><td style="padding:8px 0;color:#64748B;font-size:13px;">Deposit</td>
            <td style="padding:8px 0;text-align:right;font-size:13px;color:#0A192F;font-weight:600;">{_format_inr(booking.get('deposit_amount'))}</td></tr>
        {overtime_row}
        {extra_row}
      </table>
      <p style="margin:18px 0 0 0;font-size:13px;line-height:1.55;color:#64748B;">Thank you for choosing Royal Cars! We hope you had a great experience.</p>
    """
    html = _email_layout("✅ Ride completed", body)
    await _send_email(user["email"], f"Ride completed · {booking.get('vehicle_name')}", html)


# ------------- Cloudinary upload helper -------------
def cloudinary_upload(data: bytes, folder: str, resource_type: str = "auto", public_id: Optional[str] = None) -> dict:
    """Upload bytes to Cloudinary. Returns full Cloudinary response (with secure_url, public_id)."""
    try:
        result = cloudinary.uploader.upload(
            data,
            folder=f"{APP_NAME}/{folder}",
            resource_type=resource_type,
            public_id=public_id,
            overwrite=True,
            use_filename=False,
            unique_filename=True,
        )
        return result
    except Exception as e:
        logger.error(f"Cloudinary upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


def cloudinary_destroy(public_id: str, resource_type: str = "image") -> None:
    try:
        cloudinary.uploader.destroy(public_id, resource_type=resource_type, invalidate=True)
    except Exception as e:
        logger.warning(f"Cloudinary destroy failed for {public_id}: {e}")


# ------------- Auth endpoints -------------
@api_router.post("/auth/register")
async def register(payload: RegisterPayload, response: Response):
    email = payload.email.lower()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "email": email,
        "password_hash": hash_password(payload.password),
        "name": payload.name,
        "phone": payload.phone,
        "role": "customer",
        "kyc_status": "not_submitted",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.users.insert_one(doc)
    access = create_access_token(user_id, email, "customer")
    refresh = create_refresh_token(user_id)
    set_auth_cookies(response, access, refresh)
    return {"user": serialize_user(doc), "access_token": access}


@api_router.post("/auth/login")
async def login(payload: LoginPayload, response: Response):
    email = payload.email.lower()
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access = create_access_token(user["id"], email, user.get("role", "customer"))
    refresh = create_refresh_token(user["id"])
    set_auth_cookies(response, access, refresh)
    return {"user": serialize_user(user), "access_token": access}


@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"ok": True}


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return serialize_user(user)


@api_router.post("/auth/refresh")
async def refresh_token(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        access = create_access_token(user["id"], user["email"], user.get("role", "customer"))
        response.set_cookie("access_token", access, httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE, max_age=ACCESS_TOKEN_MINUTES * 60, path="/")
        return {"access_token": access}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


RESET_TOKEN_MINUTES = 60  # 1 hour


@api_router.post("/auth/forgot-password")
async def forgot_password(payload: ForgotPasswordPayload):
    """
    Always returns 200 to prevent email enumeration.
    Generates a secure reset token, stores it hashed, and emails a link.
    """
    email = payload.email.lower()
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if user:
        # Invalidate any existing tokens for this user
        await db.password_reset_tokens.delete_many({"user_id": user["id"]})

        raw_token = str(uuid.uuid4())
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_MINUTES)

        await db.password_reset_tokens.insert_one({
            "token_hash": token_hash,
            "user_id": user["id"],
            "email": email,
            "expires_at": expires_at.isoformat(),
            "used": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

        reset_url = f"{FRONTEND_URL}/reset-password?token={raw_token}"
        first_name = user.get("name", "there").split(" ")[0]
        body_html = f"""
          <p style="margin:0 0 12px 0;font-size:14px;line-height:1.55;color:#334155;">Hi {first_name},</p>
          <p style="margin:0 0 20px 0;font-size:14px;line-height:1.55;color:#334155;">
            We received a request to reset the password for your Royal Cars account.<br>
            Click the button below to choose a new password. This link is valid for <strong>1 hour</strong>.
          </p>
          <p style="margin:20px 0 0 0;font-size:12px;line-height:1.55;color:#94A3B8;">
            If you did not request a password reset, you can safely ignore this email.
            Your password will remain unchanged.
          </p>
        """
        html = _email_layout(
            "Reset your password",
            body_html,
            cta={"url": reset_url, "label": "Reset Password"},
        )
        await _send_email(email, "Reset your Royal Cars password", html)

    return {"ok": True, "message": "If an account with that email exists, a reset link has been sent."}


@api_router.post("/auth/reset-password")
async def reset_password(payload: ResetPasswordPayload):
    token_hash = hashlib.sha256(payload.token.encode()).hexdigest()
    record = await db.password_reset_tokens.find_one({"token_hash": token_hash})

    if not record:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    if record.get("used"):
        raise HTTPException(status_code=400, detail="This reset link has already been used")

    expires_at = datetime.fromisoformat(record["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        await db.password_reset_tokens.delete_one({"token_hash": token_hash})
        raise HTTPException(status_code=400, detail="Reset link has expired. Please request a new one")

    # Update the user's password
    new_hash = hash_password(payload.new_password)
    result = await db.users.update_one(
        {"id": record["user_id"]},
        {"$set": {"password_hash": new_hash}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    # Mark token as used (delete it)
    await db.password_reset_tokens.delete_one({"token_hash": token_hash})

    return {"ok": True, "message": "Password reset successfully. You can now log in with your new password."}


# ------------- Locations -------------
@api_router.get("/locations")
async def list_locations():
    items = await db.locations.find({"is_active": True}, {"_id": 0}).to_list(100)
    return items


@api_router.post("/locations")
async def create_location(payload: LocationIn, admin: dict = Depends(require_admin)):
    doc = payload.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.locations.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.put("/locations/{loc_id}")
async def update_location(loc_id: str, payload: LocationIn, admin: dict = Depends(require_admin)):
    await db.locations.update_one({"id": loc_id}, {"$set": payload.model_dump()})
    doc = await db.locations.find_one({"id": loc_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return doc


@api_router.delete("/locations/{loc_id}")
async def delete_location(loc_id: str, admin: dict = Depends(require_admin)):
    await db.locations.update_one({"id": loc_id}, {"$set": {"is_active": False}})
    return {"ok": True}


# ------------- Vehicles -------------
@api_router.get("/vehicles")
async def list_vehicles(location_id: Optional[str] = None, available_only: bool = True):
    q = {}
    if location_id:
        q["location_id"] = location_id
    if available_only:
        q["is_available"] = True
    items = await db.vehicles.find(q, {"_id": 0}).to_list(500)
    return items


@api_router.get("/vehicles/{vehicle_id}")
async def get_vehicle(vehicle_id: str):
    v = await db.vehicles.find_one({"id": vehicle_id}, {"_id": 0})
    if not v:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    return v


@api_router.post("/vehicles")
async def create_vehicle(payload: VehicleIn, admin: dict = Depends(require_admin)):
    doc = payload.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.vehicles.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.put("/vehicles/{vehicle_id}")
async def update_vehicle(vehicle_id: str, payload: VehicleIn, admin: dict = Depends(require_admin)):
    await db.vehicles.update_one({"id": vehicle_id}, {"$set": payload.model_dump()})
    v = await db.vehicles.find_one({"id": vehicle_id}, {"_id": 0})
    if not v:
        raise HTTPException(status_code=404, detail="Not found")
    return v


@api_router.delete("/vehicles/{vehicle_id}")
async def delete_vehicle(vehicle_id: str, admin: dict = Depends(require_admin)):
    await db.vehicles.delete_one({"id": vehicle_id})
    return {"ok": True}


# ------------- Price Hike (surge pricing) -------------

@api_router.get("/admin/price-hike")
async def get_price_hike(admin: dict = Depends(require_admin)):
    """Return the current global price hike multiplier (1.0 = normal pricing)."""
    doc = await db.settings.find_one({"key": "price_hike"}, {"_id": 0})
    if not doc:
        return {"multiplier": 1.0, "applied_at": None, "applied_by": None}
    return doc


@api_router.post("/admin/price-hike")
async def set_price_hike(multiplier: float, admin: dict = Depends(require_admin)):
    """Apply a global price multiplier (1.0–2.0) to all vehicle base prices.

    On the first hike ever, seeds base_price_per_24hrs so future adjustments
    always multiply from the original price (no compounding).
    """
    if not (1.0 <= multiplier <= 2.0):
        raise HTTPException(status_code=400, detail="Multiplier must be between 1.0 and 2.0")

    multiplier = round(multiplier, 2)
    vehicles = await db.vehicles.find({}, {"_id": 0}).to_list(500)

    for v in vehicles:
        # Seed the base price on first hike so we always multiply from the original
        base = v.get("base_price_per_24hrs") or v["price_per_24hrs"]
        new_price = round(base * multiplier, 2)
        await db.vehicles.update_one(
            {"id": v["id"]},
            {"$set": {
                "base_price_per_24hrs": base,
                "price_per_24hrs": new_price,
            }}
        )

    now = datetime.now(timezone.utc).isoformat()
    await db.settings.update_one(
        {"key": "price_hike"},
        {"$set": {
            "key": "price_hike",
            "multiplier": multiplier,
            "applied_at": now,
            "applied_by": admin["id"],
        }},
        upsert=True,
    )
    return {
        "ok": True,
        "multiplier": multiplier,
        "vehicles_updated": len(vehicles),
        "applied_at": now,
    }


@api_router.post("/upload")
async def upload_file(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    ext = (file.filename.rsplit(".", 1)[-1] if file.filename and "." in file.filename else "bin").lower()
    if ext not in {"jpg", "jpeg", "png", "webp", "pdf"}:
        raise HTTPException(status_code=400, detail="Unsupported file type")
    data = await file.read()
    resource_type = "raw" if ext == "pdf" else "image"
    result = cloudinary_upload(data, folder=f"uploads/{user['id']}", resource_type=resource_type)
    file_id = str(uuid.uuid4())
    await db.files.insert_one({
        "id": file_id,
        "public_id": result.get("public_id"),
        "secure_url": result.get("secure_url"),
        "resource_type": result.get("resource_type", resource_type),
        "original_filename": file.filename,
        "content_type": file.content_type,
        "size": result.get("bytes", len(data)),
        "owner_id": user["id"],
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"id": file_id, "url": result.get("secure_url"), "public_id": result.get("public_id")}


@api_router.post("/upload/vehicle-image")
async def upload_vehicle_image(file: UploadFile = File(...), admin: dict = Depends(require_admin)):
    ext = (file.filename.rsplit(".", 1)[-1] if file.filename and "." in file.filename else "bin").lower()
    if ext not in {"jpg", "jpeg", "png", "webp"}:
        raise HTTPException(status_code=400, detail="Unsupported image type")
    data = await file.read()
    result = cloudinary_upload(data, folder="vehicles", resource_type="image")
    file_id = str(uuid.uuid4())
    await db.files.insert_one({
        "id": file_id,
        "public_id": result.get("public_id"),
        "secure_url": result.get("secure_url"),
        "resource_type": "image",
        "original_filename": file.filename,
        "content_type": file.content_type,
        "size": result.get("bytes", len(data)),
        "owner_id": admin["id"],
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"id": file_id, "url": result.get("secure_url"), "public_id": result.get("public_id")}


# ------------- KYC -------------
KYC_DOC_TYPES = {"dl_front", "dl_back", "aadhar_front", "aadhar_back", "rent_agreement", "light_bill"}


@api_router.post("/kyc/upload")
async def kyc_upload(
    document_type: str = Form(...),
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user),
):
    if document_type not in KYC_DOC_TYPES:
        raise HTTPException(status_code=400, detail="Invalid document type")
    ext = (file.filename.rsplit(".", 1)[-1] if file.filename and "." in file.filename else "bin").lower()
    if ext not in {"jpg", "jpeg", "png", "pdf"}:
        raise HTTPException(status_code=400, detail="Only JPG/PNG/PDF allowed")
    data = await file.read()
    resource_type = "raw" if ext == "pdf" else "image"
    result = cloudinary_upload(data, folder=f"kyc/{user['id']}", resource_type=resource_type)
    secure_url = result.get("secure_url")
    public_id = result.get("public_id")
    content_type = file.content_type or ("application/pdf" if ext == "pdf" else "image/jpeg")
    await db.files.insert_one({
        "id": str(uuid.uuid4()),
        "public_id": public_id,
        "secure_url": secure_url,
        "resource_type": resource_type,
        "original_filename": file.filename,
        "content_type": content_type,
        "size": result.get("bytes", len(data)),
        "owner_id": user["id"],
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    # Delete any previous doc of this type (not yet approved) from cloudinary too
    prev_docs = await db.kyc_documents.find({
        "user_id": user["id"], "document_type": document_type,
        "verification_status": {"$ne": "approved"},
    }).to_list(10)
    for p in prev_docs:
        if p.get("public_id"):
            cloudinary_destroy(p["public_id"], resource_type=p.get("resource_type", "image"))
    await db.kyc_documents.delete_many({
        "user_id": user["id"], "document_type": document_type,
        "verification_status": {"$ne": "approved"},
    })
    doc_id = str(uuid.uuid4())
    kyc_doc = {
        "id": doc_id, "user_id": user["id"], "document_type": document_type,
        "file_url": secure_url, "public_id": public_id, "resource_type": resource_type,
        "content_type": content_type,
        "verification_status": "pending", "admin_notes": None,
        "verified_by": None, "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.kyc_documents.insert_one(kyc_doc)
    await db.users.update_one({"id": user["id"]}, {"$set": {"kyc_status": "pending"}})
    kyc_doc.pop("_id", None)
    return kyc_doc


@api_router.get("/kyc/my")
async def my_kyc(user: dict = Depends(get_current_user)):
    docs = await db.kyc_documents.find({"user_id": user["id"]}, {"_id": 0}).to_list(50)
    return {"kyc_status": user.get("kyc_status", "not_submitted"), "documents": docs}


@api_router.get("/kyc/queue")
async def kyc_queue(admin: dict = Depends(require_admin)):
    # Group by user
    users = await db.users.find({"kyc_status": {"$in": ["pending"]}}, {"_id": 0, "password_hash": 0}).to_list(200)
    result = []
    for u in users:
        docs = await db.kyc_documents.find({"user_id": u["id"]}, {"_id": 0}).to_list(20)
        result.append({"user": serialize_user(u), "documents": docs})
    return result


@api_router.get("/kyc/user/{user_id}")
async def kyc_for_user(user_id: str, admin: dict = Depends(require_admin)):
    u = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    docs = await db.kyc_documents.find({"user_id": user_id}, {"_id": 0}).to_list(50)
    return {"user": serialize_user(u), "documents": docs}


@api_router.post("/kyc/{doc_id}/verify")
async def kyc_verify(doc_id: str, payload: KYCVerifyPayload, admin: dict = Depends(require_admin)):
    doc = await db.kyc_documents.find_one({"id": doc_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    await db.kyc_documents.update_one({"id": doc_id}, {"$set": {
        "verification_status": payload.status,
        "admin_notes": payload.notes,
        "verified_by": admin["id"],
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }})
    # Recompute user kyc_status
    user_id = doc["user_id"]
    all_docs = await db.kyc_documents.find({"user_id": user_id}).to_list(50)
    types_present = {d["document_type"] for d in all_docs}
    if any(d["verification_status"] == "rejected" for d in all_docs):
        new_status = "rejected"
    else:
        required_types = {"dl_front", "dl_back", "aadhar_front", "aadhar_back"}
        approved_types = {d["document_type"] for d in all_docs if d["verification_status"] == "approved"}
        if required_types.issubset(approved_types):
            new_status = "approved"
        else:
            new_status = "pending"
    await db.users.update_one({"id": user_id}, {"$set": {"kyc_status": new_status}})
    # If a booking is awaiting KYC and user is now approved, set to 'verified'
    if new_status == "approved":
        await db.bookings.update_many(
            {"user_id": user_id, "status": "pending_kyc"},
            {"$set": {"status": "verified"}},
        )
    return {"ok": True, "kyc_status": new_status}


# ------------- Bookings -------------
def compute_rent(price_per_24hrs: float, pickup_dt: datetime, dropoff_dt: datetime) -> float:
    total_hours = max((dropoff_dt - pickup_dt).total_seconds() / 3600, 24)
    days = max(1, int((total_hours + 23) // 24))
    return round(price_per_24hrs * days, 2)


def _validate_business_hours(t: str):
    """Pickup/drop-off must be between 05:00 and 23:00 inclusive."""
    try:
        hh, mm = (int(x) for x in t.split(":")[:2])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid time format")
    minutes = hh * 60 + mm
    if minutes < 5 * 60 or minutes > 23 * 60:
        raise HTTPException(status_code=400, detail="Pickup and drop-off must be between 5:00 AM and 11:00 PM")


@api_router.post("/bookings")
async def create_booking(payload: BookingIn, user: dict = Depends(get_current_user)):
    vehicle = await db.vehicles.find_one({"id": payload.vehicle_id}, {"_id": 0})
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    _validate_business_hours(payload.pickup_time)
    _validate_business_hours(payload.dropoff_time)
    try:
        pickup_dt = datetime.fromisoformat(f"{payload.pickup_date}T{payload.pickup_time}")
        dropoff_dt = datetime.fromisoformat(f"{payload.dropoff_date}T{payload.dropoff_time}")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date/time")
    if dropoff_dt <= pickup_dt:
        raise HTTPException(status_code=400, detail="Dropoff must be after pickup")

    rent = compute_rent(vehicle["price_per_24hrs"], pickup_dt, dropoff_dt)
    deposit = vehicle["deposit_amount"]
    total = rent + deposit

    # Determine starting status: pending_kyc if user is not approved yet, else verified
    status = "verified" if user.get("kyc_status") == "approved" else "pending_kyc"

    booking_id = str(uuid.uuid4())
    doc = {
        "id": booking_id,
        "user_id": user["id"],
        "vehicle_id": payload.vehicle_id,
        "vehicle_name": vehicle["name"],
        "vehicle_image": (vehicle.get("image_urls") or [None])[0],
        "pickup_location_id": payload.pickup_location_id,
        "dropoff_location_id": payload.dropoff_location_id,
        "pickup_date": payload.pickup_date,
        "pickup_time": payload.pickup_time,
        "dropoff_date": payload.dropoff_date,
        "dropoff_time": payload.dropoff_time,
        "rent_amount": rent,
        "deposit_amount": deposit,
        "total_amount": total,
        "status": status,
        "payment_type": None,
        "paid_amount": 0.0,
        "balance_amount": total,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.bookings.insert_one(doc)
    doc.pop("_id", None)
    # Fire-and-forget email — never block the booking response
    asyncio.create_task(send_booking_received_email(user, doc))
    return doc


@api_router.get("/bookings/my")
async def my_bookings(user: dict = Depends(get_current_user)):
    items = await db.bookings.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return items


@api_router.get("/bookings/{booking_id}")
async def get_booking(booking_id: str, user: dict = Depends(get_current_user)):
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(status_code=404, detail="Booking not found")
    if user.get("role") != "admin" and b["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return b


@api_router.get("/admin/bookings")
async def all_bookings(status: Optional[str] = None, admin: dict = Depends(require_admin)):
    q = {}
    if status:
        q["status"] = status
    items = await db.bookings.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)
    # attach user info
    user_ids = list({b["user_id"] for b in items})
    users = await db.users.find({"id": {"$in": user_ids}}, {"_id": 0, "password_hash": 0}).to_list(500)
    umap = {u["id"]: u for u in users}
    for b in items:
        u = umap.get(b["user_id"])
        if u:
            b["customer_name"] = u.get("name")
            b["customer_email"] = u.get("email")
            b["customer_phone"] = u.get("phone")
    return items


@api_router.patch("/admin/bookings/{booking_id}/status")
async def update_booking_status(booking_id: str, payload: BookingStatusPayload, admin: dict = Depends(require_admin)):
    await db.bookings.update_one({"id": booking_id}, {"$set": {"status": payload.status}})
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(status_code=404, detail="Not found")
    return b


# ------------- Start Ride / End Ride -------------
@api_router.post("/admin/bookings/{booking_id}/start-ride")
async def start_ride(booking_id: str, payload: StartRidePayload, admin: dict = Depends(require_admin)):
    """Admin starts the ride: records pickup condition and transitions to 'active'."""
    booking = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    if booking["status"] != "confirmed":
        raise HTTPException(status_code=400, detail=f"Cannot start ride: booking status is '{booking['status']}', must be 'confirmed'")

    now = datetime.now(timezone.utc).isoformat()
    ride_data = {
        "status": "active",
        "ride_started_at": now,
        "ride_started_by": admin["id"],
        "odometer_start": payload.odometer_start,
        "fuel_level_start": payload.fuel_level_start,
        "pickup_photos": payload.photo_urls,
        "pickup_notes": payload.notes,
        "odometer_photo_start": payload.odometer_photo_url,
    }
    await db.bookings.update_one({"id": booking_id}, {"$set": ride_data})

    # Make the vehicle unavailable during the ride
    await db.vehicles.update_one({"id": booking["vehicle_id"]}, {"$set": {"is_available": False}})

    updated = await db.bookings.find_one({"id": booking_id}, {"_id": 0})

    # Send ride started email
    user = await db.users.find_one({"id": booking["user_id"]}, {"_id": 0})
    if user:
        asyncio.create_task(_send_ride_started_email(user, updated))

    return updated


@api_router.post("/admin/bookings/{booking_id}/end-ride")
async def end_ride(booking_id: str, payload: EndRidePayload, admin: dict = Depends(require_admin)):
    """Admin ends the ride: records return condition, calculates overtime, transitions to 'completed'."""
    booking = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    if booking["status"] != "active":
        raise HTTPException(status_code=400, detail=f"Cannot end ride: booking status is '{booking['status']}', must be 'active'")

    if payload.odometer_end < booking.get("odometer_start", 0):
        raise HTTPException(status_code=400, detail="End odometer reading cannot be less than start reading")

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    km_driven = round(payload.odometer_end - booking.get("odometer_start", 0), 1)

    # Calculate overtime
    overtime_hours = 0.0
    overtime_charge = 0.0
    try:
        dropoff_dt = datetime.fromisoformat(f"{booking['dropoff_date']}T{booking['dropoff_time']}")
        # Make timezone-naive for comparison
        actual_return = now.replace(tzinfo=None)
        if actual_return > dropoff_dt:
            overtime_seconds = (actual_return - dropoff_dt).total_seconds()
            overtime_hours = round(overtime_seconds / 3600, 1)
            # Get vehicle overtime rate
            vehicle = await db.vehicles.find_one({"id": booking["vehicle_id"]}, {"_id": 0})
            rate = (vehicle or {}).get("overtime_rate_per_hour", 0) or 0
            if rate > 0:
                overtime_charge = round(overtime_hours * rate, 2)
    except Exception as e:
        logger.warning(f"Overtime calc error: {e}")

    total_extra = round(overtime_charge + payload.extra_charges, 2)

    ride_data = {
        "status": "completed",
        "ride_ended_at": now_iso,
        "ride_ended_by": admin["id"],
        "odometer_end": payload.odometer_end,
        "km_driven": km_driven,
        "fuel_level_end": payload.fuel_level_end,
        "return_photos": payload.photo_urls,
        "return_notes": payload.notes,
        "odometer_photo_end": payload.odometer_photo_url,
        "overtime_hours": overtime_hours,
        "overtime_charge": overtime_charge,
        "extra_charges": payload.extra_charges,
        "extra_charges_reason": payload.extra_charges_reason,
        "total_extra_charges": total_extra,
    }
    await db.bookings.update_one({"id": booking_id}, {"$set": ride_data})

    # Make the vehicle available again
    await db.vehicles.update_one({"id": booking["vehicle_id"]}, {"$set": {"is_available": True}})

    updated = await db.bookings.find_one({"id": booking_id}, {"_id": 0})

    # Send ride ended email
    user = await db.users.find_one({"id": booking["user_id"]}, {"_id": 0})
    if user:
        asyncio.create_task(_send_ride_ended_email(user, updated))

    return updated


@api_router.get("/admin/active-rides")
async def get_active_rides(admin: dict = Depends(require_admin)):
    """Get all currently active rides for the dashboard."""
    rides = await db.bookings.find({"status": "active"}, {"_id": 0}).sort("ride_started_at", -1).to_list(200)
    user_ids = list({r["user_id"] for r in rides})
    users = await db.users.find({"id": {"$in": user_ids}}, {"_id": 0, "password_hash": 0}).to_list(200)
    umap = {u["id"]: u for u in users}
    for r in rides:
        u = umap.get(r["user_id"])
        if u:
            r["customer_name"] = u.get("name")
            r["customer_phone"] = u.get("phone")
    return rides


@api_router.get("/admin/confirmed-rides")
async def get_confirmed_rides(admin: dict = Depends(require_admin)):
    """Get confirmed bookings ready to start."""
    rides = await db.bookings.find({"status": "confirmed"}, {"_id": 0}).sort("pickup_date", 1).to_list(200)
    user_ids = list({r["user_id"] for r in rides})
    users = await db.users.find({"id": {"$in": user_ids}}, {"_id": 0, "password_hash": 0}).to_list(200)
    umap = {u["id"]: u for u in users}
    for r in rides:
        u = umap.get(r["user_id"])
        if u:
            r["customer_name"] = u.get("name")
            r["customer_phone"] = u.get("phone")
    return rides


# ------------- Payments (PayU Seamless UPI) -------------

def _ensure_payu():
    if not PAYU_MERCHANT_KEY or not PAYU_MERCHANT_SALT:
        raise HTTPException(status_code=500, detail="PayU not configured on server")


def _payu_hash(data_string: str) -> str:
    """Generate SHA-512 hash for PayU."""
    return hashlib.sha512(data_string.encode()).hexdigest()


def _build_payu_forward_hash(
    txnid: str,
    amount: str,
    productinfo: str,
    firstname: str,
    email: str,
) -> str:
    """
    Forward hash formula:
    sha512(key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5||||||SALT)
    """
    data = f"{PAYU_MERCHANT_KEY}|{txnid}|{amount}|{productinfo}|{firstname}|{email}|||||||||||{PAYU_MERCHANT_SALT}"
    return _payu_hash(data)


def _build_payu_verify_hash(txnid: str) -> str:
    """
    Verify payment hash formula:
    sha512(key|command|var1|SALT)
    """
    data = f"{PAYU_MERCHANT_KEY}|verify_payment|{txnid}|{PAYU_MERCHANT_SALT}"
    return _payu_hash(data)


@api_router.post("/payments/init")
async def payment_init(payload: PaymentInitPayload, user: dict = Depends(get_current_user)):
    """Initiates a PayU UPI payment. Returns intentURIData for QR code display."""
    _ensure_payu()
    booking = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    if not booking or booking["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")
    if booking["status"] not in {"verified", "confirmed", "active"}:
        raise HTTPException(status_code=400, detail="Booking not ready for payment. KYC must be approved first.")

    if payload.payment_type == "full":
        amount = round(booking["total_amount"] - booking.get("paid_amount", 0), 2)
        record_type = "full"
    elif payload.payment_type == "partial":
        if booking.get("paid_amount", 0) > 0:
            raise HTTPException(status_code=400, detail="Partial payment already made")
        amount = round(booking["total_amount"] * 0.2, 2)
        record_type = "partial_advance"
    else:  # balance
        amount = booking.get("balance_amount", 0)
        if amount <= 0:
            raise HTTPException(status_code=400, detail="No balance due")
        record_type = "balance"

    # Generate unique txnid
    is_mock = os.environ.get("MOCK_PAYMENTS") == "true" or PAYU_MERCHANT_KEY == "mock" or payload.booking_id.startswith("mock_")
    txnid = f"RC_TEST_{str(uuid.uuid4()).replace('-', '')[:10].upper()}" if is_mock else f"RC{str(uuid.uuid4()).replace('-', '')[:18].upper()}"
    amount_str = f"{amount:.2f}"

    if is_mock:
        intent_uri = f"upi://pay?pa=royalrentalcars@payu&pn=Royal%20Cars&am={amount_str}&tr={txnid}"
    else:
        productinfo = f"Booking#{booking['id'][:8]}"
        firstname = (user.get("name") or "Customer").split()[0]
        email = user["email"]
        phone = user.get("phone") or "9999999999"
        surl = f"{FRONTEND_URL}/payment/success"
        furl = f"{FRONTEND_URL}/payment/failure"

        forward_hash = _build_payu_forward_hash(txnid, amount_str, productinfo, firstname, email)

        payu_payload = {
            "key": PAYU_MERCHANT_KEY,
            "txnid": txnid,
            "amount": amount_str,
            "productinfo": productinfo,
            "firstname": firstname,
            "email": email,
            "phone": phone,
            "surl": surl,
            "furl": furl,
            "pg": "UPI",
            "bankcode": "INTENT",
            "txn_s2s_flow": "4",
            "hash": forward_hash,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(f"{PAYU_BASE_URL}/_payment", data=payu_payload)
                resp.raise_for_status()
                payu_resp = resp.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"PayU _payment HTTP error: {e.response.status_code} {e.response.text}")
            raise HTTPException(status_code=502, detail=f"PayU gateway error: {e.response.status_code}")
        except Exception as e:
            logger.error(f"PayU _payment failed: {e}")
            raise HTTPException(status_code=502, detail=f"PayU gateway error: {str(e)[:200]}")

        logger.info(f"PayU _payment raw response: {payu_resp}")

        result_val = payu_resp.get("result")
        result_dict = result_val if isinstance(result_val, dict) else {}

        data_val = payu_resp.get("data")
        data_dict = data_val if isinstance(data_val, dict) else {}

        intent_uri = (
            payu_resp.get("intentURIData")
            or result_dict.get("intentURIData")
            or data_dict.get("intentURIData")
            or ""
        )
        if not intent_uri:
            logger.error(f"PayU response missing intentURIData. Check credentials/environment. Response: {payu_resp}")
            raise HTTPException(status_code=502, detail="PayU did not return UPI intent data. Check credentials/environment.")

        if intent_uri and not intent_uri.startswith("upi://"):
            intent_uri = f"upi://pay?{intent_uri}"

    # Persist pending payment record
    await db.payments.insert_one({
        "id": str(uuid.uuid4()),
        "booking_id": payload.booking_id,
        "amount": amount,
        "payment_type": record_type,
        "payu_txnid": txnid,
        "payu_mihpayid": None,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    return {
        "txnid": txnid,
        "amount": amount,
        "intentURIData": intent_uri,
        "payment_type": record_type,
        "is_sandbox": "test" in PAYU_BASE_URL or is_mock,
    }


@api_router.post("/payments/verify")
async def payment_verify(payload: PaymentVerifyPayload, user: dict = Depends(get_current_user)):
    """Polls PayU to verify if a transaction has been paid. Safe to call repeatedly."""
    _ensure_payu()
    booking = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    if not booking or booking["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")

    # Check if already processed (idempotent)
    already = await db.payments.find_one({"payu_txnid": payload.txnid, "status": "success"})
    if already:
        fresh = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
        return fresh

    is_mock = os.environ.get("MOCK_PAYMENTS") == "true" or PAYU_MERCHANT_KEY == "mock" or payload.txnid.startswith("RC_TEST_")

    if is_mock:
        status = "success"
        mihpayid = f"mih_mock_{str(uuid.uuid4()).replace('-', '')[:10].upper()}"
    else:
        verify_hash = _build_payu_verify_hash(payload.txnid)
        verify_payload = {
            "key": PAYU_MERCHANT_KEY,
            "command": "verify_payment",
            "var1": payload.txnid,
            "hash": verify_hash,
        }

        verify_url = "https://test.payu.in/merchant/postservice?form=2" if "test" in PAYU_BASE_URL else "https://info.payu.in/merchant/postservice?form=2"

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    verify_url,
                    data=verify_payload,
                )
                resp.raise_for_status()
                verify_resp = resp.json()
        except Exception as e:
            logger.error(f"PayU verify_payment failed: {e}")
            raise HTTPException(status_code=502, detail=f"Payment verification error: {str(e)[:200]}")

        # Parse PayU verify response
        transaction_details = (
            verify_resp.get("transaction_details", {})
            or verify_resp.get("result", {})
        )
        txn = None
        if isinstance(transaction_details, dict):
            txn = transaction_details.get(payload.txnid) or next(iter(transaction_details.values()), None)

        if not txn:
            raise HTTPException(status_code=400, detail="Transaction not found in PayU response")

        status = (txn.get("status") or "").lower()
        mihpayid = txn.get("mihpayid") or txn.get("payuMoneyId") or ""

        if status != "success":
            raise HTTPException(
                status_code=402,
                detail=f"Payment not yet successful. Status: {status}",
            )


    # Update payment record
    pending = await db.payments.find_one(
        {"payu_txnid": payload.txnid, "status": "pending"},
        sort=[("created_at", -1)],
    )
    if not pending:
        raise HTTPException(status_code=400, detail="Payment record not found or already processed")

    await db.payments.update_one(
        {"id": pending["id"]},
        {"$set": {
            "payu_mihpayid": mihpayid,
            "status": "success",
            "paid_at": datetime.now(timezone.utc).isoformat(),
        }},
    )

    paid_amount = round(booking.get("paid_amount", 0) + pending["amount"], 2)
    balance = round(booking["total_amount"] - paid_amount, 2)
    update = {
        "status": "confirmed",
        "paid_amount": paid_amount,
        "balance_amount": max(balance, 0),
        "payment_type": "full" if abs(balance) < 0.01 else "partial",
    }
    await db.bookings.update_one({"id": payload.booking_id}, {"$set": update})
    fresh = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    payment_kind = "partial" if fresh.get("balance_amount", 0) > 0 else "full"
    asyncio.create_task(send_booking_confirmed_email(user, fresh, payment_kind=payment_kind))
    return fresh

@api_router.post("/payments/simulate-success")
async def payments_simulate_success(payload: PaymentVerifyPayload, user: dict = Depends(get_current_user)):
    """Only active in sandbox/test mode: forces the pending transaction to success."""
    _ensure_payu()
    if "test" not in PAYU_BASE_URL and PAYU_MERCHANT_KEY != "mock":
        raise HTTPException(status_code=400, detail="Simulation not allowed in production environment")

    booking = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    if not booking or booking["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")

    pending = await db.payments.find_one({"payu_txnid": payload.txnid, "status": "pending"})
    if not pending:
        # Check if already success (idempotence for button clicks)
        already = await db.payments.find_one({"payu_txnid": payload.txnid, "status": "success"})
        if already:
            return {"ok": True}
        raise HTTPException(status_code=404, detail="Pending payment record not found")

    # Mark payment as success in DB
    await db.payments.update_one(
        {"id": pending["id"]},
        {"$set": {
            "payu_mihpayid": f"mih_mock_{str(uuid.uuid4()).replace('-', '')[:10].upper()}",
            "status": "success",
            "paid_at": datetime.now(timezone.utc).isoformat(),
        }},
    )

    # Confirm booking
    paid_amount = round(booking.get("paid_amount", 0) + pending["amount"], 2)
    balance = round(booking["total_amount"] - paid_amount, 2)
    update = {
        "status": "confirmed",
        "paid_amount": paid_amount,
        "balance_amount": max(balance, 0),
        "payment_type": "full" if abs(balance) < 0.01 else "partial",
    }
    await db.bookings.update_one({"id": payload.booking_id}, {"$set": update})
    fresh = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    payment_kind = "partial" if fresh.get("balance_amount", 0) > 0 else "full"
    asyncio.create_task(send_booking_confirmed_email(user, fresh, payment_kind=payment_kind))
    return {"ok": True}



@api_router.post("/payments/pay-at-site")
async def pay_at_site(payload: PayAtSitePayload, user: dict = Depends(get_current_user)):
    booking = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    if not booking or booking["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")
    if booking["status"] not in {"verified", "confirmed"}:
        raise HTTPException(status_code=400, detail="Booking not ready for payment. KYC must be approved first.")

    update = {
        "status": "confirmed",
        "payment_type": "pay_at_site",
    }
    await db.bookings.update_one({"id": payload.booking_id}, {"$set": update})
    fresh = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    asyncio.create_task(send_booking_confirmed_email(user, fresh, payment_kind="pay_at_site"))
    return fresh


@api_router.post("/payments/webhook")
async def payu_webhook(request: Request):
    """PayU S2S callback — validates reverse hash and marks payment success."""
    form = await request.form()
    data = dict(form)

    status = data.get("status", "").lower()
    txnid = data.get("txnid", "")
    received_hash = data.get("hash", "")

    if not txnid or not received_hash:
        return {"status": "ignored"}

    # Reverse hash verification:
    # sha512(SALT|status|udf5|udf4|udf3|udf2|udf1|email|firstname|productinfo|amount|txnid|key)
    reverse_str = "|".join([
        PAYU_MERCHANT_SALT,
        data.get("status", ""),
        data.get("udf5", ""),
        data.get("udf4", ""),
        data.get("udf3", ""),
        data.get("udf2", ""),
        data.get("udf1", ""),
        data.get("email", ""),
        data.get("firstname", ""),
        data.get("productinfo", ""),
        data.get("amount", ""),
        txnid,
        PAYU_MERCHANT_KEY,
    ])
    expected_hash = _payu_hash(reverse_str)
    if not hmac.compare_digest(expected_hash.lower(), received_hash.lower()):
        logger.warning(f"PayU webhook hash mismatch for txnid={txnid}")
        raise HTTPException(status_code=400, detail="Invalid hash")

    mihpayid = data.get("mihpayid", "")

    if status == "success" and txnid:
        pending = await db.payments.find_one(
            {"payu_txnid": txnid, "status": "pending"},
        )
        if pending:
            await db.payments.update_one(
                {"id": pending["id"]},
                {"$set": {
                    "payu_mihpayid": mihpayid,
                    "status": "success",
                    "paid_at": datetime.now(timezone.utc).isoformat(),
                    "webhook_captured_at": datetime.now(timezone.utc).isoformat(),
                }},
            )
            booking = await db.bookings.find_one({"booking_id": pending["booking_id"]}, {"_id": 0})
            if booking:
                paid_amount = round(booking.get("paid_amount", 0) + pending["amount"], 2)
                balance = round(booking["total_amount"] - paid_amount, 2)
                await db.bookings.update_one(
                    {"id": pending["booking_id"]},
                    {"$set": {
                        "status": "confirmed",
                        "paid_amount": paid_amount,
                        "balance_amount": max(balance, 0),
                        "payment_type": "full" if abs(balance) < 0.01 else "partial",
                    }},
                )
    elif status == "failure" and txnid:
        await db.payments.update_one(
            {"payu_txnid": txnid},
            {"$set": {"status": "failed", "webhook_failed_at": datetime.now(timezone.utc).isoformat()}},
        )

    return {"ok": True}



@api_router.post("/admin/bookings/{booking_id}/mark-balance-paid")
async def admin_mark_balance_paid(booking_id: str, admin: dict = Depends(require_admin)):
    """Manual cash-at-pickup fallback: mark the remaining balance as paid without Razorpay."""
    booking = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    balance = booking.get("balance_amount", 0)
    if balance <= 0:
        raise HTTPException(status_code=400, detail="No balance due")
    await db.payments.insert_one({
        "id": str(uuid.uuid4()),
        "booking_id": booking_id,
        "amount": balance,
        "payment_type": "balance_cash",
        "payu_txnid": None,
        "payu_mihpayid": None,
        "status": "success",
        "paid_at": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    await db.bookings.update_one({"id": booking_id}, {"$set": {
        "paid_amount": booking["total_amount"],
        "balance_amount": 0,
        "payment_type": "full",
    }})
    return {"ok": True}


class ManualBookingIn(BaseModel):
    """Admin-created booking on behalf of a registered customer."""
    customer_id: str
    vehicle_id: str
    pickup_location_id: str
    dropoff_location_id: str
    pickup_date: str           # YYYY-MM-DD
    pickup_time: str           # HH:MM
    dropoff_date: str          # YYYY-MM-DD
    dropoff_time: str          # HH:MM
    coupon_code: Optional[str] = None
    payment_collection: Literal["none", "partial", "full"] = "none"
    admin_notes: Optional[str] = None


@api_router.post("/admin/bookings/manual", status_code=201)
async def admin_create_manual_booking(payload: ManualBookingIn, admin: dict = Depends(require_admin)):
    """Admin creates a confirmed booking on behalf of any registered customer.
    
    Bypasses KYC gate and payment gateway. Records payment_source='admin_cash' 
    and created_by_admin=True for audit. Fires confirmation email asynchronously.
    """
    # 1. Validate customer exists and is a customer (not another admin)
    customer = await db.users.find_one({"id": payload.customer_id, "role": "customer"}, {"_id": 0, "password_hash": 0})
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    # 2. Validate vehicle exists
    vehicle = await db.vehicles.find_one({"id": payload.vehicle_id}, {"_id": 0})
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")

    # 3. Validate business hours
    _validate_business_hours(payload.pickup_time)
    _validate_business_hours(payload.dropoff_time)

    # 4. Parse and validate dates
    try:
        pickup_dt = datetime.fromisoformat(f"{payload.pickup_date}T{payload.pickup_time}")
        dropoff_dt = datetime.fromisoformat(f"{payload.dropoff_date}T{payload.dropoff_time}")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date/time format")
    if dropoff_dt <= pickup_dt:
        raise HTTPException(status_code=400, detail="Dropoff must be after pickup")

    # 5. Resolve coupon (optional)
    coupon_doc = None
    if payload.coupon_code:
        coupon_doc = await db.discount_coupons.find_one(
            {"code": payload.coupon_code.strip().upper()}, {"_id": 0}
        )
        if not coupon_doc:
            raise HTTPException(status_code=404, detail="Coupon code not found")

    # 6. Compute pricing using customer ID so first-booking discount applies correctly
    pricing = await _compute_full_pricing(vehicle, pickup_dt, dropoff_dt, payload.customer_id, coupon_doc=coupon_doc)
    total_payable = pricing["total_payable"]

    # 7. Compute payment amounts based on admin's collection choice
    if payload.payment_collection == "full":
        paid_amount = total_payable
        balance_amount = 0.0
        payment_type = "full"
    elif payload.payment_collection == "partial":
        paid_amount = round(total_payable * 0.2, 2)
        balance_amount = round(total_payable - paid_amount, 2)
        payment_type = "partial"
    else:  # "none"
        paid_amount = 0.0
        balance_amount = total_payable
        payment_type = None

    # 8. Build and insert the booking document
    booking_id = str(uuid.uuid4())
    doc = {
        "id": booking_id,
        "user_id": payload.customer_id,
        "vehicle_id": payload.vehicle_id,
        "vehicle_name": vehicle["name"],
        "vehicle_image": (vehicle.get("image_urls") or [None])[0],
        "pickup_location_id": payload.pickup_location_id,
        "dropoff_location_id": payload.dropoff_location_id,
        "pickup_date": payload.pickup_date,
        "pickup_time": payload.pickup_time,
        "dropoff_date": payload.dropoff_date,
        "dropoff_time": payload.dropoff_time,
        # Pricing breakdown
        "rental_days": pricing["rental_days"],
        "rent_amount": pricing["rental_amount"],
        "long_term_discount_amount": pricing["long_term_discount"],
        "long_term_discount_pct": pricing["long_term_discount_pct"],
        "first_booking_discount_amount": pricing["first_booking_discount"],
        "first_booking_discount_pct": pricing["first_booking_discount_pct"],
        "applied_coupon_code": pricing["applied_coupon_code"],
        "coupon_discount_amount": pricing["coupon_discount"],
        "tax_amount": pricing["tax_amount"],
        "tax_rate_pct": pricing["tax_rate_pct"],
        "rental_amount_before_tax": pricing["taxable_amount"],
        "final_amount": pricing["final_amount"],
        "deposit_amount": pricing["deposit_amount"],
        "total_amount": total_payable,
        # Status & payment
        "status": "confirmed",
        "payment_type": payment_type,
        "payment_source": "admin_cash",
        "paid_amount": paid_amount,
        "balance_amount": balance_amount,
        # Audit fields
        "created_by_admin": True,
        "created_by_admin_id": admin["id"],
        "admin_notes": payload.admin_notes,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.bookings.insert_one(doc)
    doc.pop("_id", None)

    # 9. Increment coupon usage counter
    if coupon_doc:
        await db.discount_coupons.update_one(
            {"id": coupon_doc["id"]},
            {"$inc": {"used_count": 1}}
        )

    # 10. Fire confirmation email asynchronously — never block the response
    asyncio.create_task(send_booking_received_email(customer, doc))

    return doc


@api_router.get("/admin/payments")
async def all_payments(admin: dict = Depends(require_admin)):
    items = await db.payments.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items


# ------------- Discount Management System -------------

TAX_RATE = 0.18  # 18% GST on discounted rental amount (configurable)

# --- Pydantic models ---

class CouponIn(BaseModel):
    code: str = Field(..., min_length=3, max_length=20)
    discount_type: Literal["percentage", "fixed"]
    discount_value: float = Field(..., gt=0)
    minimum_amount: float = Field(default=0, ge=0)
    maximum_discount: float = Field(default=0, ge=0)   # 0 = no cap
    start_date: str   # ISO date string YYYY-MM-DD
    end_date: str
    usage_limit: int = Field(default=0, ge=0)          # 0 = unlimited
    is_active: bool = True


class CouponUpdateIn(BaseModel):
    discount_type: Optional[Literal["percentage", "fixed"]] = None
    discount_value: Optional[float] = None
    minimum_amount: Optional[float] = None
    maximum_discount: Optional[float] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    usage_limit: Optional[int] = None
    is_active: Optional[bool] = None


class BookingCalculateIn(BaseModel):
    vehicle_id: str
    pickup_date: str
    pickup_time: str
    dropoff_date: str
    dropoff_time: str


class ApplyCouponIn(BaseModel):
    vehicle_id: str
    pickup_date: str
    pickup_time: str
    dropoff_date: str
    dropoff_time: str
    coupon_code: str


class BookingWithDiscountIn(BaseModel):
    vehicle_id: str
    pickup_location_id: str
    dropoff_location_id: str
    pickup_date: str
    pickup_time: str
    dropoff_date: str
    dropoff_time: str
    coupon_code: Optional[str] = None


# --- Discount service helpers ---

def _compute_long_term_discount(rental_amount: float, days: int) -> tuple[float, float]:
    """Returns (discount_amount, discount_pct). 7-14d=5%, 15-29d=10%, 30+d=15%."""
    if days >= 30:
        pct = 15.0
    elif days >= 15:
        pct = 10.0
    elif days >= 7:
        pct = 5.0
    else:
        pct = 0.0
    return round(rental_amount * pct / 100, 2), pct


def _compute_first_booking_discount(rental_amount: float, completed_count: int) -> tuple[float, float]:
    """Returns (discount_amount, discount_pct). 10% for first-time customers."""
    if completed_count == 0:
        pct = 10.0
        return round(rental_amount * pct / 100, 2), pct
    return 0.0, 0.0


def _validate_coupon(coupon: dict, rental_amount_after_discounts: float):
    """Raises HTTPException if coupon is invalid. Raises nothing if valid."""
    now_date = datetime.now(timezone.utc).date().isoformat()
    if not coupon.get("is_active"):
        raise HTTPException(status_code=400, detail="Coupon is inactive")
    if coupon.get("end_date", "") < now_date:
        raise HTTPException(status_code=400, detail="Coupon has expired")
    if coupon.get("start_date", "") > now_date:
        raise HTTPException(status_code=400, detail="Coupon is not yet valid")
    usage_limit = coupon.get("usage_limit", 0)
    if usage_limit > 0 and coupon.get("used_count", 0) >= usage_limit:
        raise HTTPException(status_code=400, detail="Coupon usage limit reached")
    min_amount = coupon.get("minimum_amount", 0)
    if min_amount > 0 and rental_amount_after_discounts < min_amount:
        raise HTTPException(
            status_code=400,
            detail=f"Minimum booking amount of ₹{min_amount:.0f} required for this coupon"
        )


def _apply_coupon_discount(coupon: dict, amount_after_discounts: float) -> float:
    """Returns the coupon discount amount (clamped to amount so total never goes negative)."""
    if coupon["discount_type"] == "percentage":
        disc = amount_after_discounts * coupon["discount_value"] / 100
        max_disc = coupon.get("maximum_discount", 0)
        if max_disc > 0:
            disc = min(disc, max_disc)
    else:  # fixed
        disc = coupon["discount_value"]
    return round(min(disc, amount_after_discounts), 2)


async def _compute_full_pricing(
    vehicle: dict,
    pickup_dt: datetime,
    dropoff_dt: datetime,
    user_id: str,
    coupon_doc: Optional[dict] = None,
) -> dict:
    """Runs the full 8-step pricing computation and returns a pricing dict."""
    total_hours = max((dropoff_dt - pickup_dt).total_seconds() / 3600, 24)
    rental_days = max(1, int((total_hours + 23) // 24))
    rental_amount = round(vehicle["price_per_24hrs"] * rental_days, 2)
    deposit_amount = vehicle["deposit_amount"]

    # Step 2: long-term discount
    long_term_disc, long_term_pct = _compute_long_term_discount(rental_amount, rental_days)

    # Step 3: first booking discount
    completed_count = await db.bookings.count_documents({"user_id": user_id, "status": "completed"})
    first_booking_disc, first_booking_pct = _compute_first_booking_discount(rental_amount, completed_count)

    # Step 4: subtotal after auto-discounts
    subtotal = max(0.0, round(rental_amount - long_term_disc - first_booking_disc, 2))

    # Step 5: coupon discount (only if coupon supplied and valid)
    coupon_disc = 0.0
    coupon_code_applied = None
    if coupon_doc:
        _validate_coupon(coupon_doc, subtotal)
        coupon_disc = _apply_coupon_discount(coupon_doc, subtotal)
        coupon_code_applied = coupon_doc["code"]

    # Step 6-8: tax + final
    taxable = max(0.0, round(subtotal - coupon_disc, 2))
    tax_amount = round(taxable * TAX_RATE, 2)
    final_amount = round(taxable + tax_amount, 2)
    total_payable = round(final_amount + deposit_amount, 2)

    return {
        "rental_days": rental_days,
        "rental_amount": rental_amount,
        "long_term_discount": long_term_disc,
        "long_term_discount_pct": long_term_pct,
        "first_booking_discount": first_booking_disc,
        "first_booking_discount_pct": first_booking_pct,
        "coupon_discount": coupon_disc,
        "applied_coupon_code": coupon_code_applied,
        "taxable_amount": taxable,
        "tax_amount": tax_amount,
        "tax_rate_pct": TAX_RATE * 100,
        "final_amount": final_amount,
        "deposit_amount": deposit_amount,
        "total_payable": total_payable,
    }


# --- Coupon CRUD endpoints ---

@api_router.post("/coupons")
async def create_coupon(payload: CouponIn, admin: dict = Depends(require_admin)):
    code_upper = payload.code.strip().upper()
    existing = await db.discount_coupons.find_one({"code": code_upper})
    if existing:
        raise HTTPException(status_code=400, detail="Coupon code already exists")
    now_iso = datetime.now(timezone.utc).isoformat()
    doc = {
        "id": str(uuid.uuid4()),
        "code": code_upper,
        "discount_type": payload.discount_type,
        "discount_value": payload.discount_value,
        "minimum_amount": payload.minimum_amount,
        "maximum_discount": payload.maximum_discount,
        "start_date": payload.start_date,
        "end_date": payload.end_date,
        "usage_limit": payload.usage_limit,
        "used_count": 0,
        "is_active": payload.is_active,
        "created_by": admin["id"],
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    await db.discount_coupons.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.get("/coupons")
async def list_coupons(admin: dict = Depends(require_admin)):
    items = await db.discount_coupons.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items


@api_router.put("/coupons/{coupon_id}")
async def update_coupon(coupon_id: str, payload: CouponUpdateIn, admin: dict = Depends(require_admin)):
    coupon = await db.discount_coupons.find_one({"id": coupon_id})
    if not coupon:
        raise HTTPException(status_code=404, detail="Coupon not found")
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    await db.discount_coupons.update_one({"id": coupon_id}, {"$set": updates})
    doc = await db.discount_coupons.find_one({"id": coupon_id}, {"_id": 0})
    return doc


@api_router.delete("/coupons/{coupon_id}")
async def delete_coupon(coupon_id: str, admin: dict = Depends(require_admin)):
    result = await db.discount_coupons.delete_one({"id": coupon_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Coupon not found")
    return {"ok": True}


@api_router.patch("/coupons/{coupon_id}/toggle")
async def toggle_coupon(coupon_id: str, admin: dict = Depends(require_admin)):
    coupon = await db.discount_coupons.find_one({"id": coupon_id})
    if not coupon:
        raise HTTPException(status_code=404, detail="Coupon not found")
    new_status = not coupon.get("is_active", False)
    await db.discount_coupons.update_one(
        {"id": coupon_id},
        {"$set": {"is_active": new_status, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    doc = await db.discount_coupons.find_one({"id": coupon_id}, {"_id": 0})
    return doc


# --- Booking calculation endpoints ---

@api_router.post("/bookings/calculate")
async def calculate_booking(payload: BookingCalculateIn, user: dict = Depends(get_current_user)):
    vehicle = await db.vehicles.find_one({"id": payload.vehicle_id}, {"_id": 0})
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    try:
        pickup_dt = datetime.fromisoformat(f"{payload.pickup_date}T{payload.pickup_time}")
        dropoff_dt = datetime.fromisoformat(f"{payload.dropoff_date}T{payload.dropoff_time}")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date/time format")
    if dropoff_dt <= pickup_dt:
        raise HTTPException(status_code=400, detail="Dropoff must be after pickup")
    pricing = await _compute_full_pricing(vehicle, pickup_dt, dropoff_dt, user["id"])
    return pricing


@api_router.post("/bookings/apply-coupon")
async def apply_coupon_to_booking(payload: ApplyCouponIn, user: dict = Depends(get_current_user)):
    vehicle = await db.vehicles.find_one({"id": payload.vehicle_id}, {"_id": 0})
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    try:
        pickup_dt = datetime.fromisoformat(f"{payload.pickup_date}T{payload.pickup_time}")
        dropoff_dt = datetime.fromisoformat(f"{payload.dropoff_date}T{payload.dropoff_time}")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date/time format")
    if dropoff_dt <= pickup_dt:
        raise HTTPException(status_code=400, detail="Dropoff must be after pickup")
    coupon = await db.discount_coupons.find_one(
        {"code": payload.coupon_code.strip().upper()}, {"_id": 0}
    )
    if not coupon:
        raise HTTPException(status_code=404, detail="Coupon code not found")
    pricing = await _compute_full_pricing(vehicle, pickup_dt, dropoff_dt, user["id"], coupon_doc=coupon)
    return pricing


# --- Extended booking creation (with discounts) ---

@api_router.post("/bookings/create")
async def create_booking_with_discount(payload: BookingWithDiscountIn, user: dict = Depends(get_current_user)):
    vehicle = await db.vehicles.find_one({"id": payload.vehicle_id}, {"_id": 0})
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    _validate_business_hours(payload.pickup_time)
    _validate_business_hours(payload.dropoff_time)
    try:
        pickup_dt = datetime.fromisoformat(f"{payload.pickup_date}T{payload.pickup_time}")
        dropoff_dt = datetime.fromisoformat(f"{payload.dropoff_date}T{payload.dropoff_time}")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date/time")
    if dropoff_dt <= pickup_dt:
        raise HTTPException(status_code=400, detail="Dropoff must be after pickup")

    # Resolve coupon
    coupon_doc = None
    if payload.coupon_code:
        coupon_doc = await db.discount_coupons.find_one(
            {"code": payload.coupon_code.strip().upper()}, {"_id": 0}
        )
        if not coupon_doc:
            raise HTTPException(status_code=404, detail="Coupon code not found")

    pricing = await _compute_full_pricing(vehicle, pickup_dt, dropoff_dt, user["id"], coupon_doc=coupon_doc)

    status = "verified" if user.get("kyc_status") == "approved" else "pending_kyc"
    booking_id = str(uuid.uuid4())
    doc = {
        "id": booking_id,
        "user_id": user["id"],
        "vehicle_id": payload.vehicle_id,
        "vehicle_name": vehicle["name"],
        "vehicle_image": (vehicle.get("image_urls") or [None])[0],
        "pickup_location_id": payload.pickup_location_id,
        "dropoff_location_id": payload.dropoff_location_id,
        "pickup_date": payload.pickup_date,
        "pickup_time": payload.pickup_time,
        "dropoff_date": payload.dropoff_date,
        "dropoff_time": payload.dropoff_time,
        # Pricing breakdown
        "rental_days": pricing["rental_days"],
        "rent_amount": pricing["rental_amount"],
        "long_term_discount_amount": pricing["long_term_discount"],
        "long_term_discount_pct": pricing["long_term_discount_pct"],
        "first_booking_discount_amount": pricing["first_booking_discount"],
        "first_booking_discount_pct": pricing["first_booking_discount_pct"],
        "applied_coupon_code": pricing["applied_coupon_code"],
        "coupon_discount_amount": pricing["coupon_discount"],
        "tax_amount": pricing["tax_amount"],
        "tax_rate_pct": pricing["tax_rate_pct"],
        "rental_amount_before_tax": pricing["taxable_amount"],
        "final_amount": pricing["final_amount"],
        "deposit_amount": pricing["deposit_amount"],
        # total_amount = final + deposit (for payment system compatibility)
        "total_amount": pricing["total_payable"],
        "status": status,
        "payment_type": None,
        "paid_amount": 0.0,
        "balance_amount": pricing["total_payable"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.bookings.insert_one(doc)
    doc.pop("_id", None)

    # Increment coupon usage counter
    if coupon_doc:
        await db.discount_coupons.update_one(
            {"id": coupon_doc["id"]},
            {"$inc": {"used_count": 1}}
        )

    asyncio.create_task(send_booking_received_email(user, doc))
    return doc


# --- Admin discount report ---

@api_router.get("/admin/discount-report")
async def discount_report(admin: dict = Depends(require_admin)):
    pipeline = [
        {"$match": {"status": {"$nin": ["cancelled"]}}},
        {"$group": {
            "_id": None,
            "total_bookings": {"$sum": 1},
            "total_long_term_discount": {"$sum": {"$ifNull": ["$long_term_discount_amount", 0]}},
            "total_first_booking_discount": {"$sum": {"$ifNull": ["$first_booking_discount_amount", 0]}},
            "total_coupon_discount": {"$sum": {"$ifNull": ["$coupon_discount_amount", 0]}},
            "total_tax_collected": {"$sum": {"$ifNull": ["$tax_amount", 0]}},
            "bookings_with_long_term": {"$sum": {"$cond": [{"$gt": ["$long_term_discount_amount", 0]}, 1, 0]}},
            "bookings_with_first_booking": {"$sum": {"$cond": [{"$gt": ["$first_booking_discount_amount", 0]}, 1, 0]}},
            "bookings_with_coupon": {"$sum": {"$cond": [{"$gt": ["$coupon_discount_amount", 0]}, 1, 0]}},
        }},
    ]
    report = {"total_bookings": 0, "total_long_term_discount": 0, "total_first_booking_discount": 0,
              "total_coupon_discount": 0, "total_tax_collected": 0,
              "bookings_with_long_term": 0, "bookings_with_first_booking": 0, "bookings_with_coupon": 0}
    async for r in db.bookings.aggregate(pipeline):
        report.update({k: round(v, 2) for k, v in r.items() if k != "_id"})

    # Top coupons by usage
    top_coupons = await db.discount_coupons.find({}, {"_id": 0}).sort("used_count", -1).to_list(10)
    report["top_coupons"] = top_coupons
    report["total_discount_given"] = round(
        report["total_long_term_discount"] + report["total_first_booking_discount"] + report["total_coupon_discount"], 2
    )
    return report



# ------------- Vehicle Analytics -------------

@api_router.get("/admin/vehicles/search")
async def search_vehicles_by_plate(q: str = "", admin: dict = Depends(require_admin)):
    """
    Case-insensitive partial match on vehicle_number (number plate).
    Returns up to 20 matching vehicles with their details.
    """
    if not q.strip():
        return []
    pattern = q.strip().upper()
    # Use regex for partial, case-insensitive matching
    cursor = db.vehicles.find(
        {"vehicle_number": {"$regex": pattern, "$options": "i"}},
        {"_id": 0}
    ).limit(20)
    return await cursor.to_list(20)


@api_router.get("/admin/analytics/monthly")
async def monthly_analytics(
    vehicle_id: str,
    month: int,
    year: int,
    admin: dict = Depends(require_admin),
):
    """
    Monthly booking analytics for a specific vehicle.
    Returns totals for bookings, revenue, rental days, unique customers, and status breakdown.
    """
    # Validate inputs
    if not (1 <= month <= 12):
        raise HTTPException(status_code=400, detail="Month must be between 1 and 12")
    if year < 2000 or year > 2100:
        raise HTTPException(status_code=400, detail="Invalid year")

    vehicle = await db.vehicles.find_one({"id": vehicle_id}, {"_id": 0})
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")

    # Build month prefix for ISO date string matching e.g. "2026-06-"
    month_prefix = f"{year}-{month:02d}-"

    # Main aggregation pipeline
    pipeline = [
        {
            "$match": {
                "vehicle_id": vehicle_id,
                "pickup_date": {"$regex": f"^{month_prefix}"},
            }
        },
        {
            "$addFields": {
                # Compute rental days from pickup_date and dropoff_date strings
                "pickup_dt": {"$dateFromString": {"dateString": "$pickup_date"}},
                "dropoff_dt": {"$dateFromString": {"dateString": "$dropoff_date"}},
            }
        },
        {
            "$addFields": {
                "rental_days": {
                    "$max": [
                        1,
                        {
                            "$ceil": {
                                "$divide": [
                                    {"$subtract": ["$dropoff_dt", "$pickup_dt"]},
                                    86400000,  # ms per day
                                ]
                            }
                        },
                    ]
                }
            }
        },
        {
            "$facet": {
                "totals": [
                    {
                        "$group": {
                            "_id": None,
                            "totalBookings": {"$sum": 1},
                            "totalRevenue": {"$sum": "$rent_amount"},
                            "totalRentalDays": {"$sum": "$rental_days"},
                            "uniqueCustomers": {"$addToSet": "$user_id"},
                        }
                    }
                ],
                "statusBreakdown": [
                    {
                        "$group": {
                            "_id": "$status",
                            "count": {"$sum": 1},
                        }
                    }
                ],
            }
        },
    ]

    result = await db.bookings.aggregate(pipeline).to_list(1)

    if not result:
        totals = {}
        status_breakdown = []
    else:
        totals = result[0]["totals"][0] if result[0]["totals"] else {}
        status_breakdown = result[0]["statusBreakdown"]

    # Build status summary map
    status_map = {s["_id"]: s["count"] for s in status_breakdown}

    return {
        "vehicleId": vehicle_id,
        "vehicleName": vehicle.get("name"),
        "vehicleNumber": vehicle.get("vehicle_number"),
        "month": month,
        "year": year,
        "totalBookings": totals.get("totalBookings", 0),
        "totalRevenue": round(totals.get("totalRevenue", 0), 2),
        "totalRentalDays": int(totals.get("totalRentalDays", 0)),
        "uniqueCustomers": len(totals.get("uniqueCustomers", [])),
        "statusSummary": {
            "completed": status_map.get("completed", 0),
            "active": status_map.get("active", 0),
            "confirmed": status_map.get("confirmed", 0),
            "cancelled": status_map.get("cancelled", 0),
            "pending_kyc": status_map.get("pending_kyc", 0),
            "verified": status_map.get("verified", 0),
        },
    }


@api_router.get("/admin/analytics/yearly")
async def yearly_analytics(
    vehicle_id: str,
    year: int,
    admin: dict = Depends(require_admin),
):
    """
    Yearly booking analytics for a specific vehicle.
    Returns totals, monthly breakdown, and most-active month.
    """
    if year < 2000 or year > 2100:
        raise HTTPException(status_code=400, detail="Invalid year")

    vehicle = await db.vehicles.find_one({"id": vehicle_id}, {"_id": 0})
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")

    year_prefix = str(year)

    MONTH_NAMES = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December",
    ]

    pipeline = [
        {
            "$match": {
                "vehicle_id": vehicle_id,
                "pickup_date": {"$regex": f"^{year_prefix}-"},
            }
        },
        {
            "$addFields": {
                "pickup_dt": {"$dateFromString": {"dateString": "$pickup_date"}},
                "dropoff_dt": {"$dateFromString": {"dateString": "$dropoff_date"}},
            }
        },
        {
            "$addFields": {
                "rental_days": {
                    "$max": [
                        1,
                        {
                            "$ceil": {
                                "$divide": [
                                    {"$subtract": ["$dropoff_dt", "$pickup_dt"]},
                                    86400000,
                                ]
                            }
                        },
                    ]
                },
                "month_num": {"$month": "$pickup_dt"},
            }
        },
        {
            "$facet": {
                "totals": [
                    {
                        "$group": {
                            "_id": None,
                            "totalBookings": {"$sum": 1},
                            "totalRevenue": {"$sum": "$rent_amount"},
                            "totalRentalDays": {"$sum": "$rental_days"},
                        }
                    }
                ],
                "monthly": [
                    {
                        "$group": {
                            "_id": "$month_num",
                            "bookings": {"$sum": 1},
                            "revenue": {"$sum": "$rent_amount"},
                            "rentalDays": {"$sum": "$rental_days"},
                        }
                    },
                    {"$sort": {"_id": 1}},
                ],
            }
        },
    ]

    result = await db.bookings.aggregate(pipeline).to_list(1)

    if not result:
        totals_raw = {}
        monthly_raw = []
    else:
        totals_raw = result[0]["totals"][0] if result[0]["totals"] else {}
        monthly_raw = result[0]["monthly"]

    # Build full 12-month array (fill gaps with zeros)
    monthly_map = {r["_id"]: r for r in monthly_raw}
    monthly_bookings = []
    for i in range(1, 13):
        entry = monthly_map.get(i, {})
        monthly_bookings.append({
            "month": MONTH_NAMES[i - 1],
            "monthNum": i,
            "bookings": entry.get("bookings", 0),
            "revenue": round(entry.get("revenue", 0), 2),
            "rentalDays": int(entry.get("rentalDays", 0)),
        })

    # Most active month by booking count
    most_active = max(monthly_bookings, key=lambda x: x["bookings"], default=None)

    return {
        "vehicleId": vehicle_id,
        "vehicleName": vehicle.get("name"),
        "vehicleNumber": vehicle.get("vehicle_number"),
        "year": year,
        "totalBookings": totals_raw.get("totalBookings", 0),
        "totalRevenue": round(totals_raw.get("totalRevenue", 0), 2),
        "totalRentalDays": int(totals_raw.get("totalRentalDays", 0)),
        "mostActiveMonth": most_active["month"] if most_active and most_active["bookings"] > 0 else None,
        "monthlyBookings": monthly_bookings,
    }


# ------------- Admin dashboard metrics + customers -------------
@api_router.get("/admin/metrics")
async def admin_metrics(admin: dict = Depends(require_admin)):
    total_bookings = await db.bookings.count_documents({})
    active_bookings = await db.bookings.count_documents({"status": {"$in": ["confirmed", "active", "verified"]}})
    completed_bookings = await db.bookings.count_documents({"status": "completed"})
    pending_kyc_count = await db.users.count_documents({"kyc_status": "pending"})
    total_vehicles = await db.vehicles.count_documents({})
    available_vehicles = await db.vehicles.count_documents({"is_available": True})
    total_customers = await db.users.count_documents({"role": "customer"})

    pipeline = [
        {"$match": {"status": "success"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
    ]
    revenue_cursor = db.payments.aggregate(pipeline)
    revenue = 0.0
    async for r in revenue_cursor:
        revenue = r.get("total", 0.0)

    # Pending balance from confirmed partial bookings
    pipeline2 = [
        {"$match": {"balance_amount": {"$gt": 0}, "status": {"$in": ["confirmed", "active"]}}},
        {"$group": {"_id": None, "total": {"$sum": "$balance_amount"}}},
    ]
    pending_balance = 0.0
    async for r in db.bookings.aggregate(pipeline2):
        pending_balance = r.get("total", 0.0)

    utilization = round((active_bookings / total_vehicles) * 100, 1) if total_vehicles else 0.0

    return {
        "total_bookings": total_bookings,
        "active_bookings": active_bookings,
        "completed_bookings": completed_bookings,
        "pending_kyc": pending_kyc_count,
        "total_vehicles": total_vehicles,
        "available_vehicles": available_vehicles,
        "total_customers": total_customers,
        "revenue": revenue,
        "pending_balance": pending_balance,
        "fleet_utilization": utilization,
    }


@api_router.get("/admin/customers")
async def list_customers(admin: dict = Depends(require_admin)):
    users = await db.users.find({"role": "customer"}, {"_id": 0, "password_hash": 0}).to_list(500)
    for u in users:
        u["booking_count"] = await db.bookings.count_documents({"user_id": u["id"]})
    return [serialize_user(u) | {"booking_count": u.get("booking_count", 0)} for u in users]


@api_router.get("/admin/customers/{customer_id}")
async def get_customer_detail(customer_id: str, admin: dict = Depends(require_admin)):
    u = await db.users.find_one({"id": customer_id, "role": "customer"}, {"_id": 0, "password_hash": 0})
    if not u:
        raise HTTPException(status_code=404, detail="Customer not found")
    bookings = await db.bookings.find({"user_id": customer_id}, {"_id": 0}).sort("created_at", -1).to_list(100)
    kyc_docs = await db.kyc_documents.find({"user_id": customer_id}, {"_id": 0}).to_list(20)
    customer = serialize_user(u)
    customer["booking_count"] = len(bookings)
    total_spent = sum(b.get("paid_amount", 0) or 0 for b in bookings)
    customer["total_spent"] = total_spent
    return {"customer": customer, "bookings": bookings, "kyc_documents": kyc_docs}


# ------------- Health -------------
@api_router.get("/")
async def root():
    return {"message": "Royal Cars API", "status": "ok"}


# ------------- Mount & CORS -------------
app.include_router(api_router)

cors_origins = [FRONTEND_URL, "http://localhost:3000", "http://localhost:5173", "https://royalrentalcars.in"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------- Startup: seed + indexes -------------
async def seed_locations():
    count = await db.locations.count_documents({})
    if count == 0:
        defaults = [
            {"id": str(uuid.uuid4()), "name": "Kharghar - Little World Mall", "address": "Sector 2, Kharghar, Navi Mumbai", "is_active": True, "created_at": datetime.now(timezone.utc).isoformat()},
            {"id": str(uuid.uuid4()), "name": "Panvel - Orion Mall", "address": "Panvel, Navi Mumbai", "is_active": True, "created_at": datetime.now(timezone.utc).isoformat()},
        ]
        await db.locations.insert_many(defaults)
        logger.info("Seeded default locations")


async def seed_admin():
    existing = await db.users.find_one({"email": ADMIN_EMAIL})
    if not existing:
        await db.users.insert_one({
            "id": str(uuid.uuid4()),
            "email": ADMIN_EMAIL,
            "password_hash": hash_password(ADMIN_PASSWORD),
            "name": "Royal Cars Admin",
            "phone": "+91-0000000000",
            "role": "admin",
            "kyc_status": "approved",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"Seeded admin: {ADMIN_EMAIL}")
    elif not verify_password(ADMIN_PASSWORD, existing["password_hash"]):
        await db.users.update_one({"email": ADMIN_EMAIL}, {"$set": {"password_hash": hash_password(ADMIN_PASSWORD), "role": "admin"}})
        logger.info("Updated admin password")


async def seed_demo_vehicles():
    if await db.vehicles.count_documents({}) > 0:
        return
    locs = await db.locations.find({}, {"_id": 0}).to_list(10)
    if not locs:
        return
    loc_kharghar = next((loc for loc in locs if "Kharghar" in loc["name"]), locs[0])
    loc_panvel = next((loc for loc in locs if "Panvel" in loc["name"]), locs[-1])
    demo = [
        {
            "name": "Hyundai Creta", "type": "SUV", "fuel_type": "Petrol",
            "image_urls": ["https://images.unsplash.com/photo-1758411898312-8592bb81e30d?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDk1Nzd8MHwxfHNlYXJjaHwzfHxwcmVtaXVtJTIwd2hpdGUlMjBzdXYlMjBjYXJ8ZW58MHx8fHwxNzc2NzY1MTM5fDA&ixlib=rb-4.1.0&q=85"],
            "price_per_24hrs": 2800, "deposit_amount": 5000, "is_available": True,
            "location_id": loc_kharghar["id"], "description": "Spacious SUV with premium interiors.",
            "seats": 5, "transmission": "Manual",
        },
        {
            "name": "Maruti Swift", "type": "Hatchback", "fuel_type": "Petrol",
            "image_urls": ["https://images.unsplash.com/photo-1549317661-bd32c8ce0db2?auto=format&fit=crop&w=940&q=80"],
            "price_per_24hrs": 1500, "deposit_amount": 3000, "is_available": True,
            "location_id": loc_kharghar["id"], "description": "Efficient city hatchback, easy to drive.",
            "seats": 5, "transmission": "Manual",
        },
        {
            "name": "Toyota Innova Crysta", "type": "MPV", "fuel_type": "Diesel",
            "image_urls": ["https://images.pexels.com/photos/19410427/pexels-photo-19410427.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940"],
            "price_per_24hrs": 3800, "deposit_amount": 7000, "is_available": True,
            "location_id": loc_panvel["id"], "description": "Family MPV with 7 seats and plenty of space.",
            "seats": 7, "transmission": "Manual",
        },
        {
            "name": "Honda City", "type": "Sedan", "fuel_type": "Petrol",
            "image_urls": ["https://images.unsplash.com/photo-1552519507-da3b142c6e3d?auto=format&fit=crop&w=940&q=80"],
            "price_per_24hrs": 2200, "deposit_amount": 4000, "is_available": True,
            "location_id": loc_panvel["id"], "description": "Premium sedan with automatic transmission.",
            "seats": 5, "transmission": "Automatic",
        },
    ]
    for v in demo:
        v["id"] = str(uuid.uuid4())
        v["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.vehicles.insert_many(demo)
    logger.info("Seeded demo vehicles")


@app.on_event("startup")
async def on_startup():
    # Indexes
    await db.users.create_index("email", unique=True)
    await db.bookings.create_index("user_id")
    await db.bookings.create_index("status")
    await db.kyc_documents.create_index("user_id")
    await db.vehicles.create_index("location_id")
    # Discount indexes
    await db.discount_coupons.create_index("code", unique=True)
    await db.discount_coupons.create_index("is_active")
    # Analytics indexes
    await db.vehicles.create_index("vehicle_number")
    await db.bookings.create_index("vehicle_id")
    await db.bookings.create_index("pickup_date")
    await db.bookings.create_index("created_at")
    # Seed
    await seed_admin()
    await seed_locations()
    await seed_demo_vehicles()


@app.on_event("shutdown")
async def on_shutdown():
    client.close()
