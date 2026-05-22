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
import razorpay
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

RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET") or ""
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)) if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET else None

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
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


class BookingStatusPayload(BaseModel):
    status: Literal["pending_kyc", "verified", "confirmed", "active", "completed", "cancelled"]


class StartRidePayload(BaseModel):
    odometer_start: float = Field(..., ge=0, description="Starting odometer reading in km")
    fuel_level_start: Optional[str] = Field(None, description="Starting fuel level e.g. 'Full', '3/4', '1/2', '1/4'")
    photo_urls: List[str] = Field(default=[], description="Pickup condition photo URLs")
    notes: Optional[str] = None


class EndRidePayload(BaseModel):
    odometer_end: float = Field(..., ge=0, description="Ending odometer reading in km")
    fuel_level_end: Optional[str] = Field(None, description="Ending fuel level")
    photo_urls: List[str] = Field(default=[], description="Return condition photo URLs")
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


# ------------- File upload (generic) -------------
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


# ------------- Payments (Razorpay) -------------
def _ensure_razorpay():
    if not razorpay_client:
        raise HTTPException(status_code=500, detail="Razorpay not configured on server")


async def _get_or_create_razorpay_customer(user: dict) -> Optional[str]:
    existing = user.get("razorpay_customer_id")
    if existing:
        return existing
    try:
        cust = razorpay_client.customer.create({
            "name": user.get("name") or "Customer",
            "email": user["email"],
            "contact": user.get("phone") or "",
            "fail_existing": "0",
        })
        cid = cust.get("id")
        if cid:
            await db.users.update_one({"id": user["id"]}, {"$set": {"razorpay_customer_id": cid}})
        return cid
    except Exception as e:
        logger.warning(f"Razorpay customer create failed: {e}")
        return None


@api_router.post("/payments/init")
async def payment_init(payload: PaymentInitPayload, user: dict = Depends(get_current_user)):
    _ensure_razorpay()
    booking = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    if not booking or booking["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")
    if booking["status"] not in {"verified", "confirmed", "active"}:
        raise HTTPException(status_code=400, detail="Booking not ready for payment. KYC must be approved first.")

    if payload.payment_type == "full":
        amount = booking["total_amount"] - booking.get("paid_amount", 0)
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

    amount_paise = int(round(amount * 100))
    customer_id = await _get_or_create_razorpay_customer(user)

    receipt = f"bk_{payload.booking_id[:30]}"
    order_opts = {
        "amount": amount_paise,
        "currency": "INR",
        "receipt": receipt,
        "payment_capture": 1,
        "notes": {
            "booking_id": booking["id"],
            "user_id": user["id"],
            "payment_type": record_type,
        },
    }
    try:
        order = razorpay_client.order.create(order_opts)
    except Exception as e:
        logger.error(f"Razorpay order create failed: {e}")
        raise HTTPException(status_code=500, detail=f"Payment init failed: {e}")

    await db.payments.insert_one({
        "id": str(uuid.uuid4()),
        "booking_id": payload.booking_id,
        "amount": amount,
        "payment_type": record_type,
        "razorpay_order_id": order["id"],
        "razorpay_payment_id": None,
        "razorpay_customer_id": customer_id,
        "status": "pending",
        "is_balance_charge": record_type == "balance",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    return {
        "order_id": order["id"],
        "amount": amount_paise,
        "currency": "INR",
        "key": RAZORPAY_KEY_ID,
        "customer_id": customer_id,
        "save_token": payload.payment_type == "partial",
        "prefill": {
            "name": user.get("name") or "",
            "email": user["email"],
            "contact": user.get("phone") or "",
        },
        "notes": order_opts["notes"],
    }


@api_router.post("/payments/verify")
async def payment_verify(payload: PaymentVerifyPayload, user: dict = Depends(get_current_user)):
    _ensure_razorpay()
    booking = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    if not booking or booking["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")

    try:
        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": payload.razorpay_order_id,
            "razorpay_payment_id": payload.razorpay_payment_id,
            "razorpay_signature": payload.razorpay_signature,
        })
    except razorpay.errors.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Payment signature verification failed")

    # Fetch payment to capture token_id (saved card) if any
    token_id = None
    try:
        p = razorpay_client.payment.fetch(payload.razorpay_payment_id)
        token_id = p.get("token_id")
    except Exception as e:
        logger.warning(f"Payment fetch failed: {e}")

    pending = await db.payments.find_one(
        {"razorpay_order_id": payload.razorpay_order_id, "status": "pending"},
        sort=[("created_at", -1)],
    )
    if not pending:
        raise HTTPException(status_code=400, detail="Order not found or already processed")

    await db.payments.update_one(
        {"id": pending["id"]},
        {"$set": {
            "razorpay_payment_id": payload.razorpay_payment_id,
            "razorpay_signature": payload.razorpay_signature,
            "razorpay_token_id": token_id,
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
    if token_id and pending.get("payment_type") == "partial_advance":
        update["razorpay_token_id"] = token_id
        update["razorpay_customer_id"] = pending.get("razorpay_customer_id")
    await db.bookings.update_one({"id": payload.booking_id}, {"$set": update})
    fresh = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    payment_kind = "partial" if fresh.get("balance_amount", 0) > 0 else "full"
    asyncio.create_task(send_booking_confirmed_email(user, fresh, payment_kind=payment_kind))
    return fresh


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


@api_router.post("/admin/bookings/{booking_id}/charge-balance")
async def admin_charge_balance(booking_id: str, admin: dict = Depends(require_admin)):
    _ensure_razorpay()
    booking = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    balance = booking.get("balance_amount", 0)
    if balance <= 0:
        raise HTTPException(status_code=400, detail="No balance due")
    customer_id = booking.get("razorpay_customer_id")
    token_id = booking.get("razorpay_token_id")
    if not customer_id or not token_id:
        raise HTTPException(status_code=400, detail="No saved payment method on this booking. Collect at pickup manually or mark paid.")

    user = await db.users.find_one({"id": booking["user_id"]}, {"_id": 0, "password_hash": 0})
    balance_paise = int(round(balance * 100))
    try:
        order = razorpay_client.order.create({
            "amount": balance_paise,
            "currency": "INR",
            "receipt": f"bal_{booking_id[:30]}",
            "payment_capture": 1,
            "notes": {"booking_id": booking_id, "type": "balance_charge"},
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Order create failed: {e}")

    try:
        result = razorpay_client.payment.create_recurring_payment({
            "email": user["email"],
            "contact": user.get("phone") or "",
            "amount": balance_paise,
            "currency": "INR",
            "order_id": order["id"],
            "customer_id": customer_id,
            "token": token_id,
            "recurring": "1",
            "description": f"Balance for booking {booking_id[:8]}",
        })
    except Exception as e:
        logger.error(f"Recurring payment failed: {e}")
        raise HTTPException(status_code=502, detail=f"Auto-charge failed: {str(e)[:200]}. Customer can pay at pickup.")

    payment_id = result.get("razorpay_payment_id") or result.get("id")
    await db.payments.insert_one({
        "id": str(uuid.uuid4()),
        "booking_id": booking_id,
        "amount": balance,
        "payment_type": "balance",
        "razorpay_order_id": order["id"],
        "razorpay_payment_id": payment_id,
        "razorpay_customer_id": customer_id,
        "status": "success",
        "is_balance_charge": True,
        "paid_at": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    await db.bookings.update_one({"id": booking_id}, {"$set": {
        "paid_amount": booking["total_amount"],
        "balance_amount": 0,
        "payment_type": "full",
    }})
    return {"ok": True, "payment_id": payment_id}


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
        "razorpay_order_id": None,
        "razorpay_payment_id": None,
        "status": "success",
        "is_balance_charge": True,
        "paid_at": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    await db.bookings.update_one({"id": booking_id}, {"$set": {
        "paid_amount": booking["total_amount"],
        "balance_amount": 0,
        "payment_type": "full",
    }})
    return {"ok": True}


@api_router.post("/payments/webhook")
async def razorpay_webhook(request: Request):
    """Idempotent async confirmation. Only active when RAZORPAY_WEBHOOK_SECRET is set."""
    if not RAZORPAY_WEBHOOK_SECRET:
        return {"status": "webhook_disabled"}
    body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature", "")
    expected = hmac.new(RAZORPAY_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=400, detail="Invalid signature")
    import json as _json
    event = _json.loads(body.decode())
    event_type = event.get("event")
    entity = (event.get("payload", {}).get("payment") or {}).get("entity") or {}
    payment_id = entity.get("id")
    order_id = entity.get("order_id")
    if event_type == "payment.captured" and order_id:
        await db.payments.update_one(
            {"razorpay_order_id": order_id},
            {"$set": {"razorpay_payment_id": payment_id, "status": "success", "webhook_captured_at": datetime.now(timezone.utc).isoformat()}},
        )
    elif event_type == "payment.failed" and order_id:
        await db.payments.update_one(
            {"razorpay_order_id": order_id},
            {"$set": {"status": "failed", "webhook_failed_at": datetime.now(timezone.utc).isoformat()}},
        )
    return {"status": "processed"}


@api_router.get("/admin/payments")
async def all_payments(admin: dict = Depends(require_admin)):
    items = await db.payments.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items


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
    # Seed
    await seed_admin()
    await seed_locations()
    await seed_demo_vehicles()


@app.on_event("shutdown")
async def on_shutdown():
    client.close()
