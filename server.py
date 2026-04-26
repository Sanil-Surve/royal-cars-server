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
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 60 * 24  # 1 day for smooth demo
REFRESH_TOKEN_DAYS = 7

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
    secure=True,
)

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
    response.set_cookie("access_token", access, httponly=True, secure=True, samesite="none", max_age=ACCESS_TOKEN_MINUTES * 60, path="/")
    response.set_cookie("refresh_token", refresh, httponly=True, secure=True, samesite="none", max_age=REFRESH_TOKEN_DAYS * 86400, path="/")


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
    payment_type: Literal["full", "partial"]


class PaymentVerifyPayload(BaseModel):
    booking_id: str
    payment_id: str


class BookingStatusPayload(BaseModel):
    status: Literal["pending_kyc", "verified", "confirmed", "active", "completed", "cancelled"]


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
        response.set_cookie("access_token", access, httponly=True, secure=True, samesite="none", max_age=ACCESS_TOKEN_MINUTES * 60, path="/")
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
    if payload.status == "rejected":
        new_status = "rejected"
    elif types_present >= KYC_DOC_TYPES and all(d["verification_status"] == "approved" for d in all_docs):
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


@api_router.post("/bookings")
async def create_booking(payload: BookingIn, user: dict = Depends(get_current_user)):
    vehicle = await db.vehicles.find_one({"id": payload.vehicle_id}, {"_id": 0})
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
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


# ------------- Payments (mock Razorpay) -------------
@api_router.post("/payments/init")
async def payment_init(payload: PaymentInitPayload, user: dict = Depends(get_current_user)):
    booking = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    if not booking or booking["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")
    if booking["status"] not in {"verified", "confirmed"}:
        raise HTTPException(status_code=400, detail="Booking not ready for payment. KYC must be approved first.")
    amount = booking["total_amount"] if payload.payment_type == "full" else round(booking["total_amount"] * 0.2, 2)
    order_id = f"order_mock_{uuid.uuid4().hex[:12]}"
    await db.payments.insert_one({
        "id": str(uuid.uuid4()),
        "booking_id": payload.booking_id,
        "amount": amount,
        "payment_type": "full" if payload.payment_type == "full" else "partial_advance",
        "razorpay_order_id": order_id,
        "razorpay_payment_id": None,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"order_id": order_id, "amount": amount, "currency": "INR", "key": "rzp_test_mock"}


@api_router.post("/payments/verify")
async def payment_verify(payload: PaymentVerifyPayload, user: dict = Depends(get_current_user)):
    booking = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    if not booking or booking["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")
    # Mark most recent pending payment as success
    pending = await db.payments.find_one(
        {"booking_id": payload.booking_id, "status": "pending"},
        sort=[("created_at", -1)],
    )
    if not pending:
        raise HTTPException(status_code=400, detail="No pending payment")
    paid_amount = booking.get("paid_amount", 0) + pending["amount"]
    balance = round(booking["total_amount"] - paid_amount, 2)
    await db.payments.update_one(
        {"id": pending["id"]},
        {"$set": {
            "razorpay_payment_id": payload.payment_id,
            "status": "success",
            "paid_at": datetime.now(timezone.utc).isoformat(),
        }},
    )
    new_status = "confirmed"
    payment_type = "full" if abs(balance) < 0.01 else "partial"
    await db.bookings.update_one(
        {"id": payload.booking_id},
        {"$set": {
            "status": new_status,
            "paid_amount": paid_amount,
            "balance_amount": max(balance, 0),
            "payment_type": payment_type,
        }},
    )
    b = await db.bookings.find_one({"id": payload.booking_id}, {"_id": 0})
    return b


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

cors_origins = [FRONTEND_URL, "http://localhost:5173"]
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
