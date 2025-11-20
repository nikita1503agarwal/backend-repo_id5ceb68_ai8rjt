import os
from datetime import datetime, timedelta, timezone, date
from typing import List, Optional, Dict

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
import hashlib
from passlib.context import CryptContext

from database import db, create_document, get_documents
from schemas import User, Cycle, Prediction, Payment, AnalyticsEvent

# --- Config ---
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = "HS256"
ACCESS_TTL_MIN = int(os.getenv("ACCESS_TTL_MIN", "60"))
REFRESH_TTL_DAYS = int(os.getenv("REFRESH_TTL_DAYS", "30"))

STRIPE_SECRET = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="CycleSync Pro API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# --- Helpers ---

def now_utc():
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_tokens(user: dict) -> Dict[str, str]:
    payload = {"sub": str(user.get("_id")), "email": user["email"], "roles": user.get("roles", ["user"]), "exp": now_utc() + timedelta(minutes=ACCESS_TTL_MIN), "type": "access"}
    access = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    refresh = jwt.encode({"sub": str(user.get("_id")), "type": "refresh", "exp": now_utc() + timedelta(days=REFRESH_TTL_DAYS)}, JWT_SECRET, algorithm=JWT_ALG)
    return {"access": access, "refresh": refresh}


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        data = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        if data.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = db["user"].find_one({"_id": db.client.get_default_database().codec_options.document_class.objectid_class(data["sub"])})
        # Fallback simple lookup by string id if above fails
        if not user:
            user = db["user"].find_one({"_id": data["sub"]})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_roles(*roles):
    def wrapper(user=Depends(get_current_user)):
        user_roles = user.get("roles", [])
        if any(r in user_roles for r in roles):
            return user
        raise HTTPException(status_code=403, detail="Forbidden")
    return wrapper


# --- Schemas for requests ---
class RegisterPayload(BaseModel):
    email: str
    password: str

class LoginPayload(BaseModel):
    email: str
    password: str

class GoogleLoginPayload(BaseModel):
    id_token: str

class CyclePayload(Cycle):
    pass


# --- Routes ---
@app.get("/")
def root():
    return {"name": "CycleSync Pro API", "status": "ok"}

@app.get("/test")
def test_database():
    info = {"backend": "ok", "database": "down"}
    try:
        db.list_collection_names()
        info["database"] = "ok"
    except Exception as e:
        info["error"] = str(e)
    return info

# Auth
@app.post("/api/auth/register")
def register(payload: RegisterPayload):
    existing = db["user"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        providers=["password"],
    ).model_dump()
    uid = create_document("user", user)
    user["_id"] = uid
    tokens = create_tokens(user)
    return {"user": {"email": user["email"], "roles": user.get("roles", ["user"])}, "tokens": tokens}

@app.post("/api/auth/login")
def login(payload: LoginPayload):
    user = db["user"].find_one({"email": payload.email.lower()})
    if not user or not user.get("password_hash") or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    tokens = create_tokens(user)
    return {"user": {"email": user["email"], "roles": user.get("roles", ["user"])}, "tokens": tokens}

@app.post("/api/auth/google")
def google_login(payload: GoogleLoginPayload):
    # Minimal verification of Google ID token signature
    # In production, validate with google.oauth2.id_token.verify_oauth2_token
    from google.oauth2 import id_token
    from google.auth.transport import requests as grequests

    try:
        idinfo = id_token.verify_oauth2_token(payload.id_token, grequests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Google token missing email")
        user = db["user"].find_one({"email": email.lower()})
        if not user:
            user = User(email=email.lower(), providers=["google"], roles=["user"]).model_dump()
            uid = create_document("user", user)
            user["_id"] = uid
        tokens = create_tokens(user)
        return {"user": {"email": email, "roles": user.get("roles", ["user"])}, "tokens": tokens}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Google auth failed: {str(e)}")

# Cycles
@app.get("/api/cycles")
def list_cycles(user=Depends(get_current_user)):
    docs = get_documents("cycle", {"user_id": str(user.get("_id"))})
    return {"items": docs}

@app.post("/api/cycles")
def create_cycle(payload: CyclePayload, user=Depends(get_current_user)):
    data = payload.model_dump()
    data["user_id"] = str(user.get("_id"))
    cid = create_document("cycle", data)
    return {"id": cid}

# Prediction engine (rules + stats)
@app.get("/api/predictions")
def predictions(user=Depends(get_current_user)):
    cycles = get_documents("cycle", {"user_id": str(user.get("_id"))})
    if not cycles:
        return {"prediction": None, "message": "Add at least one cycle to get predictions"}

    # Compute average cycle length and period length
    lengths = []
    period_lengths = []
    for c in cycles:
        try:
            s = datetime.fromisoformat(str(c["start_date"]))
            e = datetime.fromisoformat(str(c.get("end_date") or c["start_date"]))
            period_lengths.append((e - s).days + 1)
            lengths.append((s - datetime.fromisoformat(str(cycles[0]["start_date"]))).days)  # fallback simplistic
        except Exception:
            pass

    avg_period = max(1, int(sum(period_lengths)/len(period_lengths))) if period_lengths else 5
    # Estimate cycle length as 28 if insufficient data
    avg_cycle = 28
    if len(cycles) >= 2:
        cycles_sorted = sorted(cycles, key=lambda x: x["start_date"]) 
        diffs = []
        for i in range(1, len(cycles_sorted)):
            s_prev = datetime.fromisoformat(str(cycles_sorted[i-1]["start_date"]))
            s_curr = datetime.fromisoformat(str(cycles_sorted[i]["start_date"]))
            diffs.append((s_curr - s_prev).days)
        if diffs:
            avg_cycle = int(sum(diffs)/len(diffs))

    last_start = max([datetime.fromisoformat(str(c["start_date"])) for c in cycles])
    next_period_start = (last_start + timedelta(days=avg_cycle)).date()
    ovulation_date = (last_start + timedelta(days=max(14, avg_cycle - 14))).date()
    fertile_window = [ (ovulation_date - timedelta(days=2)) + timedelta(days=i) for i in range(5) ]

    # Simple confidence: based on number of cycles and variance
    confidence = min(0.95, 0.5 + 0.1*len(cycles))

    pred = {
        "next_period_start": str(next_period_start),
        "ovulation_date": str(ovulation_date),
        "fertile_window": [str(d) for d in fertile_window],
        "confidence": round(confidence, 2),
        "method": "rules+stats"
    }
    return {"prediction": pred}

# Google Calendar: one-way push (stub metadata; token storage omitted)
class CalendarSyncPayload(BaseModel):
    events: List[Dict]

@app.post("/api/calendar/sync")
def calendar_sync(payload: CalendarSyncPayload, user=Depends(get_current_user)):
    # In production, use stored OAuth tokens to push events to Google Calendar API
    # Here we just acknowledge receipt and return what would be created
    return {"status": "queued", "count": len(payload.events)}

# Stripe subscriptions
try:
    import stripe
    stripe.api_key = STRIPE_SECRET
except Exception:
    stripe = None

class SubscribePayload(BaseModel):
    price_id: str  # frontend provides correct Price ID

@app.post("/api/payments/subscribe")
def subscribe(payload: SubscribePayload, request: Request, user=Depends(get_current_user)):
    if not stripe:
        raise HTTPException(status_code=500, detail="Stripe not configured")
    domain = request.headers.get("origin") or "http://localhost:3000"
    customer_id = user.get("subscription", {}).get("stripe_customer_id")
    try:
        if not customer_id:
            customer = stripe.Customer.create(email=user["email"])
            customer_id = customer.id
            db["user"].update_one({"_id": user["_id"]}, {"$set": {"subscription.stripe_customer_id": customer_id}})
        session = stripe.checkout.Session.create(
            mode="subscription",
            customer=customer_id,
            line_items=[{"price": payload.price_id, "quantity": 1}],
            allow_promotion_codes=True,
            success_url=f"{domain}/dashboard?status=success",
            cancel_url=f"{domain}/settings?status=canceled",
            subscription_data={"trial_period_days": 14}
        )
        return {"checkoutUrl": session.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

from fastapi import Response

@app.post("/api/payments/webhook")
async def stripe_webhook(request: Request):
    if not stripe:
        return Response(status_code=200)
    payload = await request.body()
    sig = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return Response(status_code=400)

    etype = event["type"]
    data = event["data"]["object"]
    # Minimal handling for subscription lifecycle
    if etype in ["customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"]:
        sub = data
        customer_id = sub.get("customer")
        status = sub.get("status")
        db["user"].update_one({"subscription.stripe_customer_id": customer_id}, {"$set": {"subscription.status": status, "subscription.stripe_subscription_id": sub.get("id")}})
        create_document("payment", {"user_id": "", "stripe_event": etype, "status": status, "subscription_id": sub.get("id")})
    return Response(status_code=200)

# Analytics
@app.get("/api/analytics")
def analytics(user=Depends(require_roles("admin", "super-admin"))):
    users = db["user"].count_documents({})
    premium = db["user"].count_documents({"subscription.tier": "premium", "subscription.status": {"$in": ["active", "trialing"]}})
    enterprise = db["user"].count_documents({"subscription.tier": "enterprise", "subscription.status": {"$in": ["active", "trialing"]}})
    cycles = db["cycle"].count_documents({})
    return {"users": users, "premium": premium, "enterprise": enterprise, "cycles": cycles}

# Simple rate limiting (IP + route). In production use Redis.
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict

requests_counter = defaultdict(list)

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        key = f"{request.client.host}:{request.url.path}"
        now = datetime.now().timestamp()
        window = 60
        max_req = 120
        recent = [t for t in requests_counter[key] if now - t < window]
        recent.append(now)
        requests_counter[key] = recent
        if len(recent) > max_req:
            return Response(status_code=429)
        return await call_next(request)

app.add_middleware(RateLimitMiddleware)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
