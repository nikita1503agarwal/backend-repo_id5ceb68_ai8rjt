"""
CycleSync Pro Database Schemas

Each Pydantic model represents a MongoDB collection. Collection name = lowercase class name.

Models:
- User: auth, profile, roles, subscription
- Cycle: period logs, symptoms, metrics, sexual activity, tags
- Prediction: prediction snapshots and accuracy
- Payment: subscription and invoices
- AnalyticsEvent: usage events for BI
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Literal, Dict
from datetime import date, datetime

class SubscriptionPlan(BaseModel):
    tier: Literal["free", "premium", "enterprise"] = "free"
    status: Literal["inactive", "trialing", "active", "past_due", "canceled"] = "inactive"
    stripe_customer_id: Optional[str] = None
    stripe_subscription_id: Optional[str] = None
    trial_end: Optional[datetime] = None

class GoogleIntegration(BaseModel):
    connected: bool = False
    email: Optional[str] = None
    calendar_id: Optional[str] = None
    # Tokens are stored encrypted server-side; only metadata here

class Profile(BaseModel):
    display_name: Optional[str] = None
    birth_year: Optional[int] = Field(None, ge=1900, le=2100)
    height_cm: Optional[float] = Field(None, ge=50, le=250)
    weight_kg: Optional[float] = Field(None, ge=20, le=400)
    cycle_length_avg: Optional[int] = Field(None, ge=15, le=60)
    period_length_avg: Optional[int] = Field(None, ge=1, le=10)

class User(BaseModel):
    email: str
    password_hash: Optional[str] = None
    providers: List[str] = ["password"]
    roles: List[str] = ["user"]
    subscription: SubscriptionPlan = SubscriptionPlan()
    google: GoogleIntegration = GoogleIntegration()
    profile: Profile = Profile()
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class SymptomEntry(BaseModel):
    name: str
    severity: Optional[int] = Field(None, ge=1, le=5)

class MedicationEntry(BaseModel):
    name: str
    dose: Optional[str] = None

class PhysicalMetrics(BaseModel):
    temperature_c: Optional[float] = Field(None, ge=30, le=45)
    weight_kg: Optional[float] = Field(None, ge=20, le=400)
    blood_pressure: Optional[str] = None
    sleep_quality: Optional[int] = Field(None, ge=1, le=5)

class MoodEntry(BaseModel):
    emoji: str
    note: Optional[str] = None

class Cycle(BaseModel):
    user_id: str
    start_date: date
    end_date: Optional[date] = None
    flow: Optional[Literal["light", "medium", "heavy"]] = None
    symptoms: List[SymptomEntry] = []
    mood: Optional[MoodEntry] = None
    medications: List[MedicationEntry] = []
    physical: Optional[PhysicalMetrics] = PhysicalMetrics()
    sexual_activity: Optional[Literal["none", "protected", "unprotected"]] = "none"
    tags: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Prediction(BaseModel):
    user_id: str
    generated_at: datetime
    next_period_start: Optional[date] = None
    ovulation_date: Optional[date] = None
    fertile_window: List[date] = []
    confidence: float = Field(0.0, ge=0, le=1)
    method: str = "rules+stats"
    accuracy_notes: Optional[str] = None

class Payment(BaseModel):
    user_id: str
    stripe_event: str
    amount: Optional[int] = None
    currency: Optional[str] = "usd"
    status: Optional[str] = None
    invoice_id: Optional[str] = None
    subscription_id: Optional[str] = None
    created_at: Optional[datetime] = None

class AnalyticsEvent(BaseModel):
    user_id: Optional[str] = None
    type: str
    properties: Dict[str, str] = {}
    created_at: Optional[datetime] = None

