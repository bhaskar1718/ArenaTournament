
import hashlib
import hmac
import secrets
import smtplib
import json
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import jwt
import razorpay
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

from .config import settings
from .db import Base, engine, get_db
from .models import User, Otp, Tournament, Registration, Payment


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Arena Tournament API")

# CORS: allow your published Netlify website
allowed_origins = [
    "https://hrtgamerssolotournament.netlify.app",
]

configured_origin = str(settings.frontend_origin or "").rstrip("/")
if configured_origin and configured_origin not in allowed_origins:
    allowed_origins.append(configured_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)


def token(u):
    return jwt.encode(
        {
            "sub": str(u.id),
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=settings.jwt_expire_minutes),
        },
        settings.jwt_secret,
        algorithm="HS256",
    )


def digest(email, purpose, otp):
    return hmac.new(
        settings.jwt_secret.encode(),
        f"{email.lower()}:{purpose}:{otp}".encode(),
        hashlib.sha256,
    ).hexdigest()


def send(email, otp, purpose):
    if not all([
        settings.smtp_host,
        settings.smtp_username,
        settings.smtp_password,
        settings.smtp_from,
    ]):
        raise HTTPException(
            503,
            "Configure SMTP_* values to send verification emails.",
        )

    message = EmailMessage()
    message["Subject"] = "Arena Tournament verification code"
    message["From"] = settings.smtp_from
    message["To"] = email
    message.set_content(
        f"Your {purpose.replace('_', ' ')} code is {otp}. "
        "It expires in 10 minutes."
    )

    with smtplib.SMTP(
        settings.smtp_host,
        settings.smtp_port,
        timeout=15,
    ) as server:
        server.starttls()
        server.login(
            settings.smtp_username,
            settings.smtp_password,
        )
        server.send_message(message)


def issue(db, email, purpose):
    now = datetime.now(timezone.utc)

    count = (
        db.scalar(
            select(func.count())
            .select_from(Otp)
            .where(
                Otp.email == email.lower(),
                Otp.purpose == purpose,
                Otp.created_at > now - timedelta(minutes=15),
            )
        )
        or 0
    )

    if count >= 5:
        raise HTTPException(429, "Too many OTP requests. Try later.")

    code = f"{secrets.randbelow(1000000):06d}"

    row = Otp(
        email=email.lower(),
        purpose=purpose,
        digest=digest(email, purpose, code),
        expires_at=now + timedelta(minutes=10),
    )

    db.add(row)
    db.commit()

    try:
        send(email, code, purpose)
    except Exception:
        db.delete(row)
        db.commit()
        raise


def checkotp(db, email, purpose, code):
    row = db.scalar(
        select(Otp)
        .where(
            Otp.email == email.lower(),
            Otp.purpose == purpose,
        )
        .order_by(Otp.created_at.desc())
    )

    if (
        not row
        or row.expires_at < datetime.now(timezone.utc)
        or row.attempts >= 5
    ):
        raise HTTPException(400, "OTP expired or unavailable.")

    row.attempts += 1

    if not hmac.compare_digest(
        row.digest,
        digest(email, purpose, code),
    ):
        db.commit()
        raise HTTPException(400, "Incorrect OTP.")

    db.delete(row)
    db.commit()


def me(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
):
    if not creds:
        raise HTTPException(401, "Login required")

    try:
        claims = jwt.decode(
            creds.credentials,
            settings.jwt_secret,
            algorithms=["HS256"],
        )
    except Exception:
        raise HTTPException(401, "Invalid or expired session")

    if claims.get("role") == "static_admin":
        return User(
            id=0,
            name=settings.admin_username,
            email="admin@arena.local",
            is_admin=True,
            is_verified=True,
        )

    try:
        uid = int(claims["sub"])
    except Exception:
        raise HTTPException(401, "Invalid or expired session")

    user = db.get(User, uid)

    if not user or not user.is_verified:
        raise HTTPException(401, "Account unavailable")

    return user


def admin(u: User = Depends(me)):
    if not u.is_admin:
        raise HTTPException(403, "Admin access required")
    return u


class Signup(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class Verify(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    otp: str = Field(min_length=6, max_length=6)


class Login(BaseModel):
    email: EmailStr
    password: str


class EmailOnly(BaseModel):
    email: EmailStr


class Reset(BaseModel):
    email: EmailStr
    otp: str
    new_password: str = Field(min_length=8, max_length=128)


class PayVerify(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


class AdminLogin(BaseModel):
    username: str
    password: str


class RegistrationInput(BaseModel):
    game_uid: str = Field(min_length=1, max_length=80)
    game_name: str = Field(min_length=1, max_length=120)
    phonepe_number: str = Field(min_length=10, max_length=20)


class RoomInfo(BaseModel):
    room_id: str = Field(max_length=120)
    room_password: str = Field(max_length=120)


class NewTournament(BaseModel):
    title: str
    game: str
    starts_at: str
    entry_fee_paise: int = Field(ge=0)
    prize_text: str
    slots: int = Field(ge=2)
    description: str = ""


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/admin-login")
def static_admin_login(p: AdminLogin):
    if not settings.admin_username or not settings.admin_password:
        raise HTTPException(
            503,
            "Set ADMIN_USERNAME and ADMIN_PASSWORD in backend environment variables.",
        )
    if (
        not hmac.compare_digest(p.username, settings.admin_username)
        or not hmac.compare_digest(p.password, settings.admin_password)
    ):
        raise HTTPException(401, "Invalid admin username or password.")

    access_token = jwt.encode(
        {
            "sub": "static-admin",
            "role": "static_admin",
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=settings.jwt_expire_minutes),
        },
        settings.jwt_secret,
        algorithm="HS256",
    )
    return {
        "access_token": access_token,
        "user": {
            "id": 0,
            "name": settings.admin_username,
            "email": "admin@arena.local",
            "is_admin": True,
        },
    }


@app.post("/auth/signup")
def signup(p: Signup, db: Session = Depends(get_db)):
    email = p.email.lower()

    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Email already registered.")

    issue(db, email, "signup")

    return {
        "message": (
            "OTP sent to your email. Enter name, email, password "
            "and OTP to finish signup."
        )
    }


@app.post("/auth/verify-signup")
def verify_signup(p: Verify, db: Session = Depends(get_db)):
    email = p.email.lower()

    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Email already registered.")

    checkotp(db, email, "signup", p.otp)

    user = User(
        name=p.name,
        email=email,
        password_hash=pwd.hash(p.password),
        is_verified=True,
        is_admin=email == settings.admin_email.lower(),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "access_token": token(user),
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "is_admin": user.is_admin,
        },
    }


@app.post("/auth/login")
def login(p: Login, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == p.email.lower()))

    if not user or not pwd.verify(p.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password.")

    if not user.is_verified:
        raise HTTPException(403, "Email not verified.")

    return {
        "access_token": token(user),
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "is_admin": user.is_admin,
        },
    }


@app.post("/auth/forgot-password")
def forgot(p: EmailOnly, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == p.email.lower()))

    if user:
        issue(db, p.email, "reset_password")

    return {
        "message": "If this email is registered, a reset code has been sent."
    }


@app.post("/auth/reset-password")
def reset(p: Reset, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == p.email.lower()))

    if not user:
        raise HTTPException(400, "Invalid reset request.")

    checkotp(db, p.email, "reset_password", p.otp)
    user.password_hash = pwd.hash(p.new_password)
    db.commit()

    return {"message": "Password reset successfully."}


@app.get("/me")
def profile(u: User = Depends(me)):
    return {
        "id": u.id,
        "name": u.name,
        "email": u.email,
        "is_admin": u.is_admin,
    }


@app.get("/tournaments")
def list_tournaments(db: Session = Depends(get_db)):
    tournaments = db.scalars(
        select(Tournament).order_by(Tournament.id.desc())
    ).all()

    if not tournaments:
        db.add_all([
            Tournament(
                title="Full Map Solo Clash",
                game="Free Fire",
                starts_at="Coming soon",
                entry_fee_paise=2100,
                prize_text="See official rules",
                slots=100,
                status="open",
                description="Solo tournament. Check rules before entering.",
            ),
            Tournament(
                title="Squad Showdown",
                game="Free Fire",
                starts_at="Coming soon",
                entry_fee_paise=0,
                prize_text="Community event",
                slots=48,
                status="open",
                description="Free-entry community event.",
            ),
        ])
        db.commit()

        tournaments = db.scalars(
            select(Tournament).order_by(Tournament.id.desc())
        ).all()

    return [
        {
            "id": t.id,
            "title": t.title,
            "game": t.game,
            "starts_at": t.starts_at,
            "entry_fee_paise": t.entry_fee_paise,
            "prize_text": t.prize_text,
            "slots": t.slots,
            "status": t.status,
            "description": t.description,
        }
        for t in tournaments
    ]


@app.post("/tournaments/{tid}/register")
def register(
    tid: int,
    p: RegistrationInput,
    db: Session = Depends(get_db),
    u: User = Depends(me),
):
    tournament = db.get(Tournament, tid)

    if not tournament or tournament.status != "open":
        raise HTTPException(404, "Tournament not open.")

    existing = db.scalar(
        select(Registration).where(
            Registration.user_id == u.id,
            Registration.tournament_id == tid,
        )
    )

    if existing:
        existing.game_uid = p.game_uid.strip()
        existing.game_name = p.game_name.strip()
        existing.phonepe_number = p.phonepe_number.strip()
        db.commit()
        return {
            "registration_id": existing.id,
            "status": existing.status,
        }

    count = (
        db.scalar(
            select(func.count())
            .select_from(Registration)
            .where(
                Registration.tournament_id == tid,
                Registration.status.in_(
                    ["confirmed", "pending_payment"]
                ),
            )
        )
        or 0
    )

    if count >= tournament.slots:
        raise HTTPException(409, "Tournament is full.")

    registration = Registration(
        user_id=u.id,
        tournament_id=tid,
        status=(
            "pending_payment"
            if tournament.entry_fee_paise
            else "confirmed"
        ),
        game_uid=p.game_uid.strip(),
        game_name=p.game_name.strip(),
        phonepe_number=p.phonepe_number.strip(),
    )

    db.add(registration)
    db.commit()
    db.refresh(registration)

    return {
        "registration_id": registration.id,
        "status": registration.status,
    }


@app.post("/payments/create-order")
def create_order(
    p: dict,
    db: Session = Depends(get_db),
    u: User = Depends(me),
):
    registration = db.get(Registration, p.get("registration_id"))

    if not registration or registration.user_id != u.id:
        raise HTTPException(404, "Registration not found.")

    tournament = db.get(Tournament, registration.tournament_id)

    if not tournament or tournament.entry_fee_paise <= 0:
        raise HTTPException(400, "No payment required.")

    if not settings.razorpay_key_id or not settings.razorpay_key_secret:
        raise HTTPException(503, "Configure Razorpay test keys first.")

    try:
        order = razorpay.Client(
            auth=(
                settings.razorpay_key_id,
                settings.razorpay_key_secret,
            )
        ).order.create({
            "amount": tournament.entry_fee_paise,
            "currency": "INR",
            "receipt": f"reg_{registration.id}",
            "notes": {
                "registration_id": str(registration.id),
                "user_id": str(u.id),
            },
        })
    except Exception:
        raise HTTPException(502, "Could not create payment order.")

    db.add(
        Payment(
            registration_id=registration.id,
            order_id=order["id"],
            amount_paise=tournament.entry_fee_paise,
            status="created",
        )
    )
    db.commit()

    return {
        "order_id": order["id"],
        "amount": tournament.entry_fee_paise,
        "currency": "INR",
        "key_id": settings.razorpay_key_id,
    }


@app.post("/payments/verify")
def verify_payment(
    p: PayVerify,
    db: Session = Depends(get_db),
    u: User = Depends(me),
):
    payment = db.scalar(
        select(Payment).where(
            Payment.order_id == p.razorpay_order_id
        )
    )

    if not payment:
        raise HTTPException(404, "Order not found.")

    registration = db.get(Registration, payment.registration_id)

    if not registration or registration.user_id != u.id:
        raise HTTPException(403, "Not your payment.")

    expected = hmac.new(
        settings.razorpay_key_secret.encode(),
        f"{p.razorpay_order_id}|{p.razorpay_payment_id}".encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, p.razorpay_signature):
        raise HTTPException(400, "Signature verification failed.")

    payment.payment_id = p.razorpay_payment_id
    payment.status = "signature_verified"
    registration.status = "confirmed"
    db.commit()

    return {"status": "confirmed"}


@app.post("/payments/webhook")
async def webhook(req: Request, db: Session = Depends(get_db)):
    raw = await req.body()
    signature = req.headers.get("X-Razorpay-Signature", "")

    if not settings.razorpay_webhook_secret:
        raise HTTPException(503, "Webhook secret not configured.")

    expected = hmac.new(
        settings.razorpay_webhook_secret.encode(),
        raw,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise HTTPException(400, "Invalid webhook signature.")

    event = json.loads(raw)
    entity = (
        event.get("payload", {})
        .get("payment", {})
        .get("entity", {})
    )

    if event.get("event") == "payment.captured" and entity.get("order_id"):
        payment = db.scalar(
            select(Payment).where(
                Payment.order_id == entity["order_id"]
            )
        )

        if payment:
            payment.payment_id = entity.get("id")
            payment.status = "captured"

            registration = db.get(
                Registration, payment.registration_id
            )

            if registration:
                registration.status = "confirmed"

            db.commit()

    return {"ok": True}


@app.get("/admin/overview")
def overview(
    db: Session = Depends(get_db),
    _: User = Depends(admin),
):
    return {
        "users": db.scalar(select(func.count()).select_from(User)) or 0,
        "tournaments": db.scalar(
            select(func.count()).select_from(Tournament)
        ) or 0,
        "registrations": db.scalar(
            select(func.count()).select_from(Registration)
        ) or 0,
        "payments": db.scalar(
            select(func.count())
            .select_from(Payment)
            .where(
                Payment.status.in_(["captured", "signature_verified"])
            )
        ) or 0,
    }


@app.get("/admin/users")
def users(
    db: Session = Depends(get_db),
    _: User = Depends(admin),
):
    return [
        {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "verified": user.is_verified,
            "admin": user.is_admin,
        }
        for user in db.scalars(
            select(User).order_by(User.id.desc()).limit(500)
        ).all()
    ]


@app.get("/admin/registrations")
def registrations(
    db: Session = Depends(get_db),
    _: User = Depends(admin),
):
    return [
        {
            "id": r.id,
            "name": r.user.name,
            "email": r.user.email,
            "tournament": r.tournament.title,
            "status": r.status,
            "game_uid": r.game_uid,
            "game_name": r.game_name,
            "phonepe_number": r.phonepe_number,
            "created_at": r.created_at.isoformat(),
        }
        for r in db.scalars(
            select(Registration)
            .order_by(Registration.id.desc())
            .limit(500)
        ).all()
    ]


@app.post("/admin/tournaments")
def create_tournament(
    p: NewTournament,
    db: Session = Depends(get_db),
    _: User = Depends(admin),
):
    tournament = Tournament(**p.model_dump(), status="open")
    db.add(tournament)
    db.commit()
    db.refresh(tournament)

    return {"id": tournament.id, "title": tournament.title}


@app.patch("/admin/tournaments/{tid}/status")
def tournament_status(
    tid: int,
    p: dict,
    db: Session = Depends(get_db),
    _: User = Depends(admin),
):
    tournament = db.get(Tournament, tid)

    if not tournament:
        raise HTTPException(404, "Tournament not found.")

    if p.get("status") not in [
        "open", "closed", "completed", "cancelled"
    ]:
        raise HTTPException(422, "Invalid status.")

    tournament.status = p["status"]
    db.commit()

    return {"id": tournament.id, "status": tournament.status}


@app.patch("/admin/tournaments/{tid}/room")
def update_room(
    tid: int,
    p: RoomInfo,
    db: Session = Depends(get_db),
    _: User = Depends(admin),
):
    tournament = db.get(Tournament, tid)
    if not tournament:
        raise HTTPException(404, "Tournament not found.")

    tournament.room_id = p.room_id.strip()
    tournament.room_password = p.room_password.strip()
    db.commit()
    return {"id": tournament.id, "room_updated": True}


@app.get("/my/registrations")
def my_registrations(
    db: Session = Depends(get_db),
    u: User = Depends(me),
):
    rows = db.scalars(
        select(Registration)
        .where(
            Registration.user_id == u.id,
            Registration.status == "confirmed",
        )
        .order_by(Registration.id.desc())
    ).all()
    return [
        {
            "id": r.id,
            "tournament": r.tournament.title,
            "status": r.status,
            "room_id": r.tournament.room_id,
            "room_password": r.tournament.room_password,
        }
        for r in rows
    ]
