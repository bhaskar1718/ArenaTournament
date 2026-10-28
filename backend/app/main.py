import hashlib,hmac,secrets,smtplib
from datetime import datetime,timedelta,timezone
from email.message import EmailMessage
from fastapi import FastAPI,Depends,HTTPException,Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import select,func
import jwt,razorpay
from passlib.context import CryptContext
from pydantic import BaseModel,EmailStr,Field
from .config import settings
from .db import Base,engine,get_db
from .models import User,Otp,Tournament,Registration,Payment
Base.metadata.create_all(bind=engine)
app=FastAPI(title="Arena Tournament API")
app.add_middleware(CORSMiddleware,allow_origins=[settings.frontend_origin],allow_methods=["*"],allow_headers=["*"])
pwd=CryptContext(schemes=["bcrypt"],deprecated="auto")
bearer=HTTPBearer(auto_error=False)
def token(u): return jwt.encode({"sub":str(u.id),"exp":datetime.now(timezone.utc)+timedelta(minutes=settings.jwt_expire_minutes)},settings.jwt_secret,algorithm="HS256")
def digest(email,purpose,otp): return hmac.new(settings.jwt_secret.encode(),f"{email.lower()}:{purpose}:{otp}".encode(),hashlib.sha256).hexdigest()
def send(email,otp,purpose):
    if not all([settings.smtp_host,settings.smtp_username,settings.smtp_password,settings.smtp_from]): raise HTTPException(503,"Configure SMTP_* values in .env to send real email.")
    m=EmailMessage();m["Subject"]="Arena Tournament verification code";m["From"]=settings.smtp_from;m["To"]=email
    m.set_content(f"Your {purpose.replace('_',' ')} code is {otp}. It expires in 10 minutes.")
    with smtplib.SMTP(settings.smtp_host,settings.smtp_port,timeout=15) as s:
        s.starttls();s.login(settings.smtp_username,settings.smtp_password);s.send_message(m)
def issue(db,email,purpose):
    now=datetime.now(timezone.utc)
    n=db.scalar(select(func.count()).select_from(Otp).where(Otp.email==email.lower(),Otp.purpose==purpose,Otp.created_at>now-timedelta(minutes=15))) or 0
    if n>=5: raise HTTPException(429,"Too many OTP requests. Try later.")
    code=f"{secrets.randbelow(1000000):06d}"
    row=Otp(email=email.lower(),purpose=purpose,digest=digest(email,purpose,code),expires_at=now+timedelta(minutes=10))
    db.add(row);db.commit()
    try: send(email,code,purpose)
    except Exception: db.delete(row);db.commit();raise
def checkotp(db,email,purpose,code):
    row=db.scalar(select(Otp).where(Otp.email==email.lower(),Otp.purpose==purpose).order_by(Otp.created_at.desc()))
    if not row or row.expires_at<datetime.now(timezone.utc) or row.attempts>=5: raise HTTPException(400,"OTP expired or unavailable.")
    row.attempts+=1
    if not hmac.compare_digest(row.digest,digest(email,purpose,code)): db.commit();raise HTTPException(400,"Incorrect OTP.")
    db.delete(row);db.commit()
def me(creds:HTTPAuthorizationCredentials=Depends(bearer),db:Session=Depends(get_db)):
    if not creds: raise HTTPException(401,"Login required")
    try: uid=int(jwt.decode(creds.credentials,settings.jwt_secret,algorithms=["HS256"])["sub"])
    except Exception: raise HTTPException(401,"Invalid or expired session")
    u=db.get(User,uid)
    if not u or not u.is_verified: raise HTTPException(401,"Account unavailable")
    return u
def admin(u:User=Depends(me)):
    if not u.is_admin: raise HTTPException(403,"Admin access required")
    return u
class Signup(BaseModel):
    name:str=Field(min_length=2,max_length=120);email:EmailStr;password:str=Field(min_length=8,max_length=128)
class Verify(BaseModel):
    name:str=Field(min_length=2,max_length=120);email:EmailStr;password:str=Field(min_length=8,max_length=128);otp:str=Field(min_length=6,max_length=6)
class Login(BaseModel): email:EmailStr;password:str
class EmailOnly(BaseModel): email:EmailStr
class Reset(BaseModel): email:EmailStr;otp:str;new_password:str=Field(min_length=8,max_length=128)
class PayVerify(BaseModel): razorpay_order_id:str;razorpay_payment_id:str;razorpay_signature:str
class NewTournament(BaseModel):
    title:str;game:str;starts_at:str;entry_fee_paise:int=Field(ge=0);prize_text:str;slots:int=Field(ge=2);description:str=""
@app.get("/health")
def health(): return {"status":"ok"}
@app.post("/auth/signup")
def signup(p:Signup,db:Session=Depends(get_db)):
    email=p.email.lower()
    if db.scalar(select(User).where(User.email==email)): raise HTTPException(409,"Email already registered.")
    issue(db,email,"signup")
    return {"message":"OTP sent to your email. Enter name, email, password and OTP to finish signup."}
@app.post("/auth/verify-signup")
def verify_signup(p:Verify,db:Session=Depends(get_db)):
    email=p.email.lower()
    if db.scalar(select(User).where(User.email==email)): raise HTTPException(409,"Email already registered.")
    checkotp(db,email,"signup",p.otp)
    u=User(name=p.name,email=email,password_hash=pwd.hash(p.password),is_verified=True,is_admin=email==settings.admin_email.lower())
    db.add(u);db.commit();db.refresh(u)
    return {"access_token":token(u),"user":{"id":u.id,"name":u.name,"email":u.email,"is_admin":u.is_admin}}
@app.post("/auth/login")
def login(p:Login,db:Session=Depends(get_db)):
    u=db.scalar(select(User).where(User.email==p.email.lower()))
    if not u or not pwd.verify(p.password,u.password_hash): raise HTTPException(401,"Invalid email or password.")
    if not u.is_verified: raise HTTPException(403,"Email not verified.")
    return {"access_token":token(u),"user":{"id":u.id,"name":u.name,"email":u.email,"is_admin":u.is_admin}}
@app.post("/auth/forgot-password")
def forgot(p:EmailOnly,db:Session=Depends(get_db)):
    u=db.scalar(select(User).where(User.email==p.email.lower()))
    if u: issue(db,p.email,"reset_password")
    return {"message":"If this email is registered, a reset code has been sent."}
@app.post("/auth/reset-password")
def reset(p:Reset,db:Session=Depends(get_db)):
    u=db.scalar(select(User).where(User.email==p.email.lower()))
    if not u: raise HTTPException(400,"Invalid reset request.")
    checkotp(db,p.email,"reset_password",p.otp);u.password_hash=pwd.hash(p.new_password);db.commit()
    return {"message":"Password reset successfully."}
@app.get("/me")
def profile(u:User=Depends(me)): return {"id":u.id,"name":u.name,"email":u.email,"is_admin":u.is_admin}
@app.get("/tournaments")
def list_tournaments(db:Session=Depends(get_db)):
    ts=db.scalars(select(Tournament).order_by(Tournament.id.desc())).all()
    if not ts:
        db.add_all([Tournament(title="Full Map Solo Clash",game="Free Fire",starts_at="Coming soon",entry_fee_paise=2100,prize_text="See official rules",slots=100,status="open",description="Solo tournament. Check rules before entering."),Tournament(title="Squad Showdown",game="Free Fire",starts_at="Coming soon",entry_fee_paise=0,prize_text="Community event",slots=48,status="open",description="Free-entry community event.")]);db.commit()
        ts=db.scalars(select(Tournament).order_by(Tournament.id.desc())).all()
    return [{"id":t.id,"title":t.title,"game":t.game,"starts_at":t.starts_at,"entry_fee_paise":t.entry_fee_paise,"prize_text":t.prize_text,"slots":t.slots,"status":t.status,"description":t.description} for t in ts]
@app.post("/tournaments/{tid}/register")
def register(tid:int,db:Session=Depends(get_db),u:User=Depends(me)):
    t=db.get(Tournament,tid)
    if not t or t.status!="open": raise HTTPException(404,"Tournament not open.")
    existing=db.scalar(select(Registration).where(Registration.user_id==u.id,Registration.tournament_id==tid))
    if existing: return {"registration_id":existing.id,"status":existing.status}
    count=db.scalar(select(func.count()).select_from(Registration).where(Registration.tournament_id==tid,Registration.status.in_(["confirmed","pending_payment"]))) or 0
    if count>=t.slots: raise HTTPException(409,"Tournament is full.")
    r=Registration(user_id=u.id,tournament_id=tid,status="pending_payment" if t.entry_fee_paise else "confirmed");db.add(r);db.commit();db.refresh(r)
    return {"registration_id":r.id,"status":r.status}
@app.post("/payments/create-order")
def create_order(p:dict,db:Session=Depends(get_db),u:User=Depends(me)):
    r=db.get(Registration,p.get("registration_id"))
    if not r or r.user_id!=u.id: raise HTTPException(404,"Registration not found.")
    t=db.get(Tournament,r.tournament_id)
    if not t or t.entry_fee_paise<=0: raise HTTPException(400,"No payment required.")
    if not settings.razorpay_key_id or not settings.razorpay_key_secret: raise HTTPException(503,"Configure Razorpay test keys first.")
    try:
        order=razorpay.Client(auth=(settings.razorpay_key_id,settings.razorpay_key_secret)).order.create({"amount":t.entry_fee_paise,"currency":"INR","receipt":f"reg_{r.id}","notes":{"registration_id":str(r.id),"user_id":str(u.id)}})
    except Exception: raise HTTPException(502,"Could not create payment order.")
    db.add(Payment(registration_id=r.id,order_id=order["id"],amount_paise=t.entry_fee_paise,status="created"));db.commit()
    return {"order_id":order["id"],"amount":t.entry_fee_paise,"currency":"INR","key_id":settings.razorpay_key_id}
@app.post("/payments/verify")
def verify_payment(p:PayVerify,db:Session=Depends(get_db),u:User=Depends(me)):
    pay=db.scalar(select(Payment).where(Payment.order_id==p.razorpay_order_id))
    if not pay: raise HTTPException(404,"Order not found.")
    r=db.get(Registration,pay.registration_id)
    if not r or r.user_id!=u.id: raise HTTPException(403,"Not your payment.")
    expected=hmac.new(settings.razorpay_key_secret.encode(),f"{p.razorpay_order_id}|{p.razorpay_payment_id}".encode(),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,p.razorpay_signature): raise HTTPException(400,"Signature verification failed.")
    pay.payment_id=p.razorpay_payment_id;pay.status="signature_verified";r.status="confirmed";db.commit()
    return {"status":"confirmed"}
@app.post("/payments/webhook")
async def webhook(req:Request,db:Session=Depends(get_db)):
    raw=await req.body();sig=req.headers.get("X-Razorpay-Signature","")
    if not settings.razorpay_webhook_secret: raise HTTPException(503,"Webhook secret not configured.")
    expected=hmac.new(settings.razorpay_webhook_secret.encode(),raw,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,sig): raise HTTPException(400,"Invalid webhook signature.")
    import json
    event=json.loads(raw);entity=event.get("payload",{}).get("payment",{}).get("entity",{})
    if event.get("event")=="payment.captured" and entity.get("order_id"):
        pay=db.scalar(select(Payment).where(Payment.order_id==entity["order_id"]))
        if pay:
            pay.payment_id=entity.get("id");pay.status="captured";r=db.get(Registration,pay.registration_id)
            if r:r.status="confirmed"
            db.commit()
    return {"ok":True}
@app.get("/admin/overview")
def overview(db:Session=Depends(get_db),_:User=Depends(admin)):
    return {"users":db.scalar(select(func.count()).select_from(User)) or 0,"tournaments":db.scalar(select(func.count()).select_from(Tournament)) or 0,"registrations":db.scalar(select(func.count()).select_from(Registration)) or 0,"payments":db.scalar(select(func.count()).select_from(Payment).where(Payment.status.in_(["captured","signature_verified"]))) or 0}
@app.get("/admin/users")
def users(db:Session=Depends(get_db),_:User=Depends(admin)):
    return [{"id":u.id,"name":u.name,"email":u.email,"verified":u.is_verified,"admin":u.is_admin} for u in db.scalars(select(User).order_by(User.id.desc()).limit(500)).all()]
@app.get("/admin/registrations")
def registrations(db:Session=Depends(get_db),_:User=Depends(admin)):
    return [{"id":r.id,"email":r.user.email,"tournament":r.tournament.title,"status":r.status,"created_at":r.created_at.isoformat()} for r in db.scalars(select(Registration).order_by(Registration.id.desc()).limit(500)).all()]
@app.post("/admin/tournaments")
def create_tournament(p:NewTournament,db:Session=Depends(get_db),_:User=Depends(admin)):
    t=Tournament(**p.model_dump(),status="open");db.add(t);db.commit();db.refresh(t);return {"id":t.id,"title":t.title}
@app.patch("/admin/tournaments/{tid}/status")
def tournament_status(tid:int,p:dict,db:Session=Depends(get_db),_:User=Depends(admin)):
    t=db.get(Tournament,tid)
    if not t: raise HTTPException(404,"Tournament not found.")
    if p.get("status") not in ["open","closed","completed","cancelled"]: raise HTTPException(422,"Invalid status.")
    t.status=p["status"];db.commit();return {"id":t.id,"status":t.status}
