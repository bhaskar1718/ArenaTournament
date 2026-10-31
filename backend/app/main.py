import hashlib,hmac,secrets,smtplib
from datetime import datetime,timedelta,timezone
from email.message import EmailMessage
from fastapi import FastAPI,Depends,HTTPException,Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import select,func
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel,EmailStr,Field,field_validator
from .config import settings
from .db import Base,engine,get_db
from .models import User,Otp,Tournament,Registration,Payment
Base.metadata.create_all(bind=engine)
app=FastAPI(title="Arena Tournament API")
app.add_middleware(CORSMiddleware,allow_origins=list({settings.frontend_origin, "https://hrtgamerssolotournament.netlify.app"}),allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
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
    try: claims=jwt.decode(creds.credentials,settings.jwt_secret,algorithms=["HS256"])
    except Exception: raise HTTPException(401,"Invalid or expired session")
    if claims.get("role")=="static_admin":
        return User(id=0,name=settings.admin_username,email="admin@arena.local",is_admin=True,is_verified=True)
    try: uid=int(claims["sub"])
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
class UpiSubmission(BaseModel): registration_id:int;transaction_id:str=Field(min_length=4,max_length=120)
class AdminLogin(BaseModel): username:str;password:str
class RegistrationInput(BaseModel):
    game_uid:str=Field(min_length=1,max_length=80)
    game_name:str=Field(min_length=1,max_length=120)
    phonepe_number:str=Field(min_length=10,max_length=10,pattern=r"^[0-9]{10}$")
    allow_duplicate:bool=False
    @field_validator("game_uid","game_name","phonepe_number")
    @classmethod
    def trim_values(cls,v):
        return v.strip()
class RoomInfo(BaseModel): room_id:str=Field(max_length=120);room_password:str=Field(max_length=120);room_time:str=Field(max_length=120)
class NewTournament(BaseModel):
    title:str;game:str;starts_at:str;entry_fee_paise:int=Field(ge=0);prize_text:str;slots:int=Field(ge=2);description:str=""
@app.get("/health")
def health(): return {"status":"ok"}
@app.post("/auth/admin-login")
def static_admin_login(p:AdminLogin):
    if not settings.admin_username or not settings.admin_password: raise HTTPException(503,"Set ADMIN_USERNAME and ADMIN_PASSWORD in backend environment variables.")
    if not hmac.compare_digest(p.username,settings.admin_username) or not hmac.compare_digest(p.password,settings.admin_password): raise HTTPException(401,"Invalid admin username or password.")
    tok=jwt.encode({"sub":"static-admin","role":"static_admin","exp":datetime.now(timezone.utc)+timedelta(minutes=settings.jwt_expire_minutes)},settings.jwt_secret,algorithm="HS256")
    return {"access_token":tok,"user":{"id":0,"name":settings.admin_username,"email":"admin@arena.local","is_admin":True}}
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
def register(tid:int,p:RegistrationInput,db:Session=Depends(get_db),u:User=Depends(me)):
    t=db.get(Tournament,tid)
    if not t or t.status!="open": raise HTTPException(404,"Tournament not open.")
    previous=db.scalar(select(func.count()).select_from(Registration).where(Registration.user_id==u.id,Registration.tournament_id==tid)) or 0
    if previous and not p.allow_duplicate:
        raise HTTPException(409,"You have already registered for this tournament. Do you want to register again?")
    count=db.scalar(select(func.count()).select_from(Registration).where(Registration.tournament_id==tid,Registration.status.in_(["confirmed","pending_payment","pending_verification"]),Registration.approval_status!="rejected")) or 0
    if count>=t.slots: raise HTTPException(409,"Tournament is full.")
    r=Registration(user_id=u.id,tournament_id=tid,status="pending_payment" if t.entry_fee_paise else "confirmed",game_uid=p.game_uid,game_name=p.game_name,phonepe_number=p.phonepe_number);db.add(r);db.commit();db.refresh(r)
    return {"registration_id":r.id,"status":r.status}
@app.get("/payments/upi-info")
def upi_info(registration_id:int,db:Session=Depends(get_db),u:User=Depends(me)):
    r=db.get(Registration,registration_id)
    if not r or r.user_id!=u.id: raise HTTPException(404,"Registration not found.")
    t=db.get(Tournament,r.tournament_id)
    if not t or t.entry_fee_paise<=0: raise HTTPException(400,"No payment required.")
    if not settings.upi_id: raise HTTPException(503,"Admin must configure UPI_ID in the backend environment.")
    return {"upi_id":settings.upi_id,"amount_paise":t.entry_fee_paise,"amount_rupees":round(t.entry_fee_paise/100,2),"tournament":t.title,"registration_id":r.id,"status":r.status,"transaction_id":r.transaction_id}

@app.post("/payments/submit-upi")
def submit_upi(p:UpiSubmission,db:Session=Depends(get_db),u:User=Depends(me)):
    r=db.get(Registration,p.registration_id)
    if not r or r.user_id!=u.id: raise HTTPException(404,"Registration not found.")
    if r.status=="confirmed": raise HTTPException(409,"Payment already verified.")
    if r.status=="pending_verification": raise HTTPException(409,"Your transaction ID is already submitted. Please wait for admin verification.")
    if not p.transaction_id.strip(): raise HTTPException(422,"Enter a valid UPI transaction ID / UTR.")
    r.transaction_id=p.transaction_id.strip()
    r.status="pending_verification"
    r.approval_status="pending"
    db.commit()
    return {"registration_id":r.id,"status":r.status,"message":"Transaction ID submitted. Admin will verify your payment."}

@app.get("/admin/overview")
def overview(db:Session=Depends(get_db),_:User=Depends(admin)):
    return {"users":db.scalar(select(func.count()).select_from(User)) or 0,"tournaments":db.scalar(select(func.count()).select_from(Tournament)) or 0,"registrations":db.scalar(select(func.count()).select_from(Registration)) or 0,"payments":db.scalar(select(func.count()).select_from(Registration).join(Tournament).where(Registration.status=="confirmed",Tournament.entry_fee_paise>0)) or 0}
@app.get("/admin/users")
def users(db:Session=Depends(get_db),_:User=Depends(admin)):
    return [{"id":u.id,"name":u.name,"email":u.email,"verified":u.is_verified,"admin":u.is_admin} for u in db.scalars(select(User).order_by(User.id.desc()).limit(500)).all()]
@app.get("/admin/registrations")
def registrations(db:Session=Depends(get_db),_:User=Depends(admin)):
    return [{"id":r.id,"name":r.user.name,"email":r.user.email,"tournament_id":r.tournament_id,"tournament":r.tournament.title,"status":r.status,"approval_status":r.approval_status,"entry_fee_paise":r.tournament.entry_fee_paise,"game_uid":r.game_uid,"game_name":r.game_name,"phonepe_number":r.phonepe_number,"transaction_id":r.transaction_id,"kills":r.kills,"created_at":r.created_at.isoformat()} for r in db.scalars(select(Registration).order_by(Registration.id.desc()).limit(500)).all()]

@app.patch("/admin/registrations/{rid}/verify-payment")
def verify_upi_payment(rid:int,db:Session=Depends(get_db),_:User=Depends(admin)):
    r=db.get(Registration,rid)
    if not r: raise HTTPException(404,"Registration not found.")
    if not r.transaction_id.strip(): raise HTTPException(409,"Participant has not submitted a transaction ID.")
    r.status="confirmed"
    db.commit()
    return {"id":r.id,"status":r.status,"message":"UPI payment marked as verified. You can now approve the participant."}

@app.patch("/admin/registrations/{rid}/kills")
def update_kills(rid:int,p:dict,db:Session=Depends(get_db),_:User=Depends(admin)):
    r=db.get(Registration,rid)
    if not r: raise HTTPException(404,"Registration not found.")
    try: kills=int(p.get("kills"))
    except (TypeError,ValueError): raise HTTPException(422,"Kills must be a whole number.")
    if kills<0 or kills>999: raise HTTPException(422,"Kills must be between 0 and 999.")
    r.kills=kills;db.commit()
    return {"id":r.id,"kills":r.kills,"message":"Participant kills saved."}

@app.patch("/admin/registrations/{rid}/approval")
def registration_approval(rid:int,p:dict,db:Session=Depends(get_db),_:User=Depends(admin)):
    r=db.get(Registration,rid)
    if not r: raise HTTPException(404,"Registration not found.")
    action=p.get("approval_status")
    if action not in ["approved","rejected"]: raise HTTPException(422,"Approval status must be approved or rejected.")
    if action=="approved" and r.tournament.entry_fee_paise>0 and r.status!="confirmed":
        raise HTTPException(409,"Verify the UPI transaction first, then approve.")
    r.approval_status=action
    db.commit()
    return {"id":r.id,"approval_status":r.approval_status,"message":f"Registration {action}."}
@app.post("/admin/tournaments")
def create_tournament(p:NewTournament,db:Session=Depends(get_db),_:User=Depends(admin)):
    t=Tournament(**p.model_dump(),status="open");db.add(t);db.commit();db.refresh(t);return {"id":t.id,"title":t.title}
@app.patch("/admin/tournaments/{tid}/status")
def tournament_status(tid:int,p:dict,db:Session=Depends(get_db),_:User=Depends(admin)):
    t=db.get(Tournament,tid)
    if not t: raise HTTPException(404,"Tournament not found.")
    if p.get("status") not in ["open","closed","completed","cancelled"]: raise HTTPException(422,"Invalid status.")
    t.status=p["status"];db.commit();return {"id":t.id,"status":t.status}

@app.patch("/admin/tournaments/{tid}/room")
def update_room(tid:int,p:RoomInfo,db:Session=Depends(get_db),_:User=Depends(admin)):
    t=db.get(Tournament,tid)
    if not t: raise HTTPException(404,"Tournament not found.")
    t.room_id=p.room_id.strip();t.room_password=p.room_password.strip();t.room_time=p.room_time.strip();db.commit()
    return {"id":t.id,"room_updated":True}
@app.get("/my/registrations")
def my_registrations(db:Session=Depends(get_db),u:User=Depends(me)):
    rows=db.scalars(select(Registration).where(Registration.user_id==u.id).order_by(Registration.id.desc())).all()
    result=[]
    for r in rows:
        approved=(r.status=="confirmed" and r.approval_status=="approved")
        # Only approved participants receive the approved roster and room information.
        participants=[]
        if approved:
            approved_rows=db.scalars(
                select(Registration).where(
                    Registration.tournament_id==r.tournament_id,
                    Registration.status=="confirmed",
                    Registration.approval_status=="approved"
                ).order_by(Registration.game_name.asc(),Registration.id.asc())
            ).all()
            participants=[{"name":x.user.name,"game_name":x.game_name,"game_uid":x.game_uid,"kills":x.kills} for x in approved_rows]
        room_configured=bool(r.tournament.room_id.strip() and r.tournament.room_password.strip() and r.tournament.room_time.strip())
        result.append({"id":r.id,"tournament_id":r.tournament_id,"tournament":r.tournament.title,"entry_fee_paise":r.tournament.entry_fee_paise,"status":r.status,"approval_status":r.approval_status,"transaction_id":r.transaction_id,"created_at":r.created_at.isoformat(),"game_uid":r.game_uid,"game_name":r.game_name,"room_configured":room_configured if approved else False,"room_message":("Room details will be updated by the admin once they are created." if approved and not room_configured else None),"participants":participants if approved else [],"room_id":r.tournament.room_id if approved and room_configured else None,"room_password":r.tournament.room_password if approved and room_configured else None,"room_time":r.tournament.room_time if approved and room_configured else None,"kills":r.kills if approved else None})
    return result
