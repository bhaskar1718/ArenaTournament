from datetime import datetime, timezone
from sqlalchemy import String,Integer,Boolean,DateTime,ForeignKey,UniqueConstraint,Text
from sqlalchemy.orm import Mapped,mapped_column,relationship
from .db import Base
def now(): return datetime.now(timezone.utc)
class User(Base):
    __tablename__="users"
    id:Mapped[int]=mapped_column(primary_key=True)
    name:Mapped[str]=mapped_column(String(120))
    email:Mapped[str]=mapped_column(String(320),unique=True,index=True)
    password_hash:Mapped[str]=mapped_column(String(255))
    is_verified:Mapped[bool]=mapped_column(Boolean,default=False)
    is_admin:Mapped[bool]=mapped_column(Boolean,default=False)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class Otp(Base):
    __tablename__="otps"
    id:Mapped[int]=mapped_column(primary_key=True)
    email:Mapped[str]=mapped_column(String(320),index=True)
    purpose:Mapped[str]=mapped_column(String(30))
    digest:Mapped[str]=mapped_column(String(64))
    expires_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    attempts:Mapped[int]=mapped_column(Integer,default=0)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class Tournament(Base):
    __tablename__="tournaments"
    id:Mapped[int]=mapped_column(primary_key=True)
    title:Mapped[str]=mapped_column(String(180))
    game:Mapped[str]=mapped_column(String(100))
    starts_at:Mapped[str]=mapped_column(String(80))
    entry_fee_paise:Mapped[int]=mapped_column(Integer,default=0)
    prize_text:Mapped[str]=mapped_column(String(180),default="Details to be announced")
    slots:Mapped[int]=mapped_column(Integer,default=100)
    status:Mapped[str]=mapped_column(String(30),default="open")
    description:Mapped[str]=mapped_column(Text,default="")
class Registration(Base):
    __tablename__="registrations"
    __table_args__=(UniqueConstraint("user_id","tournament_id",name="uq_user_tournament"),)
    id:Mapped[int]=mapped_column(primary_key=True)
    user_id:Mapped[int]=mapped_column(ForeignKey("users.id"),index=True)
    tournament_id:Mapped[int]=mapped_column(ForeignKey("tournaments.id"),index=True)
    status:Mapped[str]=mapped_column(String(30),default="pending_payment")
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    user=relationship("User")
    tournament=relationship("Tournament")
class Payment(Base):
    __tablename__="payments"
    id:Mapped[int]=mapped_column(primary_key=True)
    registration_id:Mapped[int]=mapped_column(ForeignKey("registrations.id"),index=True)
    order_id:Mapped[str]=mapped_column(String(100),unique=True,index=True)
    payment_id:Mapped[str|None]=mapped_column(String(100),nullable=True,unique=True)
    amount_paise:Mapped[int]=mapped_column(Integer)
    status:Mapped[str]=mapped_column(String(30),default="created")
