from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from database import Base
from sqlalchemy.orm import relationship
from datetime import datetime
import pytz

IST=pytz.timezone('Asia/Kolkata')

class Server(Base):
    __tablename__ = "server"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100))              
    email = Column(String(255), unique=True, index=True)  
    password = Column(String(255))          
    gender = Column(String(20))    
    role = Column(String(20))

class Cashier(Base):
    __tablename__ = "cashier"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100))              
    email = Column(String(255), unique=True, index=True)  
    password = Column(String(255))          
    gender = Column(String(20))
    role = Column(String(20))

# class PasswordHistory(Base):
#     __tablename__ = "password_history"
#     id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer, ForeignKey("users.id"))
#     hashed_password = Column(String(255))
#     changed_at = Column(DateTime, default=datetime.now(IST))
#     user = relationship("User", back_populates="passwords")

class PasswordHistory(Base):
    __tablename__ = "password_history"
    id = Column(Integer, primary_key=True, index=True)
    
    server_id = Column(Integer, ForeignKey("server.id"), nullable=True)
    cashier_id = Column(Integer, ForeignKey("cashier.id"), nullable=True)

    hashed_password = Column(String(255))
    changed_at = Column(DateTime, default=datetime.now(IST))

    server = relationship("Server", backref="passwords")
    cashier = relationship("Cashier", backref="passwords")

