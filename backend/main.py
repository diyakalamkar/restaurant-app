from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from itsdangerous import URLSafeTimedSerializer
from database import SessionLocal, engine
from models import Base, Server, Cashier, PasswordHistory
import bcrypt
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import os
import pytz
import re

# App and DB setup
app = FastAPI()
Base.metadata.create_all(bind=engine)
# BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "frontend"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # points to backend/
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "../frontend"))

# Constants and secret keys
JWT_SECRET = "FSYdwgdi313rvaqiq0UA28u4e1jbkdbugWDeqwubei2fe1eHBwrlpqwnriekep1AS"
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30
SECRET_KEY = "hviy2te61r23c1uy2ei7312eb1dujf9w8yw19327te87183r1hvdygqiywd8yq8d"
SECURITY_PASSWORD_SALT = "dcnow8ye483ruv31ig91ye9313wdhnqihdw0yrih2it"
IST = pytz.timezone('Asia/Kolkata')

# Dependencies
pwd_context = bcrypt

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Password utils
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def validate_password_complexity(password: str):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
    if not re.match(pattern, password):
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long, include 1 uppercase, 1 lowercase, 1 number, and 1 special character.")

# JWT utils
def create_jwt_token(data: dict, expires_delta: timedelta = timedelta(minutes=JWT_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.now(IST) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login-jwt") #????????????????????????????????/

# def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
#     payload = decode_jwt_token(token)
#     if not payload:
#         raise HTTPException(status_code=401, detail="Invalid or expired token.")
#     email = payload.get("sub")
#     role = payload.get("role")
#     user = db.query(Server if role == "server" else Cashier).filter_by(email=email).first()
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")
#     return user
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    email = payload.get("sub")
    role = payload.get("role")
    if not email or not role:
        raise HTTPException(status_code=401, detail="Token missing email or role.")
    model = Server if role == "server" else Cashier
    user = db.query(model).filter_by(email=email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# Registration routes
@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register_user(request: Request, name: str = Form(...), email: str = Form(...), password: str = Form(...), gender: str = Form(...), role: str = Form(...), db: Session = Depends(get_db)):
    role = role.strip().lower()  # normalize
    if role not in ["server", "cashier"]:
        raise HTTPException(status_code=400, detail="Invalid role.")
    model = Server if role == "server" else Cashier

    existing_user = db.query(model).filter(model.email == email).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {"request": request, "error": "This email is already registered."})

    try:
        validate_password_complexity(password)
    except HTTPException as e:
        return templates.TemplateResponse("register.html", {"request": request, "error": e.detail})

    hashed_pw = hash_password(password)
    user = model(name=name, email=email, password=hashed_pw, gender=gender, role=role)
    db.add(user)
    db.commit()

    if role == "server":
        history = PasswordHistory(server_id=user.id, hashed_password=hashed_pw)
    else:
        history = PasswordHistory(cashier_id=user.id, hashed_password=hashed_pw)

    db.add(history)
    db.commit()
    return RedirectResponse("/login", status_code=303)

# Login and dashboard
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# @app.post("/login")
# def login_user(
#     request: Request,
#     email: str = Form(...),
#     password: str = Form(...),
#     role: str = Form(...),
#     db: Session = Depends(get_db)
# ):
#     model = Server if role == "server" else Cashier
#     user = db.query(model).filter(model.email == email).first()

#     if not user or not verify_password(password, user.password):
#         return templates.TemplateResponse("login.html", {
#             "request": request,
#             "error": "Invalid credentials."
#         })

#     token = create_jwt_token({"sub": user.email, "role": role})
#     return {"access_token": token, "token_type": "bearer", "dashboard": f"/dashboard/{role}"}


    # response = RedirectResponse(f"/dashboard/{role}", status_code=303)
    # response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True)
    # return response

@app.post("/login")
def login_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db)
):
    role = role.strip().lower()
    model = Server if role == "server" else Cashier
    user = db.query(model).filter(model.email == email).first()

    if not user or not verify_password(password, user.password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials."
        })

    token = create_jwt_token({"sub": user.email, "role": role})
    # Redirect to landing with token
    return templates.TemplateResponse("landing.html", {"request": request, "token": token})


@app.post("/login-jwt")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(Server).filter(Server.email == form_data.username).first()
    role = "server"
    if not user:
        user = db.query(Cashier).filter(Cashier.email == form_data.username).first()
        role = "cashier"
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect credentials")
    token = create_jwt_token({"sub": user.email, "role": role})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/login-jwt/server")
def login_server(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(Server).filter(Server.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password!")
    token = create_jwt_token({"sub": user.email, "role": "server"})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/login-jwt/cashier")
def login_cashier(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(Cashier).filter(Cashier.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password!")
    token = create_jwt_token({"sub": user.email, "role": "cashier"})
    return {"access_token": token, "token_type": "bearer"}

# @app.get("/dashboard/server")
# #def server_dashboard(current_user: Server = Depends(get_current_user)):
# def server_dashboard(current_user = Depends(get_current_user)):
#     if current_user.role != "server":
#         raise HTTPException(status_code=403, detail="Access forbidden for your role!")
#     return {"message": f"Welcome Server {current_user.name}"}

# @app.get("/dashboard/cashier")
# #def cashier_dashboard(current_user: Cashier = Depends(get_current_user)):
# def cashier_dashboard(current_user = Depends(get_current_user)):
#     if current_user.role != "cashier":
#         raise HTTPException(status_code=403, detail="Access forbidden for your role!")
#     return {"message": f"Welcome Cashier {current_user.name}"}

@app.post("/access-dashboard", response_class=HTMLResponse)
def access_dashboard(
    request: Request,
    token: str = Form(...),
    target: str = Form(...),  # "server" or "cashier"
    db: Session = Depends(get_db)
):
    payload = decode_jwt_token(token)
    if not payload:
        return templates.TemplateResponse("landing.html", {
            "request": request,
            "error": "Invalid or expired token.",
            "token": token
        })

    user_role = payload.get("role")
    email = payload.get("sub")

    if not email or not user_role:
        return templates.TemplateResponse("landing.html", {
            "request": request,
            "error": "Token missing required info.",
            "token": token
        })

    if user_role != target:
        return templates.TemplateResponse("landing.html", {
            "request": request,
            "error": "Access forbidden for your role.",
            "token": token
        })

    # Role matched: render dashboard
    model = Server if user_role == "server" else Cashier
    user = db.query(model).filter_by(email=email).first()

    template_file = "server.html" if user_role == "server" else "cashier.html"
    return templates.TemplateResponse(template_file, {"request": request, "user": user})


# Reset password
@app.post("/send-reset-link")
def send_reset_link(request: Request, email: str = Form(...), role: str = Form(...), db: Session = Depends(get_db)):
    model = Server if role == "server" else Cashier
    user = db.query(model).filter(model.email == email).first()
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Email not found."})
    token = URLSafeTimedSerializer(SECRET_KEY).dumps(email, salt=SECURITY_PASSWORD_SALT)
    link = f"http://127.0.0.1:8000/reset-password/{role}/{token}"
    msg = MIMEText(f"Reset your password: {link}")
    msg['Subject'] = 'Reset Password'
    msg['From'] = 'yourmail@gmail.com'
    msg['To'] = email
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login("yourmail@gmail.com", "your mail password")
        server.send_message(msg)
    return templates.TemplateResponse("login.html", {"request": request, "message": "Password reset link sent."})

@app.get("/reset-password/{role}/{token}", response_class=HTMLResponse)
def reset_password_form(role: str, token: str, request: Request):
    return templates.TemplateResponse("reset.html", {"request": request, "token": token, "role": role})

@app.post("/reset-password/{role}/{token}")
def reset_password(role: str, token: str, request: Request, password: str = Form(...), db: Session = Depends(get_db)):
    model = Server if role == "server" else Cashier
    try:
        email = URLSafeTimedSerializer(SECRET_KEY).loads(token, salt=SECURITY_PASSWORD_SALT, max_age=3600)
    except:
        return templates.TemplateResponse("reset.html", {"request": request, "token": token, "role": role, "error": "Invalid or expired token."})
    user = db.query(model).filter(model.email == email).first()
    if not user:
        return templates.TemplateResponse("reset.html", {"request": request, "token": token, "role": role, "error": "User not found."})

    try:
        validate_password_complexity(password)
    except HTTPException as e:
        return templates.TemplateResponse("reset.html", {"request": request, "token": token, "role": role, "error": e.detail})
    
    if role == "server":
        previous_passwords = db.query(PasswordHistory).filter(PasswordHistory.server_id == user.id).all()
    else:
        previous_passwords = db.query(PasswordHistory).filter(PasswordHistory.cashier_id == user.id).all()

    for old in previous_passwords:
        if bcrypt.checkpw(password.encode('utf-8'), old.hashed_password.encode('utf-8')):
            return templates.TemplateResponse("reset.html", {
                "request": request,
                "token": token,
                "role": role,
                "error": "Password reused. Choose a new one."
            })

    new_hashed = hash_password(password)
    user.password = new_hashed

    if role == "server":
        history = PasswordHistory(server_id=user.id, hashed_password=new_hashed)
    else:
        history = PasswordHistory(cashier_id=user.id, hashed_password=new_hashed)
    
    db.add(history)
    db.commit()

    return RedirectResponse("/login", status_code=303)
