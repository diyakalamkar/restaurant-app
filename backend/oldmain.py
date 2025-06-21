from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import Base, User, PasswordHistory
import os
import re
from fastapi import HTTPException
from itsdangerous import URLSafeTimedSerializer
import smtplib
from email.mime.text import MIMEText
import bcrypt 
from jose import JWTError, jwt
from datetime import datetime, timedelta
import pytz
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm

#creates an app and runs sqlalchemy to create all tables defined (users)
app = FastAPI()
Base.metadata.create_all(bind=engine)

#sets base directory for html templates
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "frontend")) #name of that folder

#get DB session dependency
#opens a session and closes it after the request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

#GET route for rendering registration form
@app.get("/register", response_class=HTMLResponse)
async def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

#POST route 2 handle registration
@app.post("/register")
#accepts form data
async def register_user(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    gender: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db)
):
    #check if email already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        #raise HTTPException(status_code=400, detail="Email already registered.")
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "This email is already registered. Try logging in or use a different email."
        })

    # validate password complexity
    #validate_password_complexity(password)
    try:
        validate_password_complexity(password)
    except HTTPException as e:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": e.detail
        })

    #save user if validation passes and everything is fine
    hashed_pw=hash_password(password)
    user = User(name=name, email=email, password=hashed_pw, gender=gender)
    #user = User(name=name, email=email, password=password, gender=gender)
    db.add(user)
    db.commit()

    db.add(PasswordHistory(user_id=user.id, hashed_password=hashed_pw))
    db.commit()
    return RedirectResponse("/login", status_code=303)

#password encryption
def hash_password(password: str) -> str:
    salt=bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

#password verification
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

#GET route for rendering login form
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

#POST route to handle login
@app.post("/login")
#checks user credentials
def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # user = db.query(User).filter(User.email == email, User.password == password).first()
    # if user:
    #     return RedirectResponse("/success", status_code=303) #if valid they'll be redirected to success page
    # return RedirectResponse("/login", status_code=303) #if not then error
    user = db.query(User).filter(User.email == email).first()
    if user and verify_password(password, user.password):
    #     token = create_jwt_token({"sub": user.email})
    #     return JSONResponse(content={"access_token": token, "token_type": "bearer"})
    # return JSONResponse(content={"error": "Invalid credentials"}, status_code=401)
        return RedirectResponse("/success", status_code=303) #if valid they'll be redirected to success page
    return RedirectResponse("/login", status_code=303) #if not then error

#GET route to show success page
@app.get("/success", response_class=HTMLResponse)
def success_page(request: Request):
    return templates.TemplateResponse("success.html", {"request": request})

#password complexity validation
def validate_password_complexity(password: str):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
    if not re.match(pattern, password):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long, include 1 uppercase, 1 lowercase, 1 number, and 1 special character."
         )
    
# User enters their email to reset their password.
# If the email exists:
# 1. A secure token is generated.
# 2. An email with the reset link is sent.
# If not, shows an error.
@app.post("/send-reset-link")
async def send_reset_link(
    request: Request,  
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return templates.TemplateResponse("login.html", {
                "request": request, 
                "error": "E-mail not found."
            })

        token = generate_reset_token(email)
        send_reset_email(email, token)

        return templates.TemplateResponse("login.html", {
            "request": request,  
            "message": "Password reset link has been sent to your e-mail."
        })
    except Exception as e:
        print("ERROR during send-reset-link:", str(e))
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Something went wrong. Please try again."
        })

#save in .env file for security
SECRET_KEY = "jdcfbaw3gqiuwe183719412bhsdvbskdjvszkjbjabsiuGSAFUSDGVJSD"
SECURITY_PASSWORD_SALT = "bdxajwhge72euf09weugvewv"

#generate_reset_token and verify_reset_token use itsdangerous to safely encode/decode the email in a time-limited token
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    return serializer.dumps(email, salt=SECURITY_PASSWORD_SALT)

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    try:
        email = serializer.loads(token, salt=SECURITY_PASSWORD_SALT, max_age=expiration)
    except:
        return None
    return email

#Sends an actual email with a password reset link using Gmail's SMTP
def send_reset_email(to_email: str, token: str):
    reset_link = f"http://127.0.0.1:8000/reset-password/{token}"
    body = f"Click the link to reset your password: {reset_link}"

    msg = MIMEText(body)
    msg['Subject'] = 'Reset Your Password'
    msg['From'] = 'diyaisworking@gmail.com'
    msg['To'] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login("diyaisworking@gmail.com", "umfh fhks yzvz evdl") 
        #pmum jtrg ghrj vxyh
        #"umfh fhks yzvz evdl"
        server.send_message(msg)

#User opens the link from their email.
#This shows the password reset form with the token.
@app.get("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_form(token: str, request: Request):
    return templates.TemplateResponse("reset.html", {"request": request, "token": token})

#User submits the new password.
# Token is verified.
# Password is checked against password history table
# Password is validated against its hashed password.
# If everything checks out, the user's password is updated.
@app.post("/reset-password/{token}")
async def reset_password(request: Request ,token: str, password: str = Form(...), db: Session = Depends(get_db)):
    email = verify_reset_token(token)
    if not email:
        return templates.TemplateResponse("reset.html", {
            "request": request,
            "token": token,
            "error": "Invalid or expired link."
        })

    #validate_password_complexity(password)
    try:
        validate_password_complexity(password)
    except HTTPException as e:
        return templates.TemplateResponse("reset.html", {
            "request": request,
            "token": token,
            "error": e.detail
        })
    
    user = db.query(User).filter(User.email == email).first()
    # if user:
    #     user.password = hash_password(password)
    #     db.commit()
    if not user:
        return templates.TemplateResponse("reset.html", {
            "request": request, #small
            "token": token,
            "error": "User not found."
        })

    #check if the password has been used before
    previous_passwords = db.query(PasswordHistory).filter(PasswordHistory.user_id == user.id).all()
    for old in previous_passwords:
        try:
            if bcrypt.checkpw(password.encode('utf-8'), old.hashed_password.encode('utf-8')):
                print("Matched reused password. Blocking reset.")
                return templates.TemplateResponse("reset.html", {
                    "request": request, #small
                    "token": token,
                    "error": "You have used this password before. Please choose a new one."
                })
        except Exception as e:
            print("Error checking password history:", str(e))
            return templates.TemplateResponse("reset.html", {
                "request": request,
                "token": token,
                "error": "Something went wrong while checking your password history."
            })
    
    #hash and update the password
    new_hashed = hash_password(password)
    user.password = new_hashed
    db.add(PasswordHistory(user_id=user.id, hashed_password=new_hashed))
    db.commit()

    return RedirectResponse("/login", status_code=303)


#JSON web token
#jwt authentication
#secret signs the tokens securely
JWT_SECRET = "evh1ywf216rew12esy1vcydsg7ts28vfttz7twe12hdev2jcdq"  # Moving to .env later
JWT_ALGORITHM = "HS256" #standard hmac algo which encodes the token
JWT_EXPIRE_MINUTES = 30 #expiry time
IST=pytz.timezone('Asia/Kolkata')

#func to create a token
def create_jwt_token(data: dict, expires_delta: timedelta = timedelta(minutes=JWT_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.now(IST) + expires_delta #adds expiration to the token
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM) #returns the encrypted token

def decode_jwt_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM]) #returns the decoded token
    except JWTError:
        return None

#renders the login form
@app.get("/login-jwt", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login-jwt")
#checks user credentials
def login_jwt(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = form_data.username  # because OAuth2 spec uses 'username'
    password = form_data.password

    user = db.query(User).filter(User.email == email).first()
    if user and verify_password(password, user.password):
        token = create_jwt_token({"sub": user.email})
        return {"access_token": token, "token_type": "bearer"}
    return JSONResponse(content={"error": "Invalid credentials"}, status_code=401)

#tells fastapi to expect the jwt in authorisation: header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login-jwt")

#extracts and verifies the token and loads user from the db
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    
    user = db.query(User).filter(User.email == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

#only accessible iftoken is valid
@app.get("/protected")
def protected_route(current_user: User = Depends(get_current_user)):
    return {
            "message": f"Hi {current_user.name}!",
            "email": current_user.email,
            "user_id": current_user.id,
            "gender": current_user.gender
            }
