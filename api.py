import os
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, status, Depends, Request, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import jwt
from functools import wraps
import secrets
from passlib.context import CryptContext

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./test.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True)
    revoked_at = Column(DateTime, default=datetime.timetz)


Base.metadata.create_all(bind=engine)


class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
    ip: Optional[str] = None
    jti: Optional[str] = None


class UserIn(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=6)
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v not in ["admin", "user", "guest"]:
            raise ValueError("Role must be admin, user, or guest")
        return v


app = FastAPI(title="Secure REST API with Attack Simulation")

origins = [
    "http://localhost",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FAILED_LOGIN_ATTEMPTS = {}
BLOCKED_IPS = {}
MAX_ATTEMPTS = 5
BLOCK_TIME = 60


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_token_with_jti(
    data: dict, expires_delta: timedelta, token_type: str = "access"
):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    jti = secrets.token_hex(16)
    to_encode.update(
        {"exp": expire, "iat": datetime.utcnow(), "jti": jti, "type": token_type}
    )
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token, jti


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    delta = expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token, _ = create_token_with_jti(data, delta)
    return token


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    delta = expires_delta or timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    token, _ = create_token_with_jti(data, delta, "refresh")
    return token


def is_token_revoked(jti: str, db: Session):
    return db.query(RevokedToken).filter(RevokedToken.jti == jti).first() is not None


def revoke_token(jti: str, db: Session):
    revoked = RevokedToken(jti=jti)
    db.add(revoked)
    db.commit()


def extract_token_data(token: str, db: Session) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")

        if jti and is_token_revoked(jti, db):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )

        return TokenData(
            username=payload.get("sub"),
            role=payload.get("role"),
            ip=payload.get("ip"),
            jti=jti,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    client_ip = request.client.host

    if client_ip in BLOCKED_IPS:
        if time.time() < BLOCKED_IPS[client_ip]:
            raise HTTPException(
                status_code=403,
                detail="IP address blocked due to too many failed attempts",
            )
        else:
            del BLOCKED_IPS[client_ip]

    content_type = request.headers.get("content-type", "")
    if (
        "application/json" in content_type
        or "application/x-www-form-urlencoded" in content_type
    ):
        body = await request.body()
        body_str = body.decode().lower()
        suspicious_patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "eval(",
            "document.cookie",
            "alert(",
        ]
        if any(pattern in body_str for pattern in suspicious_patterns):
            raise HTTPException(
                status_code=403, detail="Suspicious request blocked by WAF"
            )

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    return response


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    request: Request = None,
    db: Session = Depends(get_db),
):
    token_data = extract_token_data(token, db)
    if request and token_data.ip and request.client.host != token_data.ip:
        raise HTTPException(
            status_code=401, detail="Token was not issued from this IP address"
        )
    user = db.query(User).filter(User.username == token_data.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def role_required(required_role: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(
            *args, current_user: User = Depends(get_current_user), **kwargs
        ):
            roles_hierarchy = {"admin": 3, "user": 2, "guest": 1}
            if roles_hierarchy.get(current_user.role, 0) < roles_hierarchy.get(
                required_role, 0
            ):
                raise HTTPException(status_code=403, detail="Insufficient privileges")
            return await func(*args, current_user=current_user, **kwargs)

        return wrapper

    return decorator


@app.post("/register", response_model=Token)
def register(user_in: UserIn, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_in.username).first()
    if user:
        raise HTTPException(status_code=400, detail="User already exists")
    new_user = User(
        username=user_in.username,
        hashed_password=hash_password(user_in.password),
        role=user_in.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    token_data = {
        "sub": new_user.username,
        "role": new_user.role,
        "ip": request.client.host,
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    return Token(
        access_token=access_token, token_type="bearer", refresh_token=refresh_token
    )


@app.post("/token", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: Session = Depends(get_db),
):
    client_ip = request.client.host
    FAILED_LOGIN_ATTEMPTS.setdefault(client_ip, 0)

    if FAILED_LOGIN_ATTEMPTS[client_ip] >= MAX_ATTEMPTS:
        BLOCKED_IPS[client_ip] = time.time() + BLOCK_TIME
        raise HTTPException(
            status_code=403, detail="IP blocked due to too many failed attempts"
        )

    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        FAILED_LOGIN_ATTEMPTS[client_ip] += 1
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    FAILED_LOGIN_ATTEMPTS[client_ip] = 0

    token_data = {"sub": user.username, "role": user.role, "ip": client_ip}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return Token(
        access_token=access_token, token_type="bearer", refresh_token=refresh_token
    )


@app.post("/token/refresh", response_model=Token)
def refresh_token_endpoint(
    refresh_token: str = Header(...),
    request: Request = None,
    db: Session = Depends(get_db),
):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

        jti = payload.get("jti")
        if jti and is_token_revoked(jti, db):
            raise HTTPException(status_code=401, detail="Token has been revoked")

        if jti:
            revoke_token(jti, db)

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    token_data = {
        "sub": payload.get("sub"),
        "role": payload.get("role"),
        "ip": request.client.host,
    }

    access_token = create_access_token(token_data)
    new_refresh_token = create_refresh_token(token_data)

    return Token(
        access_token=access_token, token_type="bearer", refresh_token=new_refresh_token
    )


@app.post("/logout")
async def logout(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if jti:
            revoke_token(jti, db)
        return {"message": "Successfully logged out"}
    except (jwt.JWTError, jwt.ExpiredSignatureError):
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/protected")
@role_required("user")
async def protected_resource(current_user: User = Depends(get_current_user)):
    return {
        "message": f"Hello, {current_user.username}. You have access to the protected resource."
    }


@app.get("/admin")
@role_required("admin")
async def admin_resource(current_user: User = Depends(get_current_user)):
    return {"message": f"Admin panel - welcome, {current_user.username}"}


@app.post("/sensitive-action")
async def sensitive_action(request: Request, csrf_token: str = Header(...)):
    session_csrf_token = request.cookies.get("csrf_token")
    if not session_csrf_token or csrf_token != session_csrf_token:
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    return {"message": "Sensitive action completed"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
