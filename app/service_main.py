import secrets
from pathlib import Path
import uvicorn
from fastapi import FastAPI, Request, Response, Depends, Form, HTTPException, status, Query
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.auth import get_password_hash, verify_password, create_access_token
from app.models import get_db, User

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title=settings.APP_NAME, docs_url=None, redoc_url=None)
setattr(app.state, "limiter", limiter)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

@app.get("/", response_class=FileResponse)
async def serve_home():
    return FileResponse(TEMPLATES_DIR / "index.html")

@app.get("/login", response_class=FileResponse)
async def serve_login():
    return FileResponse(TEMPLATES_DIR / "index.html")

@app.get("/register", response_class=FileResponse)
async def serve_register():
    return FileResponse(TEMPLATES_DIR / "register.html")

@app.post("/api/login")
@limiter.limit("5/minute")
async def login_endpoint(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    remember: bool = Form(False),
    return_to: str = Form(None),
    db: Session = Depends(get_db)
):
    cleaned_email = email.strip().lower()
    user = db.query(User).filter_by(email=cleaned_email).first()

    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    token_lifetime = 30 * 24 * 60 if remember else settings.ACCESS_TOKEN_EXPIRE_MINUTES
    token = create_access_token(data={"sub": user.email, "role": user.role})

    # Validate destination URL to prevent open redirects
    redirect_target = return_to if return_to and (
        return_to.startswith("/") or
        return_to.startswith("http://localhost:8020") or
        "syncracloud.co.za" in return_to
    ) else settings.DEFAULT_REDIRECT_URL

    response = JSONResponse(content={
        "message": "Authentication successful.",
        "redirect": redirect_target
    })

    # Set authentication cookie readable by both services
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=token,
        httponly=True,
        secure=(settings.ENVIRONMENT == "production"),
        samesite="lax",
        domain=settings.COOKIE_DOMAIN,
        max_age=token_lifetime * 60
    )
    return response

@app.post("/api/register")
@limiter.limit("5/minute")
async def register_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("client"),
    db: Session = Depends(get_db)
):
    cleaned_email = email.strip().lower()
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )

    if db.query(User).filter_by(email=cleaned_email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists."
        )

    new_user = User(
        email=cleaned_email,
        password_hash=get_password_hash(password),
        role=role
    )
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully.", "email": new_user.email}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8030)