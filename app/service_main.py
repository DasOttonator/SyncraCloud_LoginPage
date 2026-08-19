import secrets
from pathlib import Path
import uvicorn
from fastapi import FastAPI, Request, Response, Depends, Form, HTTPException, status
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
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Path to HTML files directory
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


# --- SECURITY MIDDLEWARE ---
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# --- STATIC HTML PAGE HANDLERS (No Template Engine Needed) ---

@app.get("/", response_class=FileResponse)
async def serve_home():
    return FileResponse(TEMPLATES_DIR / "index.html")


@app.get("/login", response_class=FileResponse)
async def serve_login(response: Response):
    # Set CSRF cookie directly on the response
    csrf_token = secrets.token_urlsafe(32)
    res = FileResponse(TEMPLATES_DIR / "index.html")
    res.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=(settings.ENVIRONMENT == "production"),
        samesite="lax"
    )
    return res


@app.get("/register", response_class=FileResponse)
async def serve_register():
    return FileResponse(TEMPLATES_DIR / "register.html")


# --- AUTH ENDPOINTS ---

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

    existing_user = db.query(User).filter(User.email == cleaned_email).first()
    if existing_user:
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
    db.refresh(new_user)

    return {"message": "User registered successfully.", "email": new_user.email}


@app.post("/api/login")
@limiter.limit("5/minute")
async def login_endpoint(
        request: Request,
        email: str = Form(...),
        password: str = Form(...),
        remember: bool = Form(False),
        db: Session = Depends(get_db)
):
    cleaned_email = email.strip().lower()
    user = db.query(User).filter(User.email == cleaned_email).first()

    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    token_lifetime = 30 * 24 * 60 if remember else settings.ACCESS_TOKEN_EXPIRE_MINUTES
    token = create_access_token(data={"sub": user.email, "role": user.role})

    response = JSONResponse(content={"message": "Authentication successful.", "redirect": "/"})
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=token,
        httponly=True,
        secure=(settings.ENVIRONMENT == "production"),
        samesite="lax",
        max_age=token_lifetime * 60
    )
    return response


@app.post("/api/contact")
@limiter.limit("3/minute")
async def contact_inquiry(
        request: Request,
        name: str = Form(...),
        email: str = Form(...),
        service_select: str = Form(...),
        message: str = Form(...)
):
    return {"message": "Thank you. Your request has been securely processed."}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8030)