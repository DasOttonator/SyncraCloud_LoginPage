from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "SyncraCloud Auth Service"
    ENVIRONMENT: str = "development"  # Switch to 'production' on live deployment

    # MUST MATCH AUTH_SECRET_KEY in the guarded website's auth_guard.py
    SECRET_KEY: str = "CHANGE_THIS_TO_A_SECURE_64_CHAR_HEX_KEY"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 Hours

    COOKIE_NAME: str = "syncra_session"
    CSRF_COOKIE_NAME: str = "syncra_csrf"

    # In production, set to ".syncracloud.co.za" to share across all subdomains
    # In local testing on localhost, leave as None
    COOKIE_DOMAIN: str | None = None

    # Default destination after login if no return_to is specified
    DEFAULT_REDIRECT_URL: str = "http://localhost:8020/"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()