from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "SyncraCloud Auth Service"
    ENVIRONMENT: str = "production"  # change to 'development' for local tests
    SECRET_KEY: str = "CHANGE_THIS_TO_A_SECURE_64_CHAR_HEX_KEY"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Cookie security
    COOKIE_NAME: str = "syncra_session"
    CSRF_COOKIE_NAME: str = "syncra_csrf"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()