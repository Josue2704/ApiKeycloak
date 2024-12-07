from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    secret_key: str
    database_url: str
    app_port: int = 8000

    class Config:
        env_file = ".env"

settings = Settings()
