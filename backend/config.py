from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    app_name: str = "Sysmon Hunter"
    rules_dir: Path = BASE_DIR / "rules"
    db_url: str = f"sqlite+aiosqlite:///{BASE_DIR / 'data' / 'hunter.db'}"
    host: str = "0.0.0.0"
    port: int = 8000

    class Config:
        env_file = ".env"


settings = Settings()
(BASE_DIR / "data").mkdir(exist_ok=True)