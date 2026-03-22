from __future__ import annotations

from dotenv import load_dotenv
import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
load_dotenv(BASE_DIR / ".env")

def _default_db_path() -> Path:
    if Path("/.dockerenv").exists():
        return Path("/data/bd.sqlite")
    return PROJECT_ROOT / "server_app" / "bd.sqlite"

BIND_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", "9090"))
BACKLOG = int(os.getenv("SERVER_BACKLOG", "5"))
SOCKET_TIMEOUT = float(os.getenv("SERVER_SOCKET_TIMEOUT", "1"))
DB_PATH = Path(os.getenv("SERVER_DB_PATH", str(_default_db_path())))
LOG_DIR = Path(os.getenv("SERVER_LOG_DIR", PROJECT_ROOT / "server_app" / "server_logs"))
