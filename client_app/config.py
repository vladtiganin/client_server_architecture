from __future__ import annotations

from dotenv import load_dotenv
import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

load_dotenv(BASE_DIR / ".env")

DEFAULT_HOST = os.getenv("CLIENT_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("CLIENT_PORT", "9090"))
LOG_DIR = Path(os.getenv("CLIENT_LOG_DIR", PROJECT_ROOT / "client_logs"))
