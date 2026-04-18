import json
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from app.schemas import RunLog


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "data" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def generate_run_id() -> str:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    short_id = uuid4().hex[:6]
    return f"RUN-{timestamp}-{short_id}"


def save_log(log: RunLog) -> None:
    file_path = LOG_DIR / f"{log.run_id}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(log.model_dump(), f, ensure_ascii=False, indent=2)


def load_logs() -> list[dict]:
    logs = []
    for file_path in sorted(LOG_DIR.glob("*.json"), reverse=True):
        with open(file_path, "r", encoding="utf-8") as f:
            logs.append(json.load(f))
    return logs