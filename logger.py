from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path


def ensure_project_dirs(base_dir: str | Path) -> tuple[Path, Path]:
    root = Path(base_dir)
    logs_dir = root / "logs"
    reports_dir = root / "reports"
    logs_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir, reports_dir


class AppLogger:
    def __init__(self, base_dir: str | Path) -> None:
        logs_dir, _ = ensure_project_dirs(base_dir)
        self.log_path = logs_dir / f"assistant-{datetime.now():%Y%m%d}.log"
        self._logger = logging.getLogger("ai_kali_assistant")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._ensure_file_handler()

    def _ensure_file_handler(self) -> None:
        resolved_log_path = str(self.log_path.resolve())
        for handler in self._logger.handlers:
            if getattr(handler, "baseFilename", None) == resolved_log_path:
                return

        file_handler = logging.FileHandler(self.log_path, encoding="utf-8")
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        self._logger.addHandler(file_handler)

    def info(self, message: str) -> None:
        self._logger.info(message)

    def warning(self, message: str) -> None:
        self._logger.warning(message)

    def error(self, message: str) -> None:
        self._logger.error(message)

    def exception(self, message: str) -> None:
        self._logger.exception(message)
