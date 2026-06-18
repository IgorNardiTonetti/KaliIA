from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_CONFIG: dict[str, str] = {
    "kali_ip": "",
    "ssh_user": "kali",
    "ssh_password": "",
    "ollama_model": "deephat-v1-ptbr:latest",
}


class ConfigManager:
    def __init__(self, config_path: str | Path) -> None:
        self.config_path = Path(config_path)

    def load(self) -> dict[str, str]:
        if not self.config_path.exists():
            self.save(DEFAULT_CONFIG)
            return DEFAULT_CONFIG.copy()

        try:
            with self.config_path.open("r", encoding="utf-8") as file:
                raw_data: Any = json.load(file)
        except json.JSONDecodeError:
            backup_path = self._backup_invalid_config()
            self.save(DEFAULT_CONFIG)
            raise RuntimeError(
                f"config.json estava inválido. Backup criado em: {backup_path}"
            )
        except OSError as exc:
            raise RuntimeError(f"Não foi possível ler config.json: {exc}") from exc

        if not isinstance(raw_data, dict):
            self.save(DEFAULT_CONFIG)
            raise RuntimeError("config.json não contém um objeto JSON válido.")

        config = DEFAULT_CONFIG.copy()
        for key in DEFAULT_CONFIG:
            value = raw_data.get(key, DEFAULT_CONFIG[key])
            config[key] = "" if value is None else str(value)

        return config

    def save(self, config: dict[str, str]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        clean_config = DEFAULT_CONFIG.copy()
        for key in DEFAULT_CONFIG:
            clean_config[key] = str(config.get(key, DEFAULT_CONFIG[key]))

        try:
            with self.config_path.open("w", encoding="utf-8") as file:
                json.dump(clean_config, file, indent=2, ensure_ascii=False)
        except OSError as exc:
            raise RuntimeError(f"Não foi possível salvar config.json: {exc}") from exc

    def _backup_invalid_config(self) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = self.config_path.with_name(f"config.invalid-{timestamp}.json")
        try:
            self.config_path.replace(backup_path)
        except OSError as exc:
            raise RuntimeError(
                f"config.json está inválido e não foi possível criar backup: {exc}"
            ) from exc
        return backup_path
