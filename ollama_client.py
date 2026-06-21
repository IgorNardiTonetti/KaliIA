from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from threading import Event
from typing import Any, Callable

import requests


class OllamaClient:
    DEFAULT_OPTIONS: dict[str, Any] = {
        "temperature": 0.1,
        "top_p": 0.9,
        "num_ctx": 8192,
        "num_predict": 4096,
        "repeat_last_n": 1024,
        "repeat_penalty": 1.15,
    }

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        auto_start: bool = True,
        log_dir: str | Path | None = None,
        startup_timeout: int = 20,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.chat_url = f"{self.base_url}/api/chat"
        self.tags_url = f"{self.base_url}/api/tags"
        self.auto_start = auto_start
        self.log_dir = Path(log_dir) if log_dir else None
        self.startup_timeout = startup_timeout
        self._process: subprocess.Popen[bytes] | None = None

    def chat(
        self,
        model: str,
        rules: str,
        history: list[dict[str, str]],
        user_message: str,
        timeout: int = 900,
    ) -> str:
        chunks: list[str] = []
        return self.stream_chat(
            model=model,
            rules=rules,
            history=history,
            user_message=user_message,
            on_chunk=chunks.append,
            timeout=timeout,
        )

    def stream_chat(
        self,
        model: str,
        rules: str,
        history: list[dict[str, str]],
        user_message: str,
        on_chunk: Callable[[str], None],
        on_status: Callable[[str], None] | None = None,
        stop_event: Event | None = None,
        timeout: int = 900,
    ) -> str:
        self._status(on_status, "verificando Ollama")
        self.ensure_running()
        messages = self._build_messages(
            rules,
            history,
            self._fast_user_message(model, user_message),
        )
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": True,
            "options": self.DEFAULT_OPTIONS,
            "keep_alive": "30m",
        }
        chunks: list[str] = []
        first_chunk_received = False
        done_reason = ""

        try:
            self._status(on_status, "requisição enviada; aguardando primeiro token")
            with requests.post(
                self.chat_url,
                json=payload,
                stream=True,
                timeout=(10, timeout),
            ) as response:
                response.raise_for_status()
                self._status(on_status, "Ollama aceitou a requisição")
                for line in response.iter_lines(decode_unicode=True):
                    if stop_event and stop_event.is_set():
                        self._status(on_status, "geração interrompida")
                        return "".join(chunks).strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise RuntimeError(f"Ollama enviou JSON inválido: {line[:200]}") from exc

                    if data.get("error"):
                        raise RuntimeError(f"Ollama retornou erro: {data['error']}")

                    chunk = str(data.get("message", {}).get("content") or "")
                    if chunk:
                        if not first_chunk_received:
                            first_chunk_received = True
                            self._status(on_status, "recebendo resposta")
                        chunks.append(chunk)
                        on_chunk(chunk)

                    if data.get("done"):
                        done_reason = str(data.get("done_reason") or "")
                        self._status(on_status, "resposta concluída")
                        break
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                "O Ollama não respondeu em http://localhost:11434. "
                "Tentei iniciar automaticamente, mas a API continuou indisponível."
            ) from exc
        except requests.exceptions.Timeout as exc:
            if chunks:
                notice = "\n\n[Resposta parcial: o Ollama demorou demais para continuar.]"
                chunks.append(notice)
                on_chunk(notice)
                return "".join(chunks).strip()
            raise RuntimeError(
                "Ollama não enviou o primeiro token dentro do limite. "
                "Use uma pergunta menor, reinicie o Ollama ou troque para um modelo mais leve."
            ) from exc
        except requests.exceptions.HTTPError as exc:
            detail = response.text[:500] if "response" in locals() else str(exc)
            raise RuntimeError(f"Ollama retornou erro HTTP: {detail}") from exc
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Erro ao chamar a API do Ollama: {exc}") from exc

        content = "".join(chunks).strip()
        if done_reason == "length":
            notice = (
                "\n\n[Resposta pausada porque atingiu o limite de tamanho. "
                "Envie 'continue' para eu seguir do ponto em que parei.]"
            )
            chunks.append(notice)
            on_chunk(notice)
            content = "".join(chunks).strip()

        if not content and not (stop_event and stop_event.is_set()):
            raise RuntimeError("Ollama terminou sem enviar conteúdo.")

        return content

    def test(self, model: str, rules: str) -> str:
        self.ensure_running()
        try:
            response = requests.get(self.tags_url, timeout=10)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Ollama está ativo, mas não respondeu ao teste: {exc}") from exc
        except ValueError as exc:
            raise RuntimeError("Ollama respondeu ao teste com JSON inválido.") from exc

        model_names = {item.get("name") for item in data.get("models", [])}
        if model in model_names:
            return f"OK - API ativa e modelo {model} encontrado."

        available = ", ".join(sorted(str(name) for name in model_names if name))
        if available:
            return f"API ativa, mas o modelo {model} não apareceu. Modelos: {available}"
        return "API ativa, mas nenhum modelo foi listado."

    def warm_up(
        self,
        model: str,
        rules: str,
        on_status: Callable[[str], None] | None = None,
        timeout: int = 900,
    ) -> str:
        chunks: list[str] = []
        text = self.stream_chat(
            model=model,
            rules=rules,
            history=[],
            user_message="Responda somente OK.",
            on_chunk=chunks.append,
            on_status=on_status,
            timeout=timeout,
        )
        compact = " ".join(text.split())
        if not compact:
            raise RuntimeError("Ollama carregou o modelo, mas nao retornou texto.")
        return compact[:120]

    def ensure_running(self) -> None:
        if self._is_running():
            return

        if not self.auto_start:
            raise RuntimeError(
                "Não foi possível conectar ao Ollama em http://localhost:11434. "
                "Inicie com: ollama serve"
            )

        self._start_server()
        if self._wait_until_running():
            return

        log_hint = ""
        if self.log_dir:
            log_hint = f" Veja o log em: {self.log_dir / 'ollama-serve.log'}"

        raise RuntimeError(
            "Tentei iniciar o Ollama automaticamente, mas a API não ficou disponível "
            f"em {self.startup_timeout}s.{log_hint}"
        )

    def _is_running(self) -> bool:
        try:
            response = requests.get(self.tags_url, timeout=2)
            return response.status_code < 500
        except requests.exceptions.RequestException:
            return False

    def _start_server(self) -> None:
        ollama_path = shutil.which("ollama")
        if not ollama_path:
            raise RuntimeError(
                "O executável 'ollama' não foi encontrado no PATH. "
                "Instale o Ollama ou abra o app do Ollama antes de usar."
            )

        if self._process and self._process.poll() is None:
            return

        log_handle = None
        stdout_target = subprocess.DEVNULL
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            log_path = self.log_dir / "ollama-serve.log"
            log_handle = log_path.open("ab")
            stdout_target = log_handle

        creationflags = 0
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            creationflags = subprocess.CREATE_NO_WINDOW

        try:
            self._process = subprocess.Popen(
                [ollama_path, "serve"],
                stdin=subprocess.DEVNULL,
                stdout=stdout_target,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
        except OSError as exc:
            raise RuntimeError(f"Não foi possível iniciar 'ollama serve': {exc}") from exc
        finally:
            if log_handle:
                log_handle.close()

    def _wait_until_running(self) -> bool:
        deadline = time.time() + self.startup_timeout
        while time.time() < deadline:
            if self._is_running():
                return True
            if self._process and self._process.poll() is not None:
                break
            time.sleep(0.5)
        return False

    @staticmethod
    def _status(callback: Callable[[str], None] | None, message: str) -> None:
        if callback:
            callback(message)

    @staticmethod
    def _fast_user_message(model: str, user_message: str) -> str:
        if "/no_think" in user_message.lower():
            return user_message
        model_name = model.lower()
        if "qwen3" in model_name or model_name == "deephat:latest":
            return "/no_think\n" + user_message
        return user_message

    @staticmethod
    def _build_messages(
        rules: str, history: list[dict[str, str]], user_message: str
    ) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        if rules.strip():
            messages.append({"role": "system", "content": rules.strip()})

        for item in history[-10:]:
            role = item.get("role", "")
            content = item.get("content", "")
            if role in {"user", "assistant"} and content:
                messages.append({"role": role, "content": content[-4000:]})

        messages.append({"role": "user", "content": user_message})
        return messages
