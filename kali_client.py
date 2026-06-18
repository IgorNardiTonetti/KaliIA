from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Event
from typing import Callable

import paramiko


@dataclass
class SSHCommandResult:
    command: str
    exit_status: int
    stdout: str
    stderr: str
    timed_out: bool = False

    def as_text(self) -> str:
        timeout_text = "sim" if self.timed_out else "não"
        parts = [
            f"Comando: {self.command}",
            f"Exit status: {self.exit_status}",
            f"Timeout: {timeout_text}",
            "",
            "[stdout]",
            self.stdout.strip() or "(vazio)",
            "",
            "[stderr]",
            self.stderr.strip() or "(vazio)",
        ]
        return "\n".join(parts)


class KaliClient:
    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 12,
    ) -> None:
        self.hostname = hostname.strip()
        self.username = username.strip()
        self.password = password
        self.port = port
        self.timeout = timeout

    def test_connection(self) -> SSHCommandResult:
        result = self.execute("echo SSH_OK && uname -a", timeout=15)
        if result.exit_status != 0:
            raise RuntimeError(result.as_text())
        return result

    def execute(self, command: str, timeout: int = 120) -> SSHCommandResult:
        return self.execute_stream(command, timeout=timeout)

    def execute_stream(
        self,
        command: str,
        timeout: int = 120,
        on_stdout: Callable[[str], None] | None = None,
        on_stderr: Callable[[str], None] | None = None,
        on_status: Callable[[str], None] | None = None,
        stop_event: Event | None = None,
    ) -> SSHCommandResult:
        if not self.hostname:
            raise ValueError("IP do Kali não informado.")
        if not self.username:
            raise ValueError("Usuário SSH não informado.")
        if not self.password:
            raise ValueError("Senha SSH não informada.")
        if not command.strip():
            raise ValueError("Comando vazio.")

        client = self._connect()
        try:
            self._status(on_status, "conectado ao Kali; iniciando comando")
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            stdin.close()
            channel = stdout.channel
            channel.settimeout(1.0)
            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []
            deadline = time.time() + timeout
            timed_out = False
            stopped = False

            while not channel.exit_status_ready():
                self._drain_channel(channel, stdout_chunks, stderr_chunks, on_stdout, on_stderr)
                if stop_event and stop_event.is_set():
                    stopped = True
                    channel.close()
                    break
                if time.time() > deadline:
                    timed_out = True
                    channel.close()
                    break
                time.sleep(0.1)

            self._drain_channel(channel, stdout_chunks, stderr_chunks, on_stdout, on_stderr)
            exit_status = -1 if timed_out or stopped else channel.recv_exit_status()

            if stopped:
                self._append_stderr(
                    "\n[execução interrompida pelo usuário]\n",
                    stderr_chunks,
                    on_stderr,
                )
            elif timed_out:
                self._append_stderr("\n[timeout da execução SSH]\n", stderr_chunks, on_stderr)

            self._status(on_status, "comando finalizado")
            return SSHCommandResult(
                command=command,
                exit_status=exit_status,
                stdout=self._decode(stdout_chunks),
                stderr=self._decode(stderr_chunks),
                timed_out=timed_out,
            )
        except paramiko.SSHException as exc:
            raise RuntimeError(f"Erro SSH ao executar comando: {exc}") from exc
        finally:
            client.close()

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException as exc:
            raise RuntimeError("Falha de autenticação SSH.") from exc
        except paramiko.SSHException as exc:
            raise RuntimeError(f"Erro SSH: {exc}") from exc
        except OSError as exc:
            raise RuntimeError(f"Não foi possível conectar ao Kali: {exc}") from exc

        return client

    @staticmethod
    def _drain_channel(
        channel: paramiko.Channel,
        stdout_chunks: list[bytes],
        stderr_chunks: list[bytes],
        on_stdout: Callable[[str], None] | None = None,
        on_stderr: Callable[[str], None] | None = None,
    ) -> None:
        while channel.recv_ready():
            chunk = channel.recv(4096)
            stdout_chunks.append(chunk)
            if on_stdout:
                on_stdout(chunk.decode("utf-8", errors="replace"))
        while channel.recv_stderr_ready():
            chunk = channel.recv_stderr(4096)
            stderr_chunks.append(chunk)
            if on_stderr:
                on_stderr(chunk.decode("utf-8", errors="replace"))

    @staticmethod
    def _append_stderr(
        text: str,
        stderr_chunks: list[bytes],
        on_stderr: Callable[[str], None] | None,
    ) -> None:
        stderr_chunks.append(text.encode("utf-8"))
        if on_stderr:
            on_stderr(text)

    @staticmethod
    def _status(callback: Callable[[str], None] | None, message: str) -> None:
        if callback:
            callback(message)

    @staticmethod
    def _decode(chunks: list[bytes]) -> str:
        return b"".join(chunks).decode("utf-8", errors="replace")
