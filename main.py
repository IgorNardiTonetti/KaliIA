from __future__ import annotations

import re
import textwrap
import threading
import time
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable
import tkinter as tk

from config_manager import ConfigManager, DEFAULT_CONFIG
from kali_client import KaliClient, SSHCommandResult
from logger import AppLogger, ensure_project_dirs
from ollama_client import OllamaClient
from rules_manager import RulesManager


APP_DIR = Path(__file__).resolve().parent
COMMAND_TIMEOUT_SECONDS = 120
ANALYSIS_OUTPUT_LIMIT = 16000


class AiKaliAssistantApp:
    COMMAND_HINTS = {
        "amass",
        "arp-scan",
        "dig",
        "dirb",
        "enum4linux",
        "feroxbuster",
        "ffuf",
        "gobuster",
        "host",
        "hydra",
        "masscan",
        "nbtscan",
        "nc",
        "netcat",
        "nikto",
        "nmap",
        "nslookup",
        "nuclei",
        "ping",
        "smbclient",
        "smbmap",
        "sqlmap",
        "sslscan",
        "testssl.sh",
        "traceroute",
        "whatweb",
        "whois",
        "wpscan",
    }

    SHELL_PREFIXES = COMMAND_HINTS | {
        "cat",
        "cd",
        "curl",
        "grep",
        "head",
        "ip",
        "journalctl",
        "ls",
        "netstat",
        "openssl",
        "python",
        "python3",
        "ss",
        "sudo",
        "tail",
        "wget",
    }

    BLOCKED_PATTERNS = [
        (r"\brm\s+-[^\n]*[rf][^\n]*\s+/", "remoção destrutiva no sistema"),
        (r"\bmkfs\b", "formatação de disco"),
        (r"\bdd\s+.*\bof=", "escrita bruta em disco"),
        (r"\bshutdown\b|\breboot\b|\bpoweroff\b", "desligamento ou reinício"),
        (r"\bnc\s+.*\s-e\s", "shell reverso com netcat"),
        (r"\bbash\s+-i\b", "shell interativo remoto"),
        (r"/dev/tcp/", "shell ou conexão TCP manual suspeita"),
        (r"\bmsfvenom\b", "geração de payload"),
        (r"\bmeterpreter\b", "sessão/payload Meterpreter"),
    ]

    INTENSIVE_PATTERNS = [
        (r"\bmasscan\b", "varredura de portas em alta velocidade"),
        (r"\bhydra\b|\bmedusa\b|\bncrack\b", "tentativa de autenticação em volume"),
        (r"\bsqlmap\b", "teste automatizado que pode gerar muitas requisições"),
        (r"\bnuclei\b", "varredura automatizada por templates"),
        (r"\bffuf\b|\bgobuster\b|\bferoxbuster\b|\bdirb\b", "enumeração por wordlist"),
        (r"\bnmap\b.*\s-A\b", "nmap em modo agressivo"),
        (r"\bnmap\b.*\s-T[45]\b", "nmap com temporização alta"),
        (r"\bnmap\b.*\s-p-\b", "varredura de todas as portas"),
        (r"/(?:1[6-9]|2[0-9]|3[0-2])\b", "alvo em faixa CIDR ampla"),
    ]

    COLORS = {
        "bg": "#0d1014",
        "surface": "#161b20",
        "surface_2": "#202730",
        "surface_3": "#29313a",
        "border": "#333d46",
        "text": "#edf2f4",
        "muted": "#9da8b3",
        "input": "#0a0d10",
        "terminal": "#050708",
        "accent": "#3ddc84",
        "accent_hover": "#62e79f",
        "cyan": "#46c7dd",
        "purple": "#b494ff",
        "warning": "#f2b84b",
        "danger": "#ff5c6c",
        "danger_hover": "#ff7a86",
        "button": "#27303a",
        "button_hover": "#343e4a",
    }

    FONTS = {
        "title": ("Segoe UI", 19, "bold"),
        "section": ("Segoe UI", 11, "bold"),
        "label": ("Segoe UI", 9, "bold"),
        "body": ("Segoe UI", 10),
        "small": ("Segoe UI", 8),
        "mono": ("Cascadia Mono", 10),
    }

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("AI Kali Assistant")
        self.root.geometry("1320x840")
        self.root.minsize(1120, 720)

        ensure_project_dirs(APP_DIR)
        self.config_manager = ConfigManager(APP_DIR / "config.json")
        self.rules_manager = RulesManager(APP_DIR / "rules.txt")
        self.ollama_client = OllamaClient(log_dir=APP_DIR / "logs")
        self.logger = AppLogger(APP_DIR)

        self.history: list[dict[str, str]] = []
        self.last_ssh_output = ""
        self.last_command = ""
        self.pending_command = ""
        self.action_buttons: list[tk.Widget] = []
        self.stop_event = threading.Event()
        self.current_task_can_stop = False
        self.streaming_message_open = False
        self.stop_button: tk.Button | None = None
        self.auto_execute_var = tk.BooleanVar(value=True)
        self.auto_execute_confirmed = True
        self.auto_chain_count = 0
        self.auto_executed_commands: set[str] = set()
        self.auto_command_history: list[dict[str, str]] = []
        self.current_user_objective = ""
        self.operational_repair_count = 0
        self.busy = False
        self.activity_base = ""
        self.activity_note = ""
        self.activity_started_at = 0.0
        self.activity_after_id: str | None = None
        self.config_window: tk.Toplevel | None = None

        self.kali_ip_var = tk.StringVar()
        self.ssh_user_var = tk.StringVar()
        self.ssh_password_var = tk.StringVar()
        self.ollama_model_var = tk.StringVar(value=DEFAULT_CONFIG["ollama_model"])
        self.status_var = tk.StringVar(value="Pronto.")

        self._apply_theme()
        self._build_ui()
        self._load_initial_files()

    def _apply_theme(self) -> None:
        self.root.configure(bg=self.COLORS["bg"])
        self.root.option_add("*Font", self.FONTS["body"])
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Busy.Horizontal.TProgressbar",
            troughcolor=self.COLORS["surface_3"],
            background=self.COLORS["accent"],
            bordercolor=self.COLORS["surface_3"],
            lightcolor=self.COLORS["accent"],
            darkcolor=self.COLORS["accent"],
        )

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        shell = tk.Frame(self.root, bg=self.COLORS["bg"])
        shell.grid(row=0, column=0, sticky="nsew")
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(1, weight=1)

        self._build_header(shell)

        main = tk.Frame(shell, bg=self.COLORS["bg"])
        main.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 12))
        main.columnconfigure(0, weight=1)
        main.rowconfigure(0, weight=1)

        main_split = self._paned(main, tk.HORIZONTAL)
        main_split.grid(row=0, column=0, sticky="nsew")

        chat_area = tk.Frame(main_split, bg=self.COLORS["bg"], width=780)
        kali_area = tk.Frame(main_split, bg=self.COLORS["bg"], width=480)
        main_split.add(chat_area, minsize=520)
        main_split.add(kali_area, minsize=360)
        self.root.after(80, lambda: self._place_initial_main_sash(main_split))

        self._build_chat_panel(chat_area)
        self._build_kali_panel(kali_area)
        self._build_status_bar(shell)

    def _build_header(self, parent: tk.Widget) -> None:
        header = tk.Frame(parent, bg=self.COLORS["bg"])
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 14))
        header.columnconfigure(0, weight=1)
        header.columnconfigure(1, weight=0)
        header.columnconfigure(2, weight=1)

        brand = tk.Frame(header, bg=self.COLORS["bg"])
        brand.grid(row=0, column=0, rowspan=2, sticky="w")
        brand.columnconfigure(1, weight=1)

        badge = tk.Label(
            brand,
            text="AK",
            bg=self.COLORS["accent"],
            fg="#07100a",
            font=("Segoe UI", 13, "bold"),
            width=4,
            height=2,
        )
        badge.grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, 14))

        tk.Label(
            brand,
            text="AI Kali Assistant",
            bg=self.COLORS["bg"],
            fg=self.COLORS["text"],
            font=self.FONTS["title"],
        ).grid(row=0, column=1, sticky="sw")

        tk.Label(
            brand,
            text="Ollama local + Kali SSH",
            bg=self.COLORS["bg"],
            fg=self.COLORS["muted"],
            font=self.FONTS["body"],
        ).grid(row=1, column=1, sticky="nw", pady=(2, 0))

        config_button = self._button(header, "Configurar", self.open_config_window, "primary")
        config_button.grid(row=0, column=1, rowspan=2, sticky="n", padx=24, pady=(3, 0))

        model_chip = tk.Frame(header, bg=self.COLORS["surface_2"], padx=12, pady=8)
        model_chip.grid(row=0, column=2, rowspan=2, sticky="e")
        tk.Label(
            model_chip,
            text="MODELO",
            bg=self.COLORS["surface_2"],
            fg=self.COLORS["muted"],
            font=self.FONTS["small"],
        ).pack(anchor="e")
        tk.Label(
            model_chip,
            textvariable=self.ollama_model_var,
            bg=self.COLORS["surface_2"],
            fg=self.COLORS["cyan"],
            font=self.FONTS["section"],
        ).pack(anchor="e")

    def _build_chat_panel(self, parent: tk.Widget) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        panel, body = self._panel(parent, "Conversa", "Contexto carregado de rules.txt")
        panel.grid(row=0, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        chat_split = self._paned(body, tk.VERTICAL)
        chat_split.grid(row=0, column=0, sticky="nsew")

        chat_frame = tk.Frame(chat_split, bg=self.COLORS["surface"])
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            height=20,
            relief=tk.FLAT,
            bd=0,
        )
        self.chat_display.grid(row=0, column=0, sticky="nsew")
        self._style_text(self.chat_display, "chat")
        self.chat_display.tag_configure("speaker", font=("Segoe UI", 10, "bold"))
        self.chat_display.tag_configure("user", foreground=self.COLORS["cyan"])
        self.chat_display.tag_configure("assistant", foreground=self.COLORS["accent"])
        self.chat_display.tag_configure("system", foreground=self.COLORS["warning"])
        self.chat_display.tag_configure("error", foreground=self.COLORS["danger"])

        prompt_wrap = tk.Frame(chat_split, bg=self.COLORS["surface"])
        prompt_wrap.columnconfigure(0, weight=1)
        prompt_wrap.rowconfigure(1, weight=1)

        tk.Label(
            prompt_wrap,
            text="Mensagem",
            bg=self.COLORS["surface"],
            fg=self.COLORS["muted"],
            font=self.FONTS["label"],
        ).grid(row=0, column=0, sticky="w", pady=(0, 5))

        self.prompt_text = tk.Text(prompt_wrap, height=4, wrap=tk.WORD, relief=tk.FLAT, bd=0)
        self.prompt_text.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        self._style_text(self.prompt_text, "input")
        self.prompt_text.bind("<Control-Return>", self._send_message_event)

        send_button = self._button(prompt_wrap, "Enviar", self.send_message, "primary")
        send_button.grid(row=1, column=1, sticky="nsew", padx=(0, 8))

        self.stop_button = self._button(
            prompt_wrap,
            "Parar",
            self.stop_generation,
            "danger",
            track=False,
        )
        self.stop_button.grid(row=1, column=2, sticky="nsew")
        self.stop_button.configure(state=tk.DISABLED)

        chat_split.add(chat_frame, minsize=160)
        chat_split.add(prompt_wrap, minsize=90)

    def _build_kali_panel(self, parent: tk.Widget) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        panel, body = self._panel(parent, "Execução Kali", "Terminal e decisões automáticas")
        panel.grid(row=0, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        kali_split = self._paned(body, tk.VERTICAL)
        kali_split.grid(row=0, column=0, sticky="nsew")

        decision_frame = tk.Frame(kali_split, bg=self.COLORS["surface"])
        decision_frame.columnconfigure(0, weight=1)
        decision_frame.rowconfigure(1, weight=1)

        command_top = tk.Frame(decision_frame, bg=self.COLORS["surface"])
        command_top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        command_top.columnconfigure(0, weight=1)

        tk.Label(
            command_top,
            text="DECISÃO OPERACIONAL",
            bg=self.COLORS["surface"],
            fg=self.COLORS["purple"],
            font=self.FONTS["small"],
        ).grid(row=0, column=0, sticky="w")

        command_buttons = tk.Frame(command_top, bg=self.COLORS["surface"])
        command_buttons.grid(row=0, column=1, sticky="e")
        self._button(command_buttons, "Limpar Terminal", self.clear_command, "secondary").pack(
            side=tk.LEFT, padx=(0, 8)
        )
        self._button(command_buttons, "Relatório", self.save_report, "secondary").pack(
            side=tk.LEFT
        )

        self.command_text = tk.Text(decision_frame, height=3, wrap=tk.WORD, relief=tk.FLAT, bd=0)
        self.command_text.grid(row=1, column=0, sticky="nsew", pady=(0, 8))
        self._style_text(self.command_text, "command")
        self._set_command("Aguardando decisão operacional.")

        auto_label = tk.Label(
            decision_frame,
            text="Automação ativa: ações leves são executadas pelo app; ações intensas ficam bloqueadas.",
            bg=self.COLORS["surface"],
            fg=self.COLORS["muted"],
            font=self.FONTS["small"],
            anchor="w",
            justify=tk.LEFT,
        )
        auto_label.grid(row=2, column=0, sticky="ew", pady=(0, 8))

        terminal_frame = tk.Frame(kali_split, bg=self.COLORS["surface"])
        terminal_frame.columnconfigure(0, weight=1)
        terminal_frame.rowconfigure(1, weight=1)

        self._section_label(terminal_frame, "Terminal Kali", grid_row=0)
        self.ssh_output = scrolledtext.ScrolledText(
            terminal_frame,
            wrap=tk.WORD,
            height=10,
            relief=tk.FLAT,
            bd=0,
        )
        self.ssh_output.grid(row=1, column=0, sticky="nsew")
        self._style_text(self.ssh_output, "terminal")

        kali_split.add(decision_frame, minsize=120)
        kali_split.add(terminal_frame, minsize=140)

    def _build_status_bar(self, parent: tk.Widget) -> None:
        bar = tk.Frame(parent, bg=self.COLORS["surface_2"], padx=14, pady=9)
        bar.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 14))
        bar.columnconfigure(1, weight=1)

        tk.Label(
            bar,
            text="STATUS",
            bg=self.COLORS["surface_2"],
            fg=self.COLORS["muted"],
            font=self.FONTS["small"],
        ).grid(row=0, column=0, sticky="w", padx=(0, 10))
        tk.Label(
            bar,
            textvariable=self.status_var,
            bg=self.COLORS["surface_2"],
            fg=self.COLORS["text"],
            font=self.FONTS["body"],
            anchor="w",
        ).grid(row=0, column=1, sticky="ew")

        self.progress_bar = ttk.Progressbar(
            bar,
            mode="indeterminate",
            style="Busy.Horizontal.TProgressbar",
            length=210,
        )
        self.progress_bar.grid(row=0, column=2, sticky="e", padx=(12, 0))
        self.progress_bar.grid_remove()

    def _panel(self, parent: tk.Widget, title: str, subtitle: str) -> tuple[tk.Frame, tk.Frame]:
        outer = tk.Frame(parent, bg=self.COLORS["border"], padx=1, pady=1)
        inner = tk.Frame(outer, bg=self.COLORS["surface"], padx=16, pady=14)
        inner.pack(fill=tk.BOTH, expand=True)
        inner.columnconfigure(0, weight=1)
        inner.rowconfigure(1, weight=1)

        header = tk.Frame(inner, bg=self.COLORS["surface"])
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        header.columnconfigure(0, weight=1)

        tk.Label(
            header,
            text=title,
            bg=self.COLORS["surface"],
            fg=self.COLORS["text"],
            font=self.FONTS["section"],
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            header,
            text=subtitle,
            bg=self.COLORS["surface"],
            fg=self.COLORS["muted"],
            font=self.FONTS["small"],
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        body = tk.Frame(inner, bg=self.COLORS["surface"])
        body.grid(row=1, column=0, sticky="nsew")
        return outer, body

    def _paned(self, parent: tk.Widget, orient: str) -> tk.PanedWindow:
        return tk.PanedWindow(
            parent,
            orient=orient,
            bg=self.COLORS["border"],
            bd=0,
            relief=tk.FLAT,
            sashwidth=8,
            sashrelief=tk.FLAT,
            showhandle=True,
            handlesize=10,
            handlepad=8,
            opaqueresize=True,
        )

    def _place_initial_main_sash(self, paned: tk.PanedWindow) -> None:
        try:
            width = paned.winfo_width()
            if width > 900:
                paned.sash_place(0, int(width * 0.62), 0)
        except tk.TclError:
            return

    def _section_label(self, parent: tk.Widget, text: str, grid_row: int | None = None) -> None:
        label = tk.Label(
            parent,
            text=text.upper(),
            bg=self.COLORS["surface"],
            fg=self.COLORS["purple"],
            font=self.FONTS["small"],
        )
        if grid_row is None:
            label.pack(anchor="w", pady=(0, 8))
        else:
            label.grid(row=grid_row, column=0, sticky="w", pady=(0, 8))

    def _field(
        self, parent: tk.Widget, label_text: str, variable: tk.StringVar, show: str = ""
    ) -> tk.Entry:
        tk.Label(
            parent,
            text=label_text,
            bg=self.COLORS["surface"],
            fg=self.COLORS["muted"],
            font=self.FONTS["label"],
        ).pack(anchor="w", pady=(0, 4))
        entry = tk.Entry(
            parent,
            textvariable=variable,
            show=show,
            bg=self.COLORS["input"],
            fg=self.COLORS["text"],
            insertbackground=self.COLORS["accent"],
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.COLORS["border"],
            highlightcolor=self.COLORS["accent"],
            font=self.FONTS["body"],
        )
        entry.pack(fill=tk.X, ipady=8, pady=(0, 12))
        return entry

    def _divider(self, parent: tk.Widget) -> None:
        tk.Frame(parent, bg=self.COLORS["border"], height=1).pack(
            fill=tk.X, pady=(2, 16)
        )

    def _button(
        self,
        parent: tk.Widget,
        text: str,
        command: Callable[[], None],
        variant: str = "secondary",
        track: bool = True,
    ) -> tk.Button:
        variants = {
            "primary": (self.COLORS["accent"], "#061109", self.COLORS["accent_hover"]),
            "secondary": (self.COLORS["button"], self.COLORS["text"], self.COLORS["button_hover"]),
            "warning": (self.COLORS["warning"], "#171006", "#ffd06a"),
            "danger": (self.COLORS["danger"], "#1a0508", self.COLORS["danger_hover"]),
        }
        bg, fg, hover = variants.get(variant, variants["secondary"])
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=hover,
            activeforeground=fg,
            disabledforeground=fg,
            relief=tk.FLAT,
            bd=0,
            padx=12,
            pady=10,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            takefocus=True,
        )

        def on_enter(_event: tk.Event) -> None:
            if str(button.cget("state")) != tk.DISABLED:
                button.configure(bg=hover)

        def on_leave(_event: tk.Event) -> None:
            if str(button.cget("state")) != tk.DISABLED:
                button.configure(bg=bg)

        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)
        button.normal_bg = bg
        button.normal_fg = fg
        if track:
            self.action_buttons.append(button)
        return button

    def _style_text(self, widget: tk.Text, variant: str) -> None:
        backgrounds = {
            "chat": self.COLORS["input"],
            "input": "#10161b",
            "command": "#0b1115",
            "terminal": self.COLORS["terminal"],
        }
        widget.configure(
            bg=backgrounds.get(variant, self.COLORS["input"]),
            fg=self.COLORS["text"],
            insertbackground=self.COLORS["accent"],
            selectbackground=self.COLORS["surface_3"],
            selectforeground=self.COLORS["text"],
            padx=12,
            pady=10,
            font=self.FONTS["mono"] if variant in {"command", "terminal"} else self.FONTS["body"],
        )

    def _load_initial_files(self) -> None:
        try:
            config = self.config_manager.load()
        except RuntimeError as exc:
            config = DEFAULT_CONFIG.copy()
            self.append_chat("Sistema", str(exc), "error")
            self.logger.error(str(exc))

        self.kali_ip_var.set(config["kali_ip"])
        self.ssh_user_var.set(config["ssh_user"])
        self.ssh_password_var.set(config["ssh_password"])
        self.ollama_model_var.set(config["ollama_model"] or DEFAULT_CONFIG["ollama_model"])

        try:
            self.rules_manager.load_rules()
        except RuntimeError as exc:
            self.append_chat("Sistema", str(exc), "error")
            self.logger.error(str(exc))

    def save_config(self) -> None:
        try:
            self.config_manager.save(self._read_config_from_ui())
        except RuntimeError as exc:
            messagebox.showerror("Erro ao salvar", str(exc))
            self.logger.error(str(exc))
            return

        self.status_var.set("Configurações salvas.")
        self.logger.info("Configurações salvas.")

    def open_config_window(self) -> None:
        if self.config_window is not None and self.config_window.winfo_exists():
            self.config_window.lift()
            self.config_window.focus_force()
            return

        window = tk.Toplevel(self.root)
        self.config_window = window
        window.title("Configurar AI Kali Assistant")
        window.geometry("760x560")
        window.minsize(680, 500)
        window.configure(bg=self.COLORS["bg"])
        window.transient(self.root)
        window.grab_set()
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)

        def on_close() -> None:
            self.config_window = None
            window.destroy()

        window.protocol("WM_DELETE_WINDOW", on_close)

        panel = tk.Frame(window, bg=self.COLORS["border"], padx=1, pady=1)
        panel.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)

        inner = tk.Frame(panel, bg=self.COLORS["surface"], padx=18, pady=16)
        inner.grid(row=0, column=0, sticky="nsew")
        inner.columnconfigure(0, weight=1)
        inner.rowconfigure(1, weight=1)

        header = tk.Frame(inner, bg=self.COLORS["surface"])
        header.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        header.columnconfigure(0, weight=1)

        tk.Label(
            header,
            text="Configurações",
            bg=self.COLORS["surface"],
            fg=self.COLORS["text"],
            font=self.FONTS["title"],
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            header,
            text="Ollama, SSH Kali e regras do sistema",
            bg=self.COLORS["surface"],
            fg=self.COLORS["muted"],
            font=self.FONTS["body"],
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        content = tk.Frame(inner, bg=self.COLORS["surface"])
        content.grid(row=1, column=0, sticky="nsew")
        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=1)

        ollama_col = tk.Frame(content, bg=self.COLORS["surface"])
        ollama_col.grid(row=0, column=0, sticky="new", padx=(0, 18))
        self._section_label(ollama_col, "Ollama")
        self._field(ollama_col, "Modelo", self.ollama_model_var)
        self._button(
            ollama_col,
            "Testar Ollama",
            self.test_ollama,
            "primary",
            track=False,
        ).pack(fill=tk.X, pady=(6, 0))

        kali_col = tk.Frame(content, bg=self.COLORS["surface"])
        kali_col.grid(row=0, column=1, sticky="new")
        self._section_label(kali_col, "Kali SSH")
        self._field(kali_col, "IP do Kali", self.kali_ip_var)
        self._field(kali_col, "Usuário", self.ssh_user_var)
        self._field(kali_col, "Senha", self.ssh_password_var, show="*")
        self._button(
            kali_col,
            "Testar SSH Kali",
            self.test_ssh,
            "secondary",
            track=False,
        ).pack(fill=tk.X, pady=(6, 0))

        rules_row = tk.Frame(content, bg=self.COLORS["surface"])
        rules_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(20, 0))
        rules_row.columnconfigure(0, weight=1)
        self._section_label(rules_row, "Regras")

        def open_rules_from_config() -> None:
            try:
                window.grab_release()
            except tk.TclError:
                pass
            self.open_rules_editor()

        self._button(
            rules_row,
            "Definir Regras",
            open_rules_from_config,
            "warning",
            track=False,
        ).pack(fill=tk.X, pady=(6, 0))

        footer = tk.Frame(inner, bg=self.COLORS["surface"])
        footer.grid(row=2, column=0, sticky="e", pady=(18, 0))

        self._button(footer, "Fechar", on_close, "secondary", track=False).pack(
            side=tk.RIGHT, padx=(8, 0)
        )
        self._button(footer, "Salvar Configurações", self.save_config, "primary", track=False).pack(
            side=tk.RIGHT
        )

    def open_rules_editor(self) -> None:
        try:
            current_rules = self.rules_manager.load_rules()
        except RuntimeError as exc:
            messagebox.showerror("Erro ao abrir regras", str(exc))
            self.logger.error(str(exc))
            return

        window = tk.Toplevel(self.root)
        window.title("Definir Regras")
        window.geometry("820x560")
        window.minsize(680, 420)
        window.configure(bg=self.COLORS["bg"])
        window.transient(self.root)
        window.grab_set()
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)

        panel = tk.Frame(window, bg=self.COLORS["border"], padx=1, pady=1)
        panel.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)

        inner = tk.Frame(panel, bg=self.COLORS["surface"], padx=16, pady=14)
        inner.grid(row=0, column=0, sticky="nsew")
        inner.columnconfigure(0, weight=1)
        inner.rowconfigure(1, weight=1)

        tk.Label(
            inner,
            text="Regras do Sistema",
            bg=self.COLORS["surface"],
            fg=self.COLORS["text"],
            font=self.FONTS["section"],
        ).grid(row=0, column=0, sticky="w", pady=(0, 12))

        editor = scrolledtext.ScrolledText(inner, wrap=tk.WORD, relief=tk.FLAT, bd=0)
        editor.grid(row=1, column=0, sticky="nsew")
        self._style_text(editor, "input")
        editor.insert("1.0", current_rules)

        footer = tk.Frame(inner, bg=self.COLORS["surface"])
        footer.grid(row=2, column=0, sticky="e", pady=(12, 0))

        def save_rules() -> None:
            rules = editor.get("1.0", tk.END)
            try:
                self.rules_manager.save_rules(rules)
            except (RuntimeError, ValueError) as exc:
                messagebox.showerror("Erro ao salvar regras", str(exc), parent=window)
                self.logger.error(str(exc))
                return

            self.status_var.set("Regras salvas em rules.txt.")
            self.logger.info("Regras atualizadas.")
            window.destroy()

        self._button(footer, "Cancelar", window.destroy, "secondary", track=False).pack(
            side=tk.RIGHT, padx=(8, 0)
        )
        self._button(footer, "Salvar Regras", save_rules, "primary", track=False).pack(
            side=tk.RIGHT
        )

    def test_ollama(self) -> None:
        config = self._read_config_from_ui()
        self._save_config_silently(config)

        try:
            rules = self.rules_manager.load_rules()
        except RuntimeError as exc:
            messagebox.showerror("Erro em rules.txt", str(exc))
            return

        def worker() -> str:
            def on_status(note: str) -> None:
                self.root.after(0, lambda note=note: self.set_activity_note(note))

            model_check = self.ollama_client.test(config["ollama_model"], rules)
            warm_check = self.ollama_client.warm_up(
                config["ollama_model"],
                rules,
                on_status=on_status,
            )
            return f"{model_check}\nAquecimento: {warm_check}"

        def on_success(result: object) -> None:
            self.append_chat("Sistema", f"Teste Ollama OK.\nResposta: {result}", "system")
            self.logger.info("Teste Ollama concluído com sucesso.")

        self._run_worker("Testando e aquecendo Ollama...", worker, on_success)

    def test_ssh(self) -> None:
        config = self._read_config_from_ui()
        if not self._validate_ssh_config(config):
            return
        self._save_config_silently(config)

        def worker() -> SSHCommandResult:
            client = KaliClient(
                hostname=config["kali_ip"],
                username=config["ssh_user"],
                password=config["ssh_password"],
            )
            return client.test_connection()

        def on_success(result: object) -> None:
            if not isinstance(result, SSHCommandResult):
                raise TypeError("Resultado SSH inesperado.")
            self._set_ssh_output(result.as_text())
            self.append_chat("Sistema", "Teste SSH Kali OK.", "system")
            self.logger.info("Teste SSH Kali concluído com sucesso.")

        self._run_worker("Testando SSH no Kali...", worker, on_success)

    def send_message(self) -> None:
        user_message = self.prompt_text.get("1.0", tk.END).strip()
        if not user_message:
            return

        self.stop_event.clear()
        config = self._read_config_from_ui()
        self._save_config_silently(config)

        try:
            rules = self.rules_manager.load_rules()
        except RuntimeError as exc:
            messagebox.showerror("Erro em rules.txt", str(exc))
            self.logger.error(str(exc))
            return

        self.auto_chain_count = 0
        self.auto_executed_commands.clear()
        self.auto_command_history.clear()
        self.current_user_objective = user_message
        self.operational_repair_count = 0
        self._set_ssh_output("")
        self._set_command("Preparando decisão operacional automática...")
        self.prompt_text.delete("1.0", tk.END)
        self.append_chat("Você", user_message, "user")

        initial_command = self._build_initial_web_recon_command(user_message)
        if initial_command:
            self.history.append({"role": "user", "content": user_message})
            self.history = self.history[-20:]
            self.append_chat(
                "IA",
                "Iniciando avaliação web estruturada no Kali. Vou tomar decisões com base nas evidências coletadas.",
                "assistant",
            )
            self._handle_suggested_command(initial_command)
            return

        history_snapshot = self.history.copy()
        model_message = self._build_operational_user_message(user_message)
        self.begin_stream_message("IA")
        self.logger.info("Mensagem enviada ao Ollama.")

        def worker() -> str:
            def on_chunk(chunk: str) -> None:
                self.root.after(
                    0,
                    lambda chunk=chunk: self.append_stream_chunk(chunk, "assistant"),
                )

            def on_status(note: str) -> None:
                self.root.after(0, lambda note=note: self.set_activity_note(note))

            return self.ollama_client.stream_chat(
                model=config["ollama_model"],
                rules=rules,
                history=history_snapshot,
                user_message=model_message,
                on_chunk=on_chunk,
                on_status=on_status,
                stop_event=self.stop_event,
            )

        def on_success(answer: object) -> None:
            answer_text = str(answer)
            if self.stop_event.is_set():
                self.append_stream_chunk("\n\n[Geração interrompida pelo usuário.]", "system")
            self.end_stream_message()
            if answer_text:
                self.history.append({"role": "user", "content": user_message})
                self.history.append({"role": "assistant", "content": answer_text})
                self.history = self.history[-20:]
            suggested_command = self.extract_command_suggestion(answer_text)
            if suggested_command:
                if self._contains_pre_execution_claims(answer_text):
                    self.append_chat(
                        "Sistema",
                        "Achados declarados antes da execução foram ignorados. O terminal Kali será a fonte de evidência.",
                        "system",
                    )
                self._handle_suggested_command(suggested_command)
            elif self._needs_operational_repair(answer_text):
                self.append_chat(
                    "Sistema",
                    "A IA respondeu com procedimento/texto em vez de uma decisão executável. Corrigindo automaticamente.",
                    "system",
                )
                self.root.after(
                    80,
                    lambda: self._run_operational_repair(
                        original_request=user_message,
                        rejected_answer=answer_text,
                        config=config,
                        rules=rules,
                    ),
                )
            self.logger.info("Resposta recebida do Ollama.")

        self._run_worker(
            f"Ollama gerando resposta com {config['ollama_model']}; o primeiro token pode demorar...",
            worker,
            on_success,
            cancellable=True,
        )

    def execute_on_kali(self, auto_confirm: bool = False) -> None:
        command = self.pending_command.strip() or self.command_text.get("1.0", tk.END).strip()
        if not command:
            if not auto_confirm:
                messagebox.showwarning("Ação vazia", "Não há ação técnica para executar.")
            return

        blocked_reason = self._blocked_command_reason(command)
        if blocked_reason:
            if not auto_confirm:
                messagebox.showerror(
                    "Ação bloqueada",
                    f"Esta ação foi bloqueada por segurança: {blocked_reason}.",
                )
            self.logger.warning(f"Ação bloqueada: {blocked_reason} | {command}")
            return

        config = self._read_config_from_ui()
        if not self._validate_ssh_config(config):
            return
        self._save_config_silently(config)

        intensive_reasons = self._intensive_command_reasons(command)
        if auto_confirm and intensive_reasons:
            self.status_var.set("Ação intensa bloqueada na automação.")
            return

        if not auto_confirm and not messagebox.askyesno(
            "Confirmar execução",
            "Confirme que o alvo, o escopo e a intensidade são autorizados.\n\n"
            f"Esta ação será executada no Kali configurado ({config['kali_ip']}):\n\n"
            f"{command}",
        ):
            return

        if intensive_reasons and not messagebox.askyesno(
            "Confirmação extra",
            "Esta ação pode ser intensa pelos seguintes motivos:\n\n"
            + "\n".join(f"- {reason}" for reason in intensive_reasons)
            + "\n\nExecutar mesmo assim?",
        ):
            return

        self.stop_event.clear()
        display_command = self._display_command(command)
        self.append_ssh_output(
            "\n"
            + "=" * 72
            + f"\n[enviando ao Kali]\n{self._format_terminal_action(command)}\n\n[conectando ao Kali...]\n"
        )

        def worker() -> SSHCommandResult:
            client = KaliClient(
                hostname=config["kali_ip"],
                username=config["ssh_user"],
                password=config["ssh_password"],
            )

            def on_stdout(chunk: str) -> None:
                self.root.after(0, lambda chunk=chunk: self.append_ssh_output(chunk))

            def on_stderr(chunk: str) -> None:
                self.root.after(0, lambda chunk=chunk: self.append_ssh_output(chunk))

            def on_status(note: str) -> None:
                self.root.after(0, lambda note=note: self.set_activity_note(note))

            return client.execute_stream(
                command,
                timeout=COMMAND_TIMEOUT_SECONDS,
                on_stdout=on_stdout,
                on_stderr=on_stderr,
                on_status=on_status,
                stop_event=self.stop_event,
            )

        def on_success(result: object) -> None:
            if not isinstance(result, SSHCommandResult):
                raise TypeError("Resultado SSH inesperado.")
            self.last_command = command
            self.last_ssh_output = self._format_ssh_result_for_model(result)
            self._record_command_result(result)
            self.append_ssh_output(
                f"\n\n[finalizado: exit_status={result.exit_status}, timeout={result.timed_out}]\n"
            )
            self.append_chat(
                "Sistema",
                "Ação executada no Kali. Vou enviar a evidência para a IA decidir a continuidade da análise.",
                "system",
            )
            self.logger.info(f"Ação executada no Kali com status {result.exit_status}.")
            self.root.after(150, self.analyze_last_ssh_output)

        self._run_worker("Executando ação no Kali...", worker, on_success, cancellable=True)

    def analyze_last_ssh_output(self) -> None:
        if not self.last_command or not self.last_ssh_output.strip():
            messagebox.showwarning(
                "Sem saída SSH",
                "Execute uma ação no Kali antes de pedir análise.",
            )
            return
        self.analyze_ssh_result(self.last_command, self.last_ssh_output)

    def analyze_ssh_result(
        self,
        command: str,
        ssh_output: str,
        extra_instruction: str = "",
    ) -> None:
        config = self._read_config_from_ui()
        self._save_config_silently(config)

        try:
            rules = self.rules_manager.load_rules()
        except RuntimeError as exc:
            messagebox.showerror("Erro em rules.txt", str(exc))
            self.logger.error(str(exc))
            return

        output_for_model = self._limit_text(ssh_output, ANALYSIS_OUTPUT_LIMIT)
        history_snapshot = self.history.copy()
        history_context = self._build_command_history_context()
        extra_block = f"\nInstrucao adicional:\n{extra_instruction}\n" if extra_instruction else ""
        analysis_prompt = (
            "Resultado executado pelo app no Kali.\n"
            "Analise a saida como operador tecnico, separando evidencia real de hipotese. "
            "Tome uma decisao operacional objetiva, curta e focada no pedido original.\n"
            "Nao escreva planejamento aberto, lista de possibilidades ou etapas futuras. "
            "Nao use markdown, blocos de codigo, secoes 'Procedimento', 'Resultados' inventados ou 'Proximo Passo'. "
            "Respeite exclusoes do usuario; se ele pediu para esquecer XSS, nao volte para XSS. "
            "Decida: continuar com uma acao tecnica permitida ou concluir a analise com os achados.\n"
            "Nao invente vulnerabilidade quando a saida estiver vazia ou inconclusiva.\n"
            "Se stdout vier vazio, trate como 'sem evidencia neste teste', nao como achado.\n"
            "Nao repita curl|grep de palavras isoladas como cookie/token/auth/password/login/form/input. "
            "Se esse padrao ja falhou, mude de tecnica para uma coleta mais ampla: headers, HTML bruto, JS assets, endpoints, sourcemaps, CSP/CORS, TLS ou fluxo de autenticacao nao invasivo.\n"
            "Priorize achados fortes e verificaveis: headers de seguranca ausentes, CORS validado com evidencia, cookies sem flags, arquivos sensiveis, sourcemaps, endpoints expostos, erros verbosos, segredos em JS, problemas TLS.\n"
            "Se nao houver evidencia forte apos cobertura basica, conclua isso claramente em vez de continuar testando fraco.\n"
            "Se uma nova acao tecnica for necessaria para cumprir o objetivo, decida a acao e inclua uma unica linha no formato "
            "ACAO_KALI: <linha_shell>. Trate a linha como uma decisao tecnica objetiva, nao como rascunho.\n\n"
            f"{extra_block}"
            f"Historico resumido desta automacao:\n{history_context}\n\n"
            f"Acao executada:\n{self._display_command(command)}\n\n"
            f"Saida SSH:\n{output_for_model}"
        )

        self.stop_event.clear()
        self.append_chat(
            "Sistema",
            f"Analisando automaticamente a saída do Kali.\nAcao: {self._display_command(command)}",
            "system",
        )
        self.begin_stream_message("IA")

        def worker() -> str:
            def on_chunk(chunk: str) -> None:
                self.root.after(
                    0,
                    lambda chunk=chunk: self.append_stream_chunk(chunk, "assistant"),
                )

            def on_status(note: str) -> None:
                self.root.after(0, lambda note=note: self.set_activity_note(note))

            return self.ollama_client.stream_chat(
                model=config["ollama_model"],
                rules=rules,
                history=history_snapshot,
                user_message=analysis_prompt,
                on_chunk=on_chunk,
                on_status=on_status,
                stop_event=self.stop_event,
            )

        def on_success(answer: object) -> None:
            answer_text = str(answer)
            if self.stop_event.is_set():
                self.append_stream_chunk("\n\n[Geração interrompida pelo usuário.]", "system")
            self.end_stream_message()
            if answer_text:
                self.history.append(
                    {
                        "role": "user",
                        "content": self._limit_text(analysis_prompt, 5000),
                    }
                )
                self.history.append({"role": "assistant", "content": answer_text})
                self.history = self.history[-20:]
            suggested_command = self.extract_command_suggestion(answer_text)
            if suggested_command:
                if not self.auto_command_history and self._contains_pre_execution_claims(answer_text):
                    self.append_chat(
                        "Sistema",
                        "Achados declarados antes da execução foram ignorados. O terminal Kali será a fonte de evidência.",
                        "system",
                    )
                self._handle_suggested_command(suggested_command)
            elif self._needs_operational_repair(answer_text):
                self.append_chat(
                    "Sistema",
                    "A IA saiu do modo operacional. Corrigindo para uma ação objetiva ou conclusão baseada em evidência.",
                    "system",
                )
                self.root.after(
                    80,
                    lambda: self._run_operational_repair(
                        original_request=self.current_user_objective,
                        rejected_answer=answer_text,
                        config=config,
                        rules=rules,
                    ),
                )
            else:
                self.status_var.set("Análise concluída.")
            self.logger.info("Saída SSH analisada pela IA.")

        self._run_worker(
            "IA analisando saída do Kali...",
            worker,
            on_success,
            cancellable=True,
        )

    def save_report(self) -> None:
        reports_dir = APP_DIR / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_path = reports_dir / f"report-{timestamp}.md"
        chat_content = self.chat_display.get("1.0", tk.END).strip()
        ssh_content = self.ssh_output.get("1.0", tk.END).strip()
        command_content = self.command_text.get("1.0", tk.END).strip()
        config = self._read_config_from_ui()

        report = "\n".join(
            [
                "# Relatório AI Kali Assistant",
                "",
                f"- Data: {datetime.now():%Y-%m-%d %H:%M:%S}",
                f"- Modelo Ollama: {config['ollama_model']}",
                f"- Kali IP: {config['kali_ip'] or '(não configurado)'}",
                "",
                "## Conversa",
                "",
                "```text",
                chat_content or "(vazio)",
                "```",
                "",
                "## Ação executada",
                "",
                "```bash",
                command_content or "(vazio)",
                "```",
                "",
                "## Saída SSH",
                "",
                "```text",
                ssh_content or "(vazio)",
                "```",
                "",
            ]
        )

        try:
            report_path.write_text(report, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Erro ao salvar relatório", str(exc))
            self.logger.error(f"Erro ao salvar relatório: {exc}")
            return

        self.status_var.set(f"Relatório salvo em {report_path.name}.")
        self.logger.info(f"Relatório salvo: {report_path}")
        messagebox.showinfo("Relatório salvo", f"Arquivo criado:\n{report_path}")

    def clear_command(self) -> None:
        self.pending_command = ""
        self._set_command("Aguardando decisao operacional.")
        self._set_ssh_output("")
        self.status_var.set("Decisao e terminal limpos.")

    def stop_generation(self) -> None:
        if self.current_task_can_stop:
            self.stop_event.set()
            self.set_activity_note("parando tarefa")

    def _send_message_event(self, _event: tk.Event) -> str:
        self.send_message()
        return "break"

    def _run_worker(
        self,
        status: str,
        worker: Callable[[], object],
        on_success: Callable[[object], None],
        cancellable: bool = False,
    ) -> None:
        self.current_task_can_stop = cancellable
        self.start_activity(status)
        self._set_busy(True)

        def runner() -> None:
            try:
                result = worker()
            except Exception as exc:  # noqa: BLE001 - erro exibido na GUI e logado
                self.logger.exception(str(exc))
                self.root.after(0, lambda exc=exc: self._finish_worker_error(exc))
            else:
                self.root.after(
                    0,
                    lambda result=result, on_success=on_success: self._finish_worker_success(
                        result,
                        on_success,
                    ),
                )

        threading.Thread(target=runner, daemon=True).start()

    def _finish_worker_success(
        self,
        result: object,
        on_success: Callable[[object], None],
    ) -> None:
        try:
            on_success(result)
        except Exception as exc:  # noqa: BLE001 - erro exibido na GUI e logado
            self.logger.exception(str(exc))
            self.end_stream_message()
            self._set_busy(False)
            self.current_task_can_stop = False
            self._handle_worker_error(exc)
            return

        self._set_busy(False)
        self.current_task_can_stop = False

    def _finish_worker_error(self, exc: Exception) -> None:
        self.end_stream_message()
        self._set_busy(False)
        self.current_task_can_stop = False
        self._handle_worker_error(exc)

    def _handle_worker_error(self, exc: Exception) -> None:
        message = str(exc)
        status_message = message if len(message) <= 120 else message[:117] + "..."
        self.status_var.set(f"Erro: {status_message}")
        self.append_chat("Erro", message, "error")

    def _set_busy(self, busy: bool) -> None:
        was_activity_status = bool(
            self.activity_base and self.status_var.get().startswith(self.activity_base)
        )
        self.busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        for button in self.action_buttons:
            normal_bg = getattr(button, "normal_bg", button.cget("bg"))
            normal_fg = getattr(button, "normal_fg", button.cget("fg"))
            button.configure(
                state=state,
                bg=normal_bg,
                fg=normal_fg,
                disabledforeground=normal_fg,
            )
        if hasattr(self, "progress_bar"):
            if busy:
                self.progress_bar.grid()
                self.progress_bar.start(12)
            else:
                self.progress_bar.stop()
                self.progress_bar.grid_remove()
        if self.stop_button:
            stop_state = tk.NORMAL if busy and self.current_task_can_stop else tk.DISABLED
            self.stop_button.configure(state=stop_state)
        if not busy:
            self.stop_activity()
        if not busy and (self.status_var.get().endswith("...") or was_activity_status):
            self.status_var.set("Pronto.")

    def start_activity(self, base: str) -> None:
        self.activity_base = base.rstrip(".")
        self.activity_note = "iniciando"
        self.activity_started_at = time.monotonic()
        self.cancel_activity_tick()
        self.render_activity_status()
        self.activity_after_id = self.root.after(1000, self.tick_activity)

    def set_activity_note(self, note: str) -> None:
        self.activity_note = note
        if self.busy:
            self.render_activity_status()

    def tick_activity(self) -> None:
        if not self.busy:
            self.activity_after_id = None
            return
        self.render_activity_status()
        self.activity_after_id = self.root.after(1000, self.tick_activity)

    def render_activity_status(self) -> None:
        elapsed = max(0, int(time.monotonic() - self.activity_started_at))
        note = f" - {self.activity_note}" if self.activity_note else ""
        self.status_var.set(f"{self.activity_base} ({elapsed}s){note}")

    def stop_activity(self) -> None:
        self.cancel_activity_tick()
        self.activity_base = ""
        self.activity_note = ""
        self.activity_started_at = 0.0

    def cancel_activity_tick(self) -> None:
        if self.activity_after_id:
            try:
                self.root.after_cancel(self.activity_after_id)
            except tk.TclError:
                pass
            self.activity_after_id = None

    def _build_operational_user_message(self, user_message: str) -> str:
        return (
            "MODO OPERACIONAL AUTOMATICO DO APP:\n"
            "O usuario quer que o app faca a coleta no Kali e mostre os retornos.\n"
            "Nao entregue checklist, nao liste 5 ou 10 acoes tecnicas, nao mande o usuario executar nada.\n"
            "Nao use markdown, blocos ```bash```, secoes 'Procedimento', 'Resultados' ou 'Proximo Passo'.\n"
            "Se esta chamada ainda nao trouxe Saida SSH, voce NAO tem resultado real; nao finja teste executado.\n"
            "Respeite exclusoes do usuario. Se ele mandar esquecer XSS, nao sugira XSS.\n"
            "Tome uma decisao operacional concisa, focada no objetivo do usuario e baseada em evidencia.\n"
            "Para alvo web, comece por coleta ampla e evidencial; para IDOR/API, priorize rotas, endpoints, JS, forms, chamadas HTTP e parametros observaveis.\n"
            "Evite grep isolado de palavras-chave no HTML.\n"
            "Busque evidencia forte antes de chamar algo de vulnerabilidade. Sem evidencia forte, conclua como inconclusivo ou baixo sinal.\n"
            "Se precisa coletar evidencia, responda com no maximo 2 linhas e uma delas deve ser: ACAO_KALI: <linha_shell>\n"
            "Evite brute force, wordlists, exploracao destrutiva, persistencia, malware, evasao ou exfiltracao.\n"
            "Depois da saida SSH, o app chamara voce de novo para analisar a evidencia e decidir a continuidade.\n\n"
            f"Pedido do usuario:\n{user_message}"
        )

    def _run_operational_repair(
        self,
        original_request: str,
        rejected_answer: str,
        config: dict[str, str],
        rules: str,
    ) -> None:
        if self.operational_repair_count >= 1:
            self.status_var.set("Correção operacional interrompida para evitar repetição.")
            self.append_chat(
                "Sistema",
                "A IA repetiu uma resposta fora do formato operacional. Interrompi a correção automática para evitar loop.",
                "error",
            )
            return

        self.operational_repair_count += 1
        repair_prompt = self._build_repair_prompt(original_request, rejected_answer)
        history_snapshot: list[dict[str, str]] = []
        self.stop_event.clear()
        self.begin_stream_message("IA")

        def worker() -> str:
            def on_chunk(chunk: str) -> None:
                self.root.after(
                    0,
                    lambda chunk=chunk: self.append_stream_chunk(chunk, "assistant"),
                )

            def on_status(note: str) -> None:
                self.root.after(0, lambda note=note: self.set_activity_note(note))

            return self.ollama_client.stream_chat(
                model=config["ollama_model"],
                rules=rules,
                history=history_snapshot,
                user_message=repair_prompt,
                on_chunk=on_chunk,
                on_status=on_status,
                stop_event=self.stop_event,
            )

        def on_success(answer: object) -> None:
            answer_text = str(answer)
            if self.stop_event.is_set():
                self.append_stream_chunk("\n\n[Geração interrompida pelo usuário.]", "system")
            self.end_stream_message()
            if answer_text:
                self.history.append(
                    {
                        "role": "user",
                        "content": self._limit_text(repair_prompt, 2500),
                    }
                )
                self.history.append({"role": "assistant", "content": answer_text})
                self.history = self.history[-20:]
            suggested_command = self.extract_command_suggestion(answer_text)
            if suggested_command:
                self._handle_suggested_command(suggested_command)
            else:
                self.status_var.set("IA não retornou ação executável após correção.")

        self._run_worker(
            "Corrigindo resposta para decisão operacional...",
            worker,
            on_success,
            cancellable=True,
        )

    def _build_repair_prompt(self, original_request: str, rejected_answer: str) -> str:
        return (
            "CORRECAO OPERACIONAL OBRIGATORIA:\n"
            "Sua resposta anterior foi rejeitada pelo app porque trouxe procedimento, markdown, comando solto, resultado sem evidencia ou 'proximo passo'.\n"
            "Nao repita essa estrutura. Nao use markdown. Nao use bloco de codigo. Nao diga que algo foi testado sem Saida SSH.\n"
            "Foque estritamente no pedido original do usuario e respeite exclusoes explicitas.\n"
            "Se precisa coletar evidencia, responda apenas com uma frase curta e uma linha ACAO_KALI: <linha_shell>.\n"
            "Se ja houver evidencia suficiente no historico, conclua em ate 4 linhas citando somente fatos observados.\n"
            "Para IDOR/API, prefira coleta de endpoints/JS/forms/requisicoes e parametros observaveis; nao sugira XSS se o usuario pediu para esquecer XSS.\n\n"
            f"Pedido original:\n{original_request or '(usar objetivo do historico)'}\n\n"
            "Resposta anterior rejeitada:\n"
            f"{self._limit_text(rejected_answer, 3500)}"
        )

    def _build_initial_web_recon_command(self, user_message: str) -> str:
        url = self._extract_first_url(user_message)
        if not url:
            return ""
        scanner = r"""
        import re
        import ssl
        import urllib.error
        import urllib.parse
        import urllib.request

        TARGET_URL = __TARGET_URL__
        TIMEOUT = 18
        MAX_BODY = 350000
        MAX_ASSET = 250000
        CTX = ssl._create_unverified_context()
        BASE_HEADERS = {
            "User-Agent": "AI-Kali-Assistant/1.0 authorized-web-assessment",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        def compact(value, limit=700):
            value = re.sub(r"\s+", " ", str(value or "")).strip()
            return value[:limit] + ("...[truncated]" if len(value) > limit else "")

        def emit(kind, *parts):
            print(kind + "|" + "|".join(compact(part, 900) for part in parts))

        def fetch(url, method="GET", headers=None, max_bytes=MAX_BODY):
            merged = dict(BASE_HEADERS)
            if headers:
                merged.update(headers)
            req = urllib.request.Request(url, headers=merged, method=method)
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX) as resp:
                    raw = resp.read(max_bytes)
                    return {
                        "ok": True,
                        "status": getattr(resp, "status", 0),
                        "url": resp.geturl(),
                        "headers": resp.headers,
                        "raw": raw,
                        "text": raw.decode("utf-8", errors="replace"),
                        "error": "",
                    }
            except urllib.error.HTTPError as exc:
                raw = exc.read(max_bytes)
                return {
                    "ok": True,
                    "status": exc.code,
                    "url": exc.geturl(),
                    "headers": exc.headers,
                    "raw": raw,
                    "text": raw.decode("utf-8", errors="replace"),
                    "error": "",
                }
            except Exception as exc:
                return {
                    "ok": False,
                    "status": 0,
                    "url": url,
                    "headers": {},
                    "raw": b"",
                    "text": "",
                    "error": type(exc).__name__ + ": " + str(exc),
                }

        def header_dict(headers):
            return {str(k).lower(): str(v) for k, v in headers.items()}

        def finding(severity, title, evidence):
            emit("FINDING", severity, title, evidence)

        parsed = urllib.parse.urlparse(TARGET_URL)
        http_url = TARGET_URL.split("#", 1)[0]
        route_fragment = parsed.fragment or "(none)"
        origin = f"{parsed.scheme}://{parsed.netloc}"

        emit("START", "structured_web_assessment", TARGET_URL)
        emit("TARGET", "http_url", http_url)
        emit("TARGET", "spa_fragment", route_fragment)

        main = fetch(http_url)
        emit("HTTP", "main", str(main["status"]), main["url"], "bytes=" + str(len(main["raw"])))
        if not main["ok"]:
            finding("HIGH", "request_failed", main["error"])
            emit("END", "structured_web_assessment", "failed")
            raise SystemExit(0)

        body = main["text"]
        headers = main["headers"]
        hdrs = header_dict(headers)
        emit("HEADERS_BEGIN", "main_response")
        for key, value in headers.items():
            emit("HEADER", key, value)
        emit("HEADERS_END", "main_response")

        wanted = {
            "content-security-policy": "MEDIUM",
            "x-frame-options": "LOW",
            "x-content-type-options": "LOW",
            "referrer-policy": "LOW",
            "permissions-policy": "LOW",
            "strict-transport-security": "MEDIUM" if parsed.scheme == "https" else "INFO",
        }
        missing = [name for name in wanted if name not in hdrs]
        emit("CHECK", "missing_security_headers", ",".join(missing) if missing else "(none)")
        for name in missing:
            finding(wanted[name], "missing_security_header", name)

        cookies = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else []
        emit("CHECK", "set_cookie_count", str(len(cookies or [])))
        for cookie in (cookies or [])[:12]:
            lowered = cookie.lower()
            emit("COOKIE", cookie)
            if "secure" not in lowered and parsed.scheme == "https":
                finding("MEDIUM", "cookie_without_secure", cookie)
            if "httponly" not in lowered:
                finding("LOW", "cookie_without_httponly", cookie)
            if "samesite" not in lowered:
                finding("LOW", "cookie_without_samesite", cookie)

        cors = fetch(http_url, headers={"Origin": "https://attacker.example"})
        cors_headers = header_dict(cors["headers"])
        acao = cors_headers.get("access-control-allow-origin", "")
        acac = cors_headers.get("access-control-allow-credentials", "")
        emit("CHECK", "cors_probe", f"status={cors['status']} acao={acao or '(none)'} acac={acac or '(none)'}")
        if acao == "*" and acac.lower() == "true":
            finding("HIGH", "cors_wildcard_with_credentials", "Access-Control-Allow-Origin=* and credentials=true")
        elif acao == "https://attacker.example" and acac.lower() == "true":
            finding("HIGH", "cors_reflects_origin_with_credentials", "reflected attacker Origin and credentials=true")
        elif acao in {"*", "https://attacker.example"}:
            finding("INFO", "permissive_cors_without_credentials", f"acao={acao}; validate impact with authenticated response")

        options = fetch(http_url, method="OPTIONS", headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
        })
        emit("CHECK", "options_probe", f"status={options['status']} allow={options['headers'].get('Allow', '(none)')} acam={options['headers'].get('Access-Control-Allow-Methods', '(none)')}")

        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        emit("HTML", "title", compact(title.group(1), 220) if title else "(none)")
        forms = re.findall(r"<form\b[^>]*>", body, re.I)
        inputs = re.findall(r"<input\b[^>]*>", body, re.I)
        emit("HTML", "form_count", str(len(forms)))
        emit("HTML", "input_count", str(len(inputs)))
        for item in inputs[:16]:
            emit("HTML_INPUT", item)

        script_refs = re.findall(r"<script[^>]+src=[\"']([^\"']+)", body, re.I)
        script_urls = []
        for src in script_refs:
            abs_url = urllib.parse.urljoin(main["url"], src)
            if abs_url not in script_urls:
                script_urls.append(abs_url)
        emit("ASSETS", "script_count", str(len(script_urls)))
        for src in script_urls[:25]:
            emit("SCRIPT_SRC", src)

        endpoint_hits = set()
        secret_hits = []
        sourcemaps = []
        secret_regex = re.compile(r"(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|authorization|bearer|secret|password)\s*[:=]\s*[\"'][^\"']{6,}")
        endpoint_regex = re.compile(r"[\"']((?:/api/|/rest/|/graphql|/auth|/login|/admin|/user|/users|/oauth|/account|/session)[^\"' <>)\\]{0,180})")
        map_regex = re.compile(r"sourceMappingURL=([^\s*]+)")
        for src in script_urls[:12]:
            asset = fetch(src, max_bytes=MAX_ASSET)
            emit("ASSET_FETCH", src, "status=" + str(asset["status"]), "bytes=" + str(len(asset["raw"])))
            text = asset["text"]
            for match in secret_regex.finditer(text):
                secret_hits.append((src, compact(match.group(0), 220)))
            for match in endpoint_regex.finditer(text):
                endpoint_hits.add(urllib.parse.urljoin(origin, match.group(1)))
            for match in map_regex.finditer(text):
                sourcemaps.append(urllib.parse.urljoin(src, match.group(1).strip()))

        emit("JS", "endpoint_count", str(len(endpoint_hits)))
        for endpoint in sorted(endpoint_hits)[:40]:
            emit("JS_ENDPOINT", endpoint)
        emit("JS", "secret_pattern_count", str(len(secret_hits)))
        for src, evidence in secret_hits[:10]:
            finding("HIGH", "secret_like_pattern_in_js", f"{src} :: {evidence}")
        emit("JS", "sourcemap_reference_count", str(len(sourcemaps)))
        for smap in sourcemaps[:10]:
            probe = fetch(smap, max_bytes=120000)
            emit("SOURCEMAP_PROBE", smap, "status=" + str(probe["status"]), "bytes=" + str(len(probe["raw"])))
            if probe["status"] == 200 and len(probe["raw"]) > 50:
                finding("MEDIUM", "accessible_sourcemap", smap)

        common_paths = [
            "/robots.txt",
            "/sitemap.xml",
            "/security.txt",
            "/.well-known/security.txt",
            "/asset-manifest.json",
            "/manifest.json",
            "/config.js",
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/.env",
            "/actuator/health",
        ]
        for path in common_paths:
            target = urllib.parse.urljoin(origin, path)
            probe = fetch(target, max_bytes=60000)
            emit("PATH_PROBE", path, "status=" + str(probe["status"]), "bytes=" + str(len(probe["raw"])))
            preview = compact(probe["text"], 240)
            if probe["status"] == 200:
                emit("PATH_BODY_PREVIEW", path, preview)
                if path == "/.env" and "=" in probe["text"]:
                    finding("HIGH", "dotenv_exposed", target)
                elif path in {"/swagger.json", "/openapi.json", "/api-docs"}:
                    finding("MEDIUM", "api_documentation_exposed", target)
                elif path in {"/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt"}:
                    finding("INFO", "well_known_file_accessible", target)

        emit("END", "structured_web_assessment", "complete")
        """
        script = textwrap.dedent(scanner).strip().replace("__TARGET_URL__", repr(url))
        return "python3 - <<'PY'\n" + script + "\nPY"

    @staticmethod
    def _extract_first_url(text: str) -> str:
        match = re.search(r"https?://[^\s<>'\"`]+", text)
        if not match:
            return ""
        return match.group(0).rstrip(".,);]")

    def _record_command_result(self, result: SSHCommandResult) -> None:
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        self.auto_command_history.append(
            {
                "command": self._display_command(result.command),
                "family": self._command_family(result.command),
                "exit_status": str(result.exit_status),
                "stdout_chars": str(len(stdout)),
                "stderr_chars": str(len(stderr)),
                "timed_out": "sim" if result.timed_out else "nao",
                "stdout_preview": self._compact_line(stdout[:300]) or "(vazio)",
                "stderr_preview": self._compact_line(stderr[:200]) or "(vazio)",
            }
        )
        self.auto_command_history = self.auto_command_history[-20:]

    def _build_command_history_context(self) -> str:
        if not self.auto_command_history:
            return "(sem acoes anteriores nesta automacao)"

        lines = []
        for index, item in enumerate(self.auto_command_history[-10:], start=1):
            lines.append(
                f"{index}. acao={item['command']} | familia={item['family']} | "
                f"exit={item['exit_status']} | stdout_chars={item['stdout_chars']} | "
                f"stderr_chars={item['stderr_chars']} | timeout={item['timed_out']} | "
                f"stdout_preview={item['stdout_preview']}"
            )
        return "\n".join(lines)

    @classmethod
    def _command_family(cls, command: str) -> str:
        lowered = command.lower()
        url_match = re.search(r"https?://[^\s'\"|)#]+", command)
        url = url_match.group(0).rstrip("/") if url_match else ""
        if command.startswith("python3 - <<'PY'") and "structured_web_assessment" in command:
            return "structured-web-assessment:" + url
        if "curl" in lowered and "| grep" in lowered:
            return "curl-grep-html:" + url
        if lowered.startswith("whatweb"):
            return "whatweb:" + url
        if lowered.startswith("nmap"):
            return "nmap"
        if "curl" in lowered and any(flag in lowered for flag in [" -i", " -I", "--head"]):
            return "curl-headers:" + url
        if "curl" in lowered:
            return "curl-fetch:" + url
        first = command.split(maxsplit=1)[0].lower() if command.split() else "unknown"
        return first

    def _is_low_value_grep_cycle(self, command: str) -> bool:
        family = self._command_family(command)
        if not family.startswith("curl-grep-html:"):
            return False
        empty_same_family = 0
        for item in reversed(self.auto_command_history[-8:]):
            if item.get("family") != family:
                continue
            if item.get("stdout_chars") == "0":
                empty_same_family += 1
        return empty_same_family >= 2

    @staticmethod
    def _compact_line(text: str) -> str:
        return re.sub(r"\s+", " ", text).strip()

    def _handle_suggested_command(self, command: str) -> None:
        command = command.strip()
        if not command:
            return

        self._set_command(command)

        if self._is_low_value_grep_cycle(command):
            command_key = re.sub(r"\s+", " ", command).strip().lower()
            self.auto_executed_commands.add(command_key)
            self._append_ai_decision_to_terminal(
                command,
                "ignorada por baixo valor: repetição de curl|grep sem evidência",
            )
            self.append_chat(
                "Sistema",
                "Ação ignorada por baixo valor: a automação já executou buscas curl|grep "
                "sem saída para este alvo. Vou solicitar uma técnica diferente.",
                "system",
            )
            self.status_var.set("Ciclo fraco detectado; solicitando técnica diferente.")
            if self.last_command and self.last_ssh_output:
                self.root.after(
                    250,
                    lambda: self.analyze_ssh_result(
                        self.last_command,
                        self.last_ssh_output,
                        extra_instruction=(
                            "A acao sugerida foi rejeitada por repetir curl|grep "
                            "sem evidencia. Escolha uma tecnica materialmente diferente e "
                            "mais ampla. Nao sugira outro grep de palavra isolada."
                        ),
                    ),
                )
            return

        blocked_reason = self._blocked_command_reason(command)
        if blocked_reason:
            self._append_ai_decision_to_terminal(
                command,
                f"bloqueada pela automação: {blocked_reason}",
            )
            self.append_chat(
                "Sistema",
                f"Ação bloqueada pela automação: {blocked_reason}.\n{command}",
                "error",
            )
            self.status_var.set("Ação bloqueada pela automação.")
            return

        intensive_reasons = self._intensive_command_reasons(command)
        if intensive_reasons:
            self._append_ai_decision_to_terminal(
                command,
                "bloqueada por intensidade: " + "; ".join(intensive_reasons),
            )
            self.append_chat(
                "Sistema",
                "Ação intensa não executada automaticamente:\n"
                + "\n".join(f"- {reason}" for reason in intensive_reasons)
                + f"\n\nAção: {command}",
                "error",
            )
            self.status_var.set("Ação intensa bloqueada na automação.")
            return

        command_key = re.sub(r"\s+", " ", command).strip().lower()
        if command_key in self.auto_executed_commands:
            self._append_ai_decision_to_terminal(
                command,
                "bloqueada por repetição",
            )
            self.append_chat(
                "Sistema",
                "A IA tentou repetir uma ação que já foi executada nesta automação. "
                "Pare a repetição e revise os resultados.",
                "system",
            )
            self.status_var.set("Ação repetida bloqueada.")
            return

        self.auto_executed_commands.add(command_key)
        self.auto_chain_count += 1
        self._append_ai_decision_to_terminal(command, "aprovada para execução automática")
        self.status_var.set(f"Executando ação automática #{self.auto_chain_count}: {command}")
        self.root.after(250, lambda: self.execute_on_kali(auto_confirm=True))

    def _append_ai_decision_to_terminal(self, command: str, status: str) -> None:
        action_number = self.auto_chain_count or 1
        self.append_ssh_output(
            "\n"
            + "=" * 72
            + f"\n[IA decidiu executar #{action_number}]\n"
            + f"status: {status}\n"
            + self._format_terminal_marker(command)
            + "\n"
        )

    @staticmethod
    def _format_terminal_action(command: str) -> str:
        command = command.strip()
        if "\n" in command:
            return command
        return f"$ {command}"

    @staticmethod
    def _format_terminal_marker(command: str) -> str:
        command = command.strip()
        if "\n" in command:
            return "ACAO_KALI:\n" + command
        return "ACAO_KALI: " + command

    def _read_config_from_ui(self) -> dict[str, str]:
        model = self.ollama_model_var.get().strip() or DEFAULT_CONFIG["ollama_model"]
        return {
            "kali_ip": self.kali_ip_var.get().strip(),
            "ssh_user": self.ssh_user_var.get().strip(),
            "ssh_password": self.ssh_password_var.get(),
            "ollama_model": model,
        }

    def _save_config_silently(self, config: dict[str, str]) -> None:
        try:
            self.config_manager.save(config)
        except RuntimeError as exc:
            self.logger.error(str(exc))

    def _validate_ssh_config(self, config: dict[str, str]) -> bool:
        missing = []
        if not config["kali_ip"]:
            missing.append("IP do Kali")
        if not config["ssh_user"]:
            missing.append("usuário SSH")
        if not config["ssh_password"]:
            missing.append("senha SSH")

        if missing:
            messagebox.showwarning(
                "Configuração incompleta",
                "Preencha antes de continuar: " + ", ".join(missing) + ".",
            )
            return False
        return True

    def _set_command(self, command: str) -> None:
        command = command.strip()
        self.pending_command = command if self._looks_like_shell_command(command) else ""
        self.command_text.configure(state=tk.NORMAL)
        self.command_text.delete("1.0", tk.END)
        self.command_text.insert("1.0", self._display_command(command))
        self.command_text.configure(state=tk.DISABLED)

    def _display_command(self, command: str) -> str:
        command = command.strip()
        if not command:
            return ""
        lines = command.splitlines()
        if command.startswith("python3 - <<'PY'") and "structured_web_assessment" in command:
            url = self._extract_first_url(command)
            suffix = f" para {url}" if url else ""
            return f"avaliação web estruturada via python3{suffix} ({len(lines)} linhas)"
        if len(lines) > 3:
            return f"{lines[0]} ... ({len(lines)} linhas)"
        if len(command) > 260:
            return command[:240] + " ... [ação reduzida na interface]"
        return command

    def _format_ssh_result_for_model(self, result: SSHCommandResult) -> str:
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        timeout_text = "sim" if result.timed_out else "nao"
        return "\n".join(
            [
                f"Acao: {self._display_command(result.command)}",
                f"Exit status: {result.exit_status}",
                f"Timeout: {timeout_text}",
                "",
                "[stdout]",
                stdout or "(vazio)",
                "",
                "[stderr]",
                stderr or "(vazio)",
            ]
        )

    @staticmethod
    def _limit_text(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        half = max(1, limit // 2)
        return (
            text[:half]
            + "\n\n[... conteudo reduzido para caber no contexto ...]\n\n"
            + text[-half:]
        )

    def _set_ssh_output(self, text: str) -> None:
        self.ssh_output.delete("1.0", tk.END)
        self.ssh_output.insert("1.0", text)

    def append_ssh_output(self, text: str) -> None:
        self.ssh_output.insert(tk.END, text)
        self.ssh_output.see(tk.END)

    def append_chat(self, speaker: str, text: str, tag: str) -> None:
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"{speaker}\n", ("speaker",))
        self.chat_display.insert(tk.END, f"{text.strip()}\n\n", (tag,))
        self.chat_display.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)

    def begin_stream_message(self, speaker: str) -> None:
        self.end_stream_message()
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"{speaker}\n", ("speaker",))
        self.chat_display.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)
        self.streaming_message_open = True

    def append_stream_chunk(self, chunk: str, tag: str) -> None:
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, chunk, (tag,))
        self.chat_display.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)

    def end_stream_message(self) -> None:
        if not self.streaming_message_open:
            return
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, "\n\n")
        self.chat_display.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)
        self.streaming_message_open = False

    @classmethod
    def extract_command_suggestion(cls, answer: str) -> str:
        explicit_pattern = re.compile(
            r"^\s*(?:[-*]\s*)?`?(?:ACAO_KALI|AÇÃO_KALI|ACAO\s*\d*|AÇÃO\s*\d*|COMANDO_KALI|COMANDO|COMMAND)\s*:",
            re.IGNORECASE,
        )
        for line in answer.splitlines():
            if not explicit_pattern.match(line):
                continue
            cleaned = cls._clean_possible_command_line(line)
            if cleaned and cls._looks_like_shell_command(cleaned):
                return cleaned

        return ""

    @classmethod
    def _needs_operational_repair(cls, answer: str) -> bool:
        if not answer.strip():
            return False
        if cls.extract_command_suggestion(answer):
            return False

        lowered = answer.lower()
        bad_structure_terms = [
            "próximo passo",
            "proximo passo",
            "procedimento operacional",
            "coleta inicial",
            "análise manual",
            "analise manual",
            "execute ",
            "executar ",
            "abra ",
            "abrir arquivo",
            "```",
            "finding|",
            "## achados",
            "## recomenda",
            "## conclusão",
            "## conclusao",
        ]
        if any(term in lowered for term in bad_structure_terms):
            return True
        return cls._contains_unmarked_shell_action(answer)

    @staticmethod
    def _contains_pre_execution_claims(answer: str) -> bool:
        lowered = answer.lower()
        claim_terms = [
            "finding|",
            "## achados",
            "## recomenda",
            "## conclusão",
            "## conclusao",
            "vulnerabilidade",
            "exposto",
            "exposta",
        ]
        return any(term in lowered for term in claim_terms)

    @classmethod
    def _contains_unmarked_shell_action(cls, answer: str) -> bool:
        code_block_pattern = re.compile(
            r"```(?:bash|sh|shell|console)?\s*\n(.*?)```",
            re.IGNORECASE | re.DOTALL,
        )
        for match in code_block_pattern.finditer(answer):
            for raw_line in match.group(1).splitlines():
                cleaned = cls._clean_unmarked_shell_line(raw_line)
                if cleaned and cls._looks_like_shell_command(cleaned):
                    return True

        for raw_line in answer.splitlines():
            cleaned = cls._clean_unmarked_shell_line(raw_line)
            if cleaned and cls._looks_like_shell_command(cleaned):
                return True
        return False

    @staticmethod
    def _clean_unmarked_shell_line(line: str) -> str:
        cleaned = line.strip().strip("`")
        cleaned = re.sub(r"^\s*(?:[-*]\s*)?\d+[.)]\s*", "", cleaned)
        cleaned = re.sub(r"^\s*[-*]\s+", "", cleaned)
        if cleaned.startswith("$ "):
            cleaned = cleaned[2:].strip()
        return cleaned

    @classmethod
    def _looks_like_shell_command(cls, text: str) -> bool:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return False
        first_line = lines[0]
        if first_line.startswith(("**", "|", "<", ">", "#")):
            return False
        first_word = first_line.split(maxsplit=1)[0].lower()
        return first_word in cls.SHELL_PREFIXES

    @staticmethod
    def _clean_possible_command_line(line: str) -> str:
        cleaned = line.strip().strip("`")
        cleaned = re.sub(r"^\s*[-*]\s+", "", cleaned)
        cleaned = re.sub(
            r"^(?:ACAO_KALI|AÇÃO_KALI|ACAO\s*\d*|AÇÃO\s*\d*|COMANDO_KALI|COMANDO|COMMAND)\s*:\s*",
            "",
            cleaned,
            flags=re.IGNORECASE,
        )
        if cleaned.startswith("$ "):
            cleaned = cleaned[2:].strip()
        return cleaned

    def _blocked_command_reason(self, command: str) -> str:
        for pattern, reason in self.BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE | re.DOTALL):
                return reason
        return ""

    def _intensive_command_reasons(self, command: str) -> list[str]:
        reasons = []
        for pattern, reason in self.INTENSIVE_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE | re.DOTALL):
                reasons.append(reason)
        return reasons


def main() -> None:
    root = tk.Tk()
    app = AiKaliAssistantApp(root)
    app.append_chat(
        "Sistema",
        "Pronto. Configure Ollama, SSH e converse com a IA. Use Definir Regras para editar rules.txt.",
        "system",
    )
    root.mainloop()


if __name__ == "__main__":
    main()
