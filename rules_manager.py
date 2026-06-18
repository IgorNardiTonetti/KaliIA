from __future__ import annotations

from pathlib import Path


DEFAULT_RULES = """Você é um piloto/copiloto de cybersegurança ofensiva.
Você só deve ajudar de acordo dos comandos pelo usuário
Antes de qualquer teste, confirme alvo, escopo e intensidade.
Nunca execute comandos automaticamente.
Explique o objetivo de cada comando antes de sugerir.
Depois de receber resultados, explique achados, impacto e mitigação.
Nunca ajude com roubo de dados, persistência, malware, evasão, destruição, phishing ou acesso não autorizado.
Seu foco é reconhecimento autorizado, análise de resultados, geração de relatórios e correção de falhas.
"""


class RulesManager:
    def __init__(self, rules_path: str | Path) -> None:
        self.rules_path = Path(rules_path)

    def load_rules(self) -> str:
        if not self.rules_path.exists():
            self.save_rules(DEFAULT_RULES)
            return DEFAULT_RULES

        try:
            return self.rules_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Não foi possível ler rules.txt: {exc}") from exc

    def save_rules(self, rules: str) -> None:
        normalized_rules = rules.strip()
        if not normalized_rules:
            raise ValueError("As regras não podem ficar vazias.")

        self.rules_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.rules_path.write_text(normalized_rules + "\n", encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Não foi possível salvar rules.txt: {exc}") from exc
