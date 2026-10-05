import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.validation import validate_target

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
MAX_REPORT_BYTES = 2_000_000
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "senha",
    "token",
    "secret",
    "api_key",
    "authorization",
    "cookie",
    "set-cookie",
}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def clean_text(value: str) -> str:
    """Remove controles de terminal e campos comuns de credenciais."""
    value = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))", "", value)
    value = "".join(char for char in value if char in "\n\t" or (char.isprintable()))
    value = re.sub(
        r"(?im)^(\s*(?:set-cookie|cookie|authorization|proxy-authorization)\s*:)[^\n]*(?:\n[ \t]+[^\n]+)*",
        r"\1 [REMOVIDO]",
        value,
    )
    value = re.sub(
        r"""(?i)(["']?(?:password|passwd|senha|token|secret|api[_-]?key)["']?\s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s&;,]+)""",
        r"\1[REMOVIDO]",
        value,
    )
    return value


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REMOVIDO]" if str(key).lower() in SENSITIVE_KEYS else sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    return clean_text(value) if isinstance(value, str) else value


def new_report(target: str, mode: str, ports: str | None) -> dict:
    return {
        "project": "OFF ANGELL",
        "schema_version": 1,
        "started_at": now_iso(),
        "target": validate_target(target),
        "mode": mode,
        "requested_ports": ports,
        "status": "iniciado",
        "open_ports": [],
        "banners": [],
        "nse": [],
        "tools": [],
    }


def render_txt(report: dict) -> str:
    lines = [
        "OFF ANGELL — RELATÓRIO",
        "=" * 60,
        f"Data/hora: {report['started_at']}",
        f"Alvo: {report['target']}",
        f"Endereço analisado: {report.get('address', 'desconhecido')}",
        f"Modo: {report['mode']}",
        f"Estado: {report['status']}",
        "",
        "PORTAS ABERTAS",
    ]
    for item in report["open_ports"]:
        lines.append(
            f"{item['port']}/{item['protocol']}  {item['service']}  "
            f"{item.get('product', 'desconhecido')} {item.get('version', 'desconhecido')}"
        )
    if not report["open_ports"]:
        lines.append("Nenhuma porta aberta registrada.")
    for key, title in (
        ("banners", "BANNERS"),
        ("nse", "RESULTADOS NSE"),
        ("tools", "FERRAMENTAS OPCIONAIS"),
    ):
        lines.extend(["", title])
        lines.append(json.dumps(report[key], ensure_ascii=False, indent=2))
    if report.get("message"):
        lines.extend(["", report["message"]])
    lines.extend(["", "Resultados NSE são indícios, não confirmação de vulnerabilidade."])
    return "\n".join(lines) + "\n"


def save_report(report: dict, format_name: str, directory: Path = REPORTS_DIR) -> Path:
    extension = format_name.lower()
    if extension not in {"txt", "json"}:
        raise ValueError("Formato inválido. Escolha TXT ou JSON.")
    target = validate_target(report["target"])
    safe_host = re.sub(r"[^a-zA-Z0-9._-]", "_", target)[:80]
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H%M%S_%f")
    path = directory / f"scan_{safe_host}_{stamp}_{uuid4().hex[:8]}.{extension}"
    data = sanitize({**report, "saved_at": now_iso()})
    content = (
        json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        if extension == "json"
        else render_txt(data)
    )
    if len(content.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("Relatório excede o limite de 2 MB. Salve menos análises por sessão.")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    return path


def list_reports(directory: Path = REPORTS_DIR) -> list[Path]:
    directory = Path(directory)
    if not directory.exists():
        return []
    return sorted(
        (
            path
            for path in directory.glob("scan_*.*")
            if path.suffix in {".json", ".txt"} and path.is_file() and not path.is_symlink()
        ),
        reverse=True,
    )


def read_report(path: Path, directory: Path = REPORTS_DIR) -> str:
    path = Path(path)
    if (
        path.is_symlink()
        or path.resolve().parent != Path(directory).resolve()
        or path.suffix not in {".txt", ".json"}
    ):
        raise ValueError("Relatório inválido.")
    with path.open("rb") as stream:
        content = stream.read(MAX_REPORT_BYTES + 1)
    if len(content) > MAX_REPORT_BYTES:
        raise ValueError("Relatório excede o limite de leitura de 2 MB.")
    text = content.decode("utf-8")
    if path.suffix == ".json":
        return json.dumps(sanitize(json.loads(text)), ensure_ascii=False, indent=2)
    return clean_text(text)
