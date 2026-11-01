import json
import os
from pathlib import Path
from typing import Any

CONFIG_PATH = Path.home() / ".offangell" / "settings.json"
TOOLS_ROOT = Path(r"C:\tools")
NMAP_PATH = r"C:\tools\Nmap\nmap.exe"
ZAP_ROOT = Path(r"C:\tools\ZAP\Zed Attack Proxy")
NIKTO_PATH = r"C:\tools\nikto-2.6.1\program\nikto.pl"
JAVA_PATH = r"C:\Program Files\Eclipse Adoptium\jre-17.0.20.101-hotspot\bin\java.exe"
NUCLEI_PATH = r"C:\tools\Nuclei\nuclei.exe"
PERL_PATHS = (
    r"C:\Strawberry\perl\bin\perl.exe",
    r"C:\Strawberry\c\bin\perl.exe",
)
TOOL_PATH_DEFAULTS = {
    "nmap": NMAP_PATH,
    "nuclei": NUCLEI_PATH,
    "zap": str(ZAP_ROOT / "ZAP.exe"),
    "zap_launcher": str(ZAP_ROOT / "zap.bat"),
    "zap_baseline": "",
    "nikto": NIKTO_PATH,
    "java": JAVA_PATH,
    "perl": "",
    "powershell": "",
    "metasploit": "",
}
NUCLEI_DEFAULTS = {
    "enabled": True,
    "executable_path": "",
    "templates_directory": "",
    "timeout": 600,
    "rate_limit": 2,
    "concurrency": 2,
}
NIKTO_DEFAULTS = {"enabled": True, "timeout": 600}


def _read_dotenv(path: Path | None = None) -> dict[str, str]:
    """Read simple KEY=VALUE entries without overriding the process environment."""
    dotenv_path = Path(path) if path is not None else Path(__file__).resolve().parent.parent / ".env"
    values: dict[str, str] = {}
    try:
        for raw_line in dotenv_path.read_text(encoding="utf-8-sig").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            key, separator, value = line.partition("=")
            key = key.strip()
            if not separator or not key or not key.replace("_", "").isalnum():
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            values[key] = value
    except OSError:
        pass
    return {key: os.environ.get(key, value) for key, value in values.items()}


def _with_environment(config: dict, dotenv_path: Path | None = None) -> dict:
    """Apply .env/process environment overrides while preserving stored settings."""
    values = _read_dotenv(dotenv_path)
    tools = dict(config["tools"])
    for env_name, tool_name in (("PERL_PATH", "perl"), ("NIKTO_PATH", "nikto")):
        override = os.environ.get(env_name, values.get(env_name, "")).strip()
        if override:
            tools[tool_name] = override
    nikto = dict(config.get("nikto", NIKTO_DEFAULTS))
    enabled = os.environ.get("NIKTO_ENABLED", values.get("NIKTO_ENABLED"))
    if enabled is not None:
        nikto["enabled"] = enabled.strip().lower() in {"1", "true", "yes", "on"}
    timeout = os.environ.get("NIKTO_TIMEOUT", values.get("NIKTO_TIMEOUT"))
    if timeout is not None:
        try:
            parsed = int(timeout.strip())
            if 1 <= parsed <= 1800:
                nikto["timeout"] = parsed
        except (ValueError, AttributeError):
            pass
    return {**config, "tools": tools, "nikto": nikto}


def validate_nuclei_settings(value: Any) -> dict:
    if not isinstance(value, dict):
        raise ValueError("As configurações do Nuclei devem ser um objeto JSON.")
    settings = dict(NUCLEI_DEFAULTS)
    settings["enabled"] = value.get("enabled", settings["enabled"]) is True
    for key in ("executable_path", "templates_directory"):
        item = value.get(key, settings[key])
        if not isinstance(item, str) or len(item) > 2048 or any(ord(c) < 32 for c in item):
            raise ValueError(f"Configuração inválida: {key}.")
        settings[key] = item.strip()
    for key, lower, upper in (("timeout", 1, 600), ("rate_limit", 1, 5), ("concurrency", 1, 2)):
        item = value.get(key, settings[key])
        if isinstance(item, bool) or not isinstance(item, int) or not lower <= item <= upper:
            raise ValueError(f"{key} deve estar entre {lower} e {upper}.")
        settings[key] = item
    return settings


def validate_tool_paths(value: Any) -> dict:
    if not isinstance(value, dict):
        raise ValueError("Os caminhos das ferramentas devem ser um objeto JSON.")
    paths = dict(TOOL_PATH_DEFAULTS)
    for key in paths:
        item = value.get(key, "")
        if not isinstance(item, str) or len(item) > 4096 or any(ord(char) < 32 for char in item):
            raise ValueError(f"Caminho inválido para {key}.")
        paths[key] = item.strip()
    return paths


def load_config(path: Path | None = None, *, apply_environment: bool = True) -> dict:
    settings_path = Path(path) if path is not None else CONFIG_PATH
    defaults = {"nuclei": dict(NUCLEI_DEFAULTS), "nikto": dict(NIKTO_DEFAULTS), "tools": dict(TOOL_PATH_DEFAULTS)}
    def finish(config: dict) -> dict:
        return _with_environment(config) if apply_environment else config
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return finish(defaults)
        legacy_tools = data.get("tools", {})
        legacy_nuclei = data.get("nuclei", {})
        if not isinstance(legacy_tools, dict):
            raise ValueError("Os caminhos das ferramentas devem ser um objeto JSON.")
        if not isinstance(legacy_nuclei, dict):
            raise ValueError("As configurações do Nuclei devem ser um objeto JSON.")
        if "nuclei" in data and "nuclei" not in legacy_tools:
            legacy_tools = {**legacy_tools, "nuclei": legacy_nuclei.get("executable_path", "")}
        config = {
            "nuclei": validate_nuclei_settings(data.get("nuclei", {})),
            "nikto": _validate_nikto_settings(data.get("nikto", {})),
            "tools": validate_tool_paths(legacy_tools),
        }
        return finish(config)
    except FileNotFoundError:
        return finish(defaults)
    except (OSError, json.JSONDecodeError, ValueError):
        return finish(defaults)


def _validate_nikto_settings(value: Any) -> dict:
    if not isinstance(value, dict):
        raise ValueError("As configurações do Nikto devem ser um objeto JSON.")
    enabled = value.get("enabled", NIKTO_DEFAULTS["enabled"])
    timeout = value.get("timeout", NIKTO_DEFAULTS["timeout"])
    if not isinstance(enabled, bool):
        raise ValueError("nikto.enabled deve ser booleano.")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 1800:
        raise ValueError("nikto.timeout deve estar entre 1 e 1800 segundos.")
    return {"enabled": enabled, "timeout": timeout}


def save_config(config: dict, path: Path | None = None) -> Path:
    settings_path = Path(path) if path is not None else CONFIG_PATH
    current = load_config(settings_path, apply_environment=False)
    nuclei_settings = validate_nuclei_settings(config.get("nuclei", current["nuclei"]))
    nikto_settings = _validate_nikto_settings(config.get("nikto", current["nikto"]))
    tools = validate_tool_paths(config.get("tools", current["tools"]))
    if (
        "nuclei" in config
        and "tools" not in config
        and nuclei_settings["executable_path"] != current["nuclei"]["executable_path"]
    ):
        tools["nuclei"] = nuclei_settings["executable_path"]
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(
        json.dumps({"nuclei": nuclei_settings, "nikto": nikto_settings, "tools": tools}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return settings_path
