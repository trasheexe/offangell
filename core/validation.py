import ipaddress
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


def validate_target(value: str) -> str:
    """Aceita um único IP ou hostname, nunca opções ou listas do Nmap."""
    if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Alvo inválido: informe um único hostname ou IP.")
    target = value.strip()
    if "://" in target or "/" in target or "\\" in target:
        raise ValueError("Informe somente hostname/IP, sem URL, caminho ou rede CIDR.")
    if not target or target.startswith("-") or any(char.isspace() for char in target):
        raise ValueError("Alvo inválido: espaços e parâmetros não são aceitos.")
    if "%" in target:
        raise ValueError("Informe um IP sem identificador de interface (%).")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if ":" in target or re.fullmatch(r"[0-9.]+", target):
        raise ValueError("IP inválido. Não inclua a porta junto ao endereço.")
    try:
        hostname = target.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Hostname inválido.") from exc
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(hostname) > 253 or not all(re.fullmatch(label, part) for part in hostname.split(".")):
        raise ValueError("Hostname inválido: use letras, números, pontos e hífens internos.")
    if target.endswith(".."):
        raise ValueError("Hostname inválido.")
    return hostname


def validate_web_url(value: str) -> str:
    """Valida uma URL HTTP(S) única sem perder caminho, porta ou query string."""
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("URL inválida: informe um único endereço HTTP ou HTTPS.")
    if any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in value):
        raise ValueError("URL inválida: espaços e caracteres de controle não são aceitos.")
    if "\\" in value or "#" in value:
        raise ValueError("URL inválida: barras invertidas e fragmentos não são aceitos.")
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"}:
            raise ValueError
        if not parts.netloc or parts.username is not None or parts.password is not None:
            raise ValueError
        if parts.netloc.endswith(":") or parts.netloc.endswith("]:"):
            raise ValueError
        host = parts.hostname
        if not host:
            raise ValueError
        validate_target(host)
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, UnicodeError) as exc:
        raise ValueError(
            "URL inválida: use http:// ou https://, sem credenciais ou fragmento."
        ) from exc
    return value


def parse_web_target(value: str) -> dict:
    """Parseia URL HTTP(S) em campos validados sem criar argumentos de shell."""
    url = validate_web_url(value)
    parts = urlsplit(url)
    host = validate_target(parts.hostname or "")
    scheme = parts.scheme.lower()
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:  # Mantém o contrato mesmo se urlsplit mudar.
        raise ValueError("Porta inválida na URL.") from exc
    return {
        "url": url,
        "host": host,
        "hostname": host,
        "original_url": url,
        "ip": host if _is_ip_address(host) else None,
        "port": port,
        "protocol": scheme,
        "path": parts.path or "/",
        "query": parts.query,
    }


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_ports(value: str) -> str:
    if not value or len(value) > 4096 or not re.fullmatch(r"[0-9,-]+", value):
        raise ValueError("Portas inválidas. Exemplos: 1-1000 ou 22,80,443.")
    normalized = []
    for item in value.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", item):
            raise ValueError("Intervalo inválido. Exemplos: 1-1000 ou 80,443,8080.")
        bounds = [int(part) for part in item.split("-")]
        if any(not 1 <= port <= 65535 for port in bounds):
            raise ValueError("As portas devem estar entre 1 e 65535.")
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise ValueError("O início do intervalo não pode ser maior que o fim.")
        normalized.append("-".join(map(str, bounds)))
    return ",".join(normalized)


def service_name(service: str | Mapping[str, Any]) -> str:
    if isinstance(service, str):
        return service.lower()
    return str(service.get("service") or service.get("name") or "desconhecido").lower()


def uses_tls(port: int, service: str | Mapping[str, Any]) -> bool:
    name = service_name(service)
    tunnel = service.get("tunnel", "") if isinstance(service, Mapping) else ""
    return port in {443, 8443} or "https" in name or name.startswith("ssl/") or tunnel == "ssl"

def is_web_service(info: dict | int, service: str | Mapping[str, Any] | None = None) -> bool:
    if isinstance(info, Mapping):
        port = int(info.get("port", 0))
        service_name_value = str(info.get("service", "")).lower()
    else:
        port = int(info)
        service_name_value = service_name(service or "")

    web_ports = {
        80,
        443,
        3000,
        5000,
        8000,
        8080,
        8443,
    }

    web_services = (
        "http",
        "https",
        "web",
        "apache",
        "nginx",
        "iis",
    )

    if any(
        name in service_name_value
        for name in web_services
    ):
        return True
    known_non_web = {
        "ssh",
        "ftp",
        "sftp",
        "smtp",
        "dns",
        "mysql",
        "postgres",
        "postgresql",
        "rdp",
        "telnet",
        "snmp",
        "imap",
        "pop3",
        "ldap",
        "smb",
        "mongodb",
        "redis",
        "oracle",
        "ms-sql-s",
        "ms-sql",
        "domain",
    }
    if service_name_value in known_non_web:
        return False
    return port in web_ports

def build_web_url(target: str, port: int, service: str | Mapping[str, Any] = "") -> str:
    host = validate_target(target)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Porta inválida: use um número entre 1 e 65535.")
    authority = f"[{host}]" if ":" in host else host
    scheme = "https" if uses_tls(port, service) else "http"
    return f"{scheme}://{authority}:{port}"
