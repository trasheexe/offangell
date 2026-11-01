"""Escopo e orquestração do scanner web, sempre limitado à URL autorizada."""

import re
import time
import socket
import urllib.error
import urllib.request
from collections.abc import Callable

from core.config import validate_nuclei_settings
from core.analysis import duration_ms, execution_state, report_sections
from core.nuclei import run_nuclei
from core.reports import clean_text, now_iso
from core.tools import run_nikto, run_zap
from core.validation import parse_web_target, validate_web_url

CONNECT_TIMEOUT = 8
HTTP_BODY_LIMIT = 64 * 1024
MAX_REDIRECTS = 5


class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    """Recusa redirecionamentos para host/porta diferentes do alvo informado."""

    def __init__(self, hostname: str, port: int):
        super().__init__()
        self.hostname = hostname
        self.port = port
        self.redirects: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            parsed = parse_web_target(newurl)
        except ValueError as exc:
            raise urllib.error.HTTPError(req.full_url, code, "Redirecionamento inválido", headers, fp) from exc
        if parsed["hostname"] != self.hostname or parsed["port"] != self.port:
            raise urllib.error.HTTPError(req.full_url, code, "Redirecionamento fora do escopo autorizado", headers, fp)
        if len(self.redirects) >= MAX_REDIRECTS:
            raise urllib.error.HTTPError(req.full_url, code, "Limite de redirecionamentos excedido", headers, fp)
        self.redirects.append(parsed["url"])
        return super().redirect_request(req, fp, code, msg, headers, parsed["url"])


def _http_probe(target_url: str) -> dict:
    parsed = parse_web_target(target_url)
    redirect_handler = _ScopedRedirect(parsed["hostname"], parsed["port"])
    opener = urllib.request.build_opener(redirect_handler)
    request = urllib.request.Request(
        target_url,
        headers={"User-Agent": "OFF-ANGELL-Web-Scanner/1.0", "Range": f"bytes=0-{HTTP_BODY_LIMIT - 1}"},
        method="GET",
    )
    status = None
    headers = {}
    body = b""
    final_url = target_url
    try:
        response = opener.open(request, timeout=CONNECT_TIMEOUT)
        try:
            status = response.status
            headers = dict(response.headers.items())
            body = response.read(HTTP_BODY_LIMIT)
            final_url = response.geturl()
        finally:
            response.close()
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        final_url = exc.geturl()
        if exc.code in {301, 302, 303, 307, 308} and "fora do escopo" in str(exc.reason):
            return {"status": "fora_escopo", "redirects": redirect_handler.redirects,
                    "message": "Redirecionamento externo ou para porta não autorizada bloqueado."}
    except Exception as exc:
        return {"status": "erro", "redirects": redirect_handler.redirects,
                "message": clean_text(str(getattr(exc, "reason", exc)))[:300]}

    lower_headers = {key.lower(): value for key, value in headers.items()}
    technologies = []
    for key in ("server", "x-powered-by", "x-generator"):
        if lower_headers.get(key):
            technologies.append({"source": key, "value": clean_text(lower_headers[key])[:300]})
    for match in re.findall(rb"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", body, re.I):
        technologies.append({"source": "meta generator", "value": clean_text(match.decode("utf-8", "replace"))[:300]})
    return {
        "status": "conectado",
        "http_status": status,
        "final_url": final_url,
        "redirects": redirect_handler.redirects,
        "headers": {key: clean_text(value)[:1000] for key, value in headers.items()},
        "technologies": technologies,
    }


def resolve_web_target(target_url: str) -> dict:
    """Resolve apenas endereços do host informado e testa um deles na porta da URL."""
    parsed = parse_web_target(validate_web_url(target_url))
    hostname, port = parsed["hostname"], parsed["port"]
    try:
        addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("DNS não resolvido. Confira o hostname e a conexão de rede.") from exc
    if not addresses:
        raise ValueError("DNS não retornou endereços para esse hostname.")
    addresses.sort(key=lambda item: item[0] != socket.AF_INET)
    selected = addresses[0]
    try:
        connection = socket.create_connection((selected[4][0], port), timeout=CONNECT_TIMEOUT)
        connection.close()
    except OSError as exc:
        raise ValueError("Não foi possível conectar ao host e à porta informados.") from exc
    return {"host": hostname, "address": selected[4][0], "port": port,
            "protocol": parsed["protocol"], "path": parsed["path"]}


def _tool_failure(name: str, target_url: str, exc: Exception) -> dict:
    return {"tool": name, "url": target_url, "status": "erro", "execution_status": "failed",
            "message": clean_text(str(exc))[:500] or "Falha não detalhada.",
            "started_at": now_iso(), "finished_at": now_iso()}


def run_web_scan(target_url: str, *, nuclei_settings: dict | None = None,
                 progress_callback: Callable[[str], None] | None = None) -> dict:
    """Executa verificações passivas/limitadas e reporta o escopo da URL original."""
    started_at = now_iso()
    started_clock = time.monotonic()
    try:
        target_url = validate_web_url(target_url)
        if progress_callback:
            progress_callback("Resolvendo hostname e verificando conectividade...")
        target = resolve_web_target(target_url)
    except ValueError as exc:
        return {"target_url": target_url, "status": "erro", "started_at": started_at,
                "finished_at": now_iso(), "message": str(exc), "tools": [],
                "nuclei_findings": [], "nuclei_severity_counts": {}, "execution_status": "failed"}

    if progress_callback:
        progress_callback("Identificando serviço HTTP e redirecionamentos...")
    probe = _http_probe(target_url)
    if probe["status"] != "conectado":
        return {"target_url": target_url, "address": target["address"], "status": probe["status"],
                "started_at": started_at, "finished_at": now_iso(), "http": probe,
                "tools": [], "nuclei_findings": [], "nuclei_severity_counts": {}, "execution_status": "failed",
                "message": probe.get("message", "Falha na verificação HTTP.")}

    tools = []
    for name, runner in (("ZAP Automation Framework", run_zap), ("Nikto", run_nikto)):
        if progress_callback:
            progress_callback(f"Executando {name}...")
        try:
            tool_result = runner(target_url)
        except Exception as exc:
            tool_result = _tool_failure(name, target_url, exc)
        tool_result.setdefault("execution_status", execution_state(tool_result))
        tool_result.setdefault("duration_ms", duration_ms(tool_result) or 0)
        tools.append(tool_result)

    settings = validate_nuclei_settings(nuclei_settings or {})
    if settings["enabled"]:
        if progress_callback:
            progress_callback("Executando Nuclei...")
        try:
            nuclei_result = run_nuclei(target_url, timeout=settings["timeout"],
                executable=settings["executable_path"] or None,
                templates_dir=settings["templates_directory"] or None,
                rate_limit=settings["rate_limit"], concurrency=settings["concurrency"],
                progress_callback=progress_callback)
        except Exception as exc:
            nuclei_result = _tool_failure("Nuclei", target_url, exc)
            nuclei_result.update(findings=[], severity_counts={})
    else:
        nuclei_result = {"tool": "Nuclei", "target": target_url, "status": "desativado",
            "started_at": now_iso(), "finished_at": now_iso(),
            "message": "Nuclei está desativado nas configurações.", "findings": [], "severity_counts": {}}
    nuclei_findings = nuclei_result.get("findings", [])
    nuclei_counts = nuclei_result.get("severity_counts", {})
    if nuclei_result.get("status") != "concluído" and not nuclei_findings:
        nuclei_counts = {}
    nuclei_result.setdefault("execution_status", execution_state(nuclei_result))
    nuclei_result.setdefault("duration_ms", duration_ms(nuclei_result) or 0)
    tools.append({key: value for key, value in nuclei_result.items() if key != "findings"})
    all_findings = list(nuclei_findings)
    for tool in tools:
        for finding in tool.get("alerts", []) + tool.get("findings", []):
            if isinstance(finding, dict):
                all_findings.append(finding)
    sections = report_sections(all_findings, tools)
    states = [execution_state(tool) for tool in tools]
    overall = "partial" if any(state in {"failed", "partial", "timeout", "skipped"} for state in states) else "completed"
    return {"target_url": target_url, "address": target["address"], "target": target,
        "http": probe, "status": "concluído" if overall == "completed" else "parcial",
        "execution_status": overall, "started_at": started_at, "finished_at": now_iso(),
        "duration_ms": int((time.monotonic() - started_clock) * 1000),
        "tools": tools, "nuclei_findings": nuclei_findings, "nuclei_severity_counts": nuclei_counts,
        **sections, "message": "Alertas são indícios da ferramenta; revise evidências antes de confirmar vulnerabilidades."}
