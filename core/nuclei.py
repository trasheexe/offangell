import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from core import tools as tool_utils
from core.reports import clean_text, now_iso
from core.validation import validate_target, validate_web_url

NUCLEI_PATHS = tool_utils.NUCLEI_PATHS
TEMPLATE_ALLOWLIST = frozenset({"http-missing-security-headers", "tech-detect"})
EXCLUDED_TAGS = (
    "dos,brute,brute-force,fuzz,fuzzer,intrusive,headless,file,code,interactsh,oast,"
    "network,dns,javascript,workflow,external,exploit,malware,broadcast,default-login,"
    "creds-stuffing"
)
REQUIRED_SCAN_FLAGS = (
    "jsonl",
    "no-color",
    "omit-raw",
    "rate-limit",
    "concurrency",
    "bulk-size",
    "timeout",
    "retries",
    "max-host-error",
    "no-interactsh",
    "disable-update-check",
    "disable-unsigned-templates",
    "disable-redirects",
    "exclude-tags",
    "include-templates",
    "templates",
)
SEVERITY_MAP = {
    "info": "Informational",
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
    "unknown": "Unknown",
}
BLOCKED_YAML_KEYS = {
    "attack",
    "code",
    "dns",
    "file",
    "flow",
    "fuzz",
    "fuzzing",
    "headless",
    "interactsh",
    "javascript",
    "network",
    "payloads",
    "raw",
    "self-contained",
    "tcp",
    "unsafe",
    "variables",
    "websocket",
}


def find_nuclei(custom_path: str | None = None) -> str | None:
    if custom_path and custom_path.strip():
        return tool_utils.find_executable(NUCLEI_PATHS, configured_path=custom_path.strip(), scripts=True)
    return tool_utils.find_tool_executable("nuclei", NUCLEI_PATHS)


def _decode_output(value: bytes | str | None) -> str:
    if isinstance(value, str):
        return value
    if not value:
        return ""
    try:
        return value.decode("utf-8-sig")
    except UnicodeDecodeError:
        return value.decode("mbcs" if os.name == "nt" else "utf-8", errors="replace")


def _call_help(executable: str) -> tuple[str, str | None]:
    try:
        result = subprocess.run(
            [executable, "-h"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return "", "O Nuclei não respondeu ao comando -h dentro de 15 segundos."
    except OSError as exc:
        return "", f"Não foi possível consultar as opções do Nuclei: {clean_text(str(exc))}"
    output = _decode_output(result.stdout)
    if result.returncode != 0:
        return output, "Não foi possível ler as opções do Nuclei instalado."
    return output, None


def _has_flag(help_text: str, flag: str) -> bool:
    return re.search(r"(?<![\w-])-[\w-]*\b" + re.escape(flag) + r"\b", help_text) is not None


def check_nuclei_version(executable: str | None = None) -> dict:
    """Consulta versão e opções reais antes de montar uma linha de comando segura."""
    path = executable or find_nuclei()
    if not path:
        return {
            "status": "indisponível",
            "path": None,
            "version": None,
            "missing_flags": list(REQUIRED_SCAN_FLAGS),
            "message": "Nuclei não encontrado. Instale o binário oficial ou configure o caminho.",
        }
    try:
        version_result = subprocess.run(
            [path, "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "erro",
            "path": path,
            "version": None,
            "missing_flags": [],
            "message": "Timeout ao verificar a versão do Nuclei.",
        }
    except OSError as exc:
        return {
            "status": "erro",
            "path": path,
            "version": None,
            "missing_flags": [],
            "message": f"Falha ao verificar Nuclei: {clean_text(str(exc))}",
        }
    version_output = _decode_output(version_result.stdout)
    if version_result.returncode != 0:
        return {
            "status": "erro",
            "path": path,
            "version": None,
            "missing_flags": [],
            "message": "O comando de versão do Nuclei falhou.",
        }
    match = re.search(r"(?i)\bv?\d+\.\d+(?:\.\d+)?(?:[-+][\w.-]+)?\b", version_output)
    version = match.group(0) if match else clean_text(version_output.strip())[:120]
    help_text, help_error = _call_help(path)
    if help_error:
        return {
            "status": "erro",
            "path": path,
            "version": version,
            "missing_flags": [],
            "message": help_error,
        }
    missing_flags = [flag for flag in REQUIRED_SCAN_FLAGS if not _has_flag(help_text, flag)]
    if missing_flags:
        return {
            "status": "incompatível",
            "path": path,
            "version": version,
            "missing_flags": missing_flags,
            "message": "Esta versão do Nuclei não oferece todas as opções exigidas pelo perfil seguro.",
        }
    return {
        "status": "concluído",
        "path": path,
        "version": version,
        "missing_flags": [],
        "help_text": help_text,
        "message": f"Nuclei {version} pronto.",
    }


def _candidate_template_directories() -> list[Path]:
    candidates = []
    configured = os.environ.get("NUCLEI_TEMPLATES_DIR")
    if configured:
        candidates.append(Path(configured).expanduser())
    home = Path.home()
    candidates.extend(_saved_template_directories())
    xdg_data_home = Path(os.environ.get("XDG_DATA_HOME", str(home / ".local" / "share")))
    candidates.append(xdg_data_home / "nuclei" / "nuclei-templates")
    xdg_data_dirs = os.environ.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share")
    candidates.extend(
        Path(folder) / "nuclei" / "nuclei-templates"
        for folder in xdg_data_dirs.split(os.pathsep)
        if folder
    )
    candidates.extend((home / "nuclei-templates", home / ".local" / "nuclei-templates"))
    if os.name == "nt":
        profile = os.environ.get("USERPROFILE")
        if profile:
            candidates.insert(0, Path(profile) / "nuclei-templates")
        for variable in ("LOCALAPPDATA", "APPDATA"):
            root = os.environ.get(variable)
            if root:
                candidates.append(Path(root) / "nuclei" / "nuclei-templates")
    return candidates


def _saved_template_directories() -> list[Path]:
    home = Path.home()
    state_home = Path(os.environ.get("XDG_STATE_HOME", str(home / ".local" / "state")))
    state_files = [state_home / "nuclei" / "templates.json", home / ".templates-config.json"]
    if os.name == "nt":
        for variable in ("LOCALAPPDATA", "APPDATA"):
            root = os.environ.get(variable)
            if root:
                state_files.append(Path(root) / "nuclei" / "templates.json")
    paths = []

    def collect(value, key_hint=""):
        if isinstance(value, dict):
            for key, child in value.items():
                collect(child, str(key).lower())
        elif isinstance(value, list):
            for child in value:
                collect(child, key_hint)
        elif isinstance(value, str) and ("template" in key_hint or key_hint in {"path", "directory"}):
            candidate = Path(value).expanduser()
            if candidate.is_dir():
                paths.append(candidate)

    for state_file in state_files:
        try:
            if state_file.stat().st_size > 1_000_000:
                continue
            collect(json.loads(state_file.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
    return paths


def _find_template_directory(templates_dir: str | Path | None = None) -> Path | None:
    if templates_dir:
        path = Path(templates_dir).expanduser()
        return path.resolve() if path.is_dir() else None
    for path in _candidate_template_directories():
        if path.is_dir():
            return path.resolve()
    return None


def check_nuclei_templates(templates_dir: str | Path | None = None) -> dict:
    path = _find_template_directory(templates_dir)
    if path is None:
        return {
            "found": False,
            "path": str(templates_dir) if templates_dir else None,
            "count": 0,
            "message": "[!] Templates do Nuclei não encontrados.",
        }
    try:
        count = sum(
            1
            for suffix in ("*.yaml", "*.yml")
            for item in path.rglob(suffix)
            if item.is_file() and not item.is_symlink()
        )
    except OSError:
        count = 0
    if not count:
        return {
            "found": False,
            "path": str(path),
            "count": 0,
            "message": "[!] Templates do Nuclei não encontrados.",
        }
    return {
        "found": True,
        "path": str(path),
        "count": count,
        "message": f"{count} arquivo(s) de template encontrado(s).",
    }


def _nested_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key).lower()
            yield from _nested_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _nested_keys(item)


def _template_is_safe(template: dict) -> bool:
    if not isinstance(template, dict) or template.get("id") not in TEMPLATE_ALLOWLIST:
        return False
    info = template.get("info")
    if not isinstance(info, dict):
        return False
    if str(info.get("severity", "")).lower() not in {"info", "informational"}:
        return False
    tags = info.get("tags", [])
    if isinstance(tags, str):
        tags = [tag.strip().lower() for tag in tags.split(",")]
    elif isinstance(tags, list):
        tags = [str(tag).strip().lower() for tag in tags]
    else:
        return False
    if any(tag in EXCLUDED_TAGS.split(",") for tag in tags):
        return False
    if set(_nested_keys(template)) & BLOCKED_YAML_KEYS:
        return False
    if template.get("type", "http") != "http":
        return False
    if any(key not in {"id", "info", "http", "requests", "metadata", "type"} for key in template):
        return False
    requests = template.get("http", template.get("requests"))
    if not isinstance(requests, list) or len(requests) != 1:
        return False
    request = requests[0]
    if not isinstance(request, dict):
        return False
    allowed_request_keys = {
        "method",
        "path",
        "matchers-condition",
        "matchers",
        "host-redirects",
        "max-redirects",
        "redirects",
        "stop-at-first-match",
    }
    if set(request) - allowed_request_keys:
        return False
    method = str(request.get("method", "GET")).upper()
    if method not in {"GET", "HEAD"}:
        return False
    paths = request.get("path", [])
    if isinstance(paths, str):
        paths = [paths]
    if not isinstance(paths, list) or paths != ["{{BaseURL}}"]:
        return False
    metadata = info.get("metadata") or template.get("metadata") or {}
    if not isinstance(metadata, dict):
        return False
    max_requests = metadata.get("max-request", metadata.get("max-request-count", 1))
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or max_requests > 1:
        return False
    return True


def _safe_template_files(directory: Path) -> list[Path]:
    import yaml

    root = directory.resolve()
    candidates: dict[str, list[Path]] = {template_id: [] for template_id in TEMPLATE_ALLOWLIST}
    for template_id in sorted(TEMPLATE_ALLOWLIST):
        for suffix in (".yaml", ".yml"):
            for path in root.rglob(f"{template_id}{suffix}"):
                if not path.is_file() or path.is_symlink():
                    continue
                try:
                    if not path.resolve().is_relative_to(root) or path.stat().st_size > 1_000_000:
                        continue
                    document = yaml.safe_load(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, yaml.YAMLError):
                    continue
                if isinstance(document, dict) and document.get("id") == template_id:
                    if _template_is_safe(document):
                        candidates[template_id].append(path.resolve())
    # Um ID duplicado é ambíguo e pode ocultar um template substituído.
    return [paths[0] for paths in candidates.values() if len(paths) == 1]


def parse_nuclei_results(output: str | bytes) -> list[dict]:
    """Interpreta JSONL válido e omite qualquer request/response bruto."""
    text = _decode_output(output)
    results = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(raw, dict):
            continue
        info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
        template_id = raw.get("template-id") or raw.get("template_id")
        if not isinstance(template_id, str) or not template_id:
            continue
        severity_raw = str(info.get("severity") or "unknown").strip().lower()
        severity = SEVERITY_MAP.get(severity_raw, "Unknown")
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
        elif isinstance(tags, list):
            tags = [clean_text(str(tag)) for tag in tags]
        else:
            tags = []
        extracted = raw.get("extracted-results", raw.get("extracted_results", []))
        if isinstance(extracted, str):
            extracted = [extracted]
        if not isinstance(extracted, list):
            extracted = []
        timestamp = raw.get("timestamp") or now_iso()
        if isinstance(timestamp, datetime):
            timestamp = timestamp.astimezone().isoformat(timespec="seconds")
        reference = info.get("reference") or []
        if isinstance(reference, str):
            reference = [reference]
        elif not isinstance(reference, list):
            reference = []
        matched_at = raw.get("matched-at") or raw.get("matched_at") or raw.get("host") or ""
        results.append(
            {
                "tool": "Nuclei",
                "template_id": clean_text(template_id),
                "template_name": clean_text(str(info.get("name") or template_id)),
                "matched_at": clean_text(str(matched_at)),
                "host": clean_text(str(raw.get("host") or "")),
                "type": clean_text(str(raw.get("type") or "")),
                "severity": severity,
                "tags": tags,
                "description": clean_text(str(info.get("description") or "")),
                "recommendation": clean_text(str(info.get("remediation") or info.get("solution") or "")),
                "extracted_results": [clean_text(str(item)) for item in extracted],
                "reference": [clean_text(str(item)) for item in reference],
                "timestamp": clean_text(str(timestamp)),
                "status": "indício; requer validação manual",
            }
        )
    return deduplicate_nuclei_findings(results)


def deduplicate_nuclei_findings(findings: list[dict]) -> list[dict]:
    """Merge repeated JSONL rows while retaining distinct evidence and occurrence counts."""
    merged: dict[tuple[str, str, str, str, str], dict] = {}
    for finding in findings:
        extracted = finding.get("extracted_results", [])
        evidence_type = str(finding.get("type") or "")
        # The extracted value distinguishes multiple individual headers or resources
        # reported by the same broad template at the same URL.
        evidence_signature = "|".join(sorted(_norm_evidence(item) for item in extracted))
        key = (
            str(finding.get("template_id") or ""), str(finding.get("host") or "").casefold(),
            str(finding.get("matched_at") or "").casefold(), evidence_type.casefold(), evidence_signature,
        )
        if key not in merged:
            merged[key] = {**finding, "occurrence_count": 1, "occurrences": [finding.get("timestamp")],
                           "evidence": list(extracted)}
            continue
        existing = merged[key]
        existing["occurrence_count"] += 1
        existing["occurrences"].append(finding.get("timestamp"))
        existing["evidence"] = list(dict.fromkeys(existing["evidence"] + list(extracted)))
        existing["extracted_results"] = existing["evidence"]
    return list(merged.values())


def _norm_evidence(value: object) -> str:
    return " ".join(str(value or "").casefold().split())


def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {name: 0 for name in ("Critical", "High", "Medium", "Low", "Informational", "Unknown")}
    for finding in findings:
        severity = finding.get("severity", "Unknown")
        counts[severity if severity in counts else "Unknown"] += 1
    return counts


def _same_origin(first: str, second: str) -> bool:
    try:
        left, right = urlsplit(first), urlsplit(second)
        left_port = left.port or (443 if left.scheme.lower() == "https" else 80)
        right_port = right.port or (443 if right.scheme.lower() == "https" else 80)
        return (
            left.scheme.lower(), validate_target(left.hostname or ""), left_port
        ) == (
            right.scheme.lower(), validate_target(right.hostname or ""), right_port
        )
    except ValueError:
        return False


def _decode_jsonl_scope(findings: list[dict], target: str) -> tuple[list[dict], int]:
    in_scope = []
    rejected = 0
    for finding in findings:
        matched_at = finding.get("matched_at") or target
        if _same_origin(matched_at, target):
            in_scope.append(finding)
        else:
            rejected += 1
    return in_scope, rejected


def _progress(callback: Callable[[str], None] | None, message: str) -> None:
    if callback:
        callback(message)


def _base_result(target: str, status: str, message: str, **extra) -> dict:
    from core.analysis import EXECUTION_STATES
    if status in EXECUTION_STATES:
        state = status
    elif "indispon" in status.casefold() or "desativ" in status.casefold():
        state = "skipped"
    elif "timeout" in status.casefold():
        state = "timeout"
    elif "parcial" in status.casefold() or status.casefold() == "partial":
        state = "partial"
    elif status.casefold().startswith("conclu"):
        state = "completed"
    else:
        state = "failed"
    return {
        "tool": "Nuclei",
        "target": target,
        "status": status,
        "execution_status": state,
        "started_at": now_iso(),
        "finished_at": now_iso(),
        "message": message,
        "findings": [],
        "severity_counts": {},
        **extra,
    }


def run_nuclei(
    target: str,
    timeout: int = 600,
    *,
    executable: str | None = None,
    templates_dir: str | Path | None = None,
    rate_limit: int = 2,
    concurrency: int = 2,
    progress_callback: Callable[[str], None] | None = None,
) -> dict:
    """Executa somente o conjunto verificado e permitido pelo perfil padrão."""
    try:
        target = validate_web_url(target)
    except ValueError as exc:
        return _base_result(str(target), "erro", str(exc))
    for value, name, lower, upper in (
        (timeout, "timeout", 1, 600),
        (rate_limit, "rate_limit", 1, 5),
        (concurrency, "concurrency", 1, 2),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
            return _base_result(target, "erro", f"Configuração {name} fora dos limites seguros.")
    _progress(progress_callback, "Inicializando Nuclei...")
    path = find_nuclei(executable)
    if not path:
        return _base_result(
            target,
            "indisponível",
            "Nuclei não encontrado. Instale o binário oficial ou configure o caminho.",
        )
    version = check_nuclei_version(path)
    if version["status"] != "concluído":
        return _base_result(target, version["status"], version["message"], nuclei_version=version.get("version"))
    _progress(progress_callback, "Verificando templates...")
    templates = check_nuclei_templates(templates_dir)
    if not templates["found"]:
        return _base_result(target, "indisponível", templates["message"], nuclei_version=version["version"])
    try:
        safe_templates = _safe_template_files(Path(templates["path"]))
    except ImportError:
        return _base_result(
            target,
            "indisponível",
            "PyYAML ausente. Instale as dependências do OFF ANGELL para validar templates com segurança.",
            nuclei_version=version["version"],
        )
    if not safe_templates:
        return _base_result(
            target,
            "indisponível",
            "Nenhum template da allowlist segura passou pela inspeção local.",
            nuclei_version=version["version"],
            templates_directory=templates["path"],
        )
    _progress(progress_callback, "Aplicando política de templates seguros...")
    command = [path, "-u", target, "-jsonl", "-no-color", "-omit-raw"]
    for template_path in safe_templates:
        command.extend(
            ["-templates", str(template_path), "-include-templates", str(template_path)]
        )
    command.extend(
        [
            "-rate-limit",
            str(rate_limit),
            "-concurrency",
            str(concurrency),
            "-bulk-size",
            "1",
            "-timeout",
            "8",
            "-retries",
            "1",
            "-max-host-error",
            "5",
            "-no-interactsh",
            "-disable-update-check",
            "-disable-unsigned-templates",
            "-disable-redirects",
            "-exclude-tags",
            EXCLUDED_TAGS,
        ]
    )
    _progress(progress_callback, "Executando verificações...")
    process = None
    stdout_text = ""
    stderr_text = ""
    status = "erro"
    message = "Falha ao executar Nuclei."
    returncode = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            **tool_utils.process_options(),
        )
        stdout, stderr = process.communicate(timeout=timeout)
        stdout_text = _decode_output(stdout)
        stderr_text = _decode_output(stderr)
        returncode = process.returncode
        if returncode == 0:
            status = "concluído"
            message = "Nuclei finalizado."
        else:
            status = "erro"
            message = f"Nuclei terminou com código {returncode}; revise a instalação e os templates."
    except subprocess.TimeoutExpired as exc:
        stdout_text = _decode_output(exc.output)
        stderr_text = _decode_output(exc.stderr)
        status = "timeout"
        message = f"Timeout global de {timeout} segundos excedido."
    except FileNotFoundError:
        status = "indisponível"
        message = "O executável do Nuclei não foi encontrado ao iniciar o scan."
    except PermissionError:
        status = "erro"
        message = "Permissão insuficiente para executar Nuclei."
    except OSError as exc:
        status = "erro"
        message = f"Falha ao iniciar Nuclei: {clean_text(str(exc))}"
    finally:
        if process is not None:
            tool_utils.stop_process(process)
    _progress(progress_callback, "Processando resultados...")
    parsed = parse_nuclei_results(stdout_text)
    findings, out_of_scope = _decode_jsonl_scope(parsed, target)
    internal_error = bool(re.search(r"(?im)^\s*(?:error|fatal):", stderr_text))
    if status.casefold().startswith("conclu") and internal_error:
        status = "parcial" if findings else "erro"
        message = "Nuclei reportou erro interno apesar do c\u00f3digo de sa\u00edda zero."
    if status == "concluído" and re.search(
        r"templates loaded for current scan:\s*0|no templates found",
        stderr_text,
        flags=re.IGNORECASE,
    ):
        status = "indisponível"
        message = "Nenhum template assinado da allowlist foi carregado pelo Nuclei."
    _progress(progress_callback, "Nuclei finalizado.")
    return {
        "tool": "Nuclei",
        "target": target,
        "status": status,
        "execution_status": ("timeout" if status == "timeout" else "skipped" if "indispon" in status.casefold() else
                             "completed" if returncode == 0 and not internal_error and "nenhum template" not in message.casefold() else
                             "partial" if findings else "failed"),
        "started_at": now_iso(),
        "finished_at": now_iso(),
        "returncode": returncode,
        "nuclei_version": version["version"],
        "templates_directory": templates["path"],
        "templates_selected": [path.name for path in safe_templates],
        "message": message,
        "findings": findings,
        "severity_counts": severity_counts(findings),
        "invalid_jsonl_lines": sum(
            1
            for line in stdout_text.splitlines()
            if line.strip() and _is_invalid_json(line)
        ),
        "out_of_scope_findings": out_of_scope,
        "stdout": clean_text(stdout_text),
        "stderr": clean_text(stderr_text),
    }


def _is_invalid_json(line: str) -> bool:
    try:
        json.loads(line)
        return False
    except (json.JSONDecodeError, TypeError):
        return True


def update_nuclei_templates(
    *,
    confirm: bool = False,
    executable: str | None = None,
    templates_dir: str | Path | None = None,
    timeout: int = 600,
) -> dict:
    """Atualiza templates somente após uma confirmação explícita do chamador."""
    if confirm is not True:
        return {"status": "cancelado", "message": "Atualização cancelada; nenhuma alteração foi feita."}
    path = find_nuclei(executable)
    if not path:
        return {"status": "indisponível", "message": "Nuclei não encontrado."}
    help_text, error = _call_help(path)
    if error:
        return {"status": "erro", "message": error}
    command = [path, "-update-templates"]
    if templates_dir:
        if not _has_flag(help_text, "update-template-dir"):
            return {
                "status": "incompatível",
                "message": "Esta versão do Nuclei não permite escolher o diretório de atualização.",
            }
        command.extend(["-update-template-dir", str(Path(templates_dir).expanduser())])
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "message": f"Timeout ao atualizar templates após {timeout} segundos."}
    except OSError as exc:
        return {"status": "erro", "message": f"Falha ao atualizar templates: {clean_text(str(exc))}"}
    status = "concluído" if result.returncode == 0 else "erro"
    output = clean_text(_decode_output(result.stdout).strip())[:1000]
    return {
        "status": status,
        "returncode": result.returncode,
        "message": output or ("Templates atualizados." if status == "concluído" else "Falha na atualização."),
    }
