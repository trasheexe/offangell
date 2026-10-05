import importlib.util
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from core.reports import now_iso
from core.validation import build_web_url

NMAP_PATHS = (
    "nmap",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
)
NIKTO_PATHS = (
    "nikto",
    "nikto.pl",
    r"C:\nikto\program\nikto.pl",
    r"C:\Program Files\Nikto\program\nikto.pl",
    "/usr/bin/nikto",
    "/usr/local/bin/nikto",
    "/usr/share/nikto/program/nikto.pl",
    "/usr/share/nikto/nikto.pl",
)
ZAP_PATHS = (
    "zap-baseline.py",
    r"C:\zap\zap-baseline.py",
    r"C:\Program Files\ZAP\Zed Attack Proxy\zap-baseline.py",
    r"C:\Program Files\OWASP\Zed Attack Proxy\zap-baseline.py",
    "/zap/zap-baseline.py",
    "/usr/local/bin/zap-baseline.py",
    "/usr/share/zaproxy/zap-baseline.py",
)
PERL_PATHS = ("perl", r"C:\Strawberry\perl\bin\perl.exe", "/usr/bin/perl", "/usr/local/bin/perl")
TOOL_TIMEOUT = 600


def find_executable(candidates: tuple[str, ...], *, scripts: bool = False) -> str | None:
    """Busca no PATH e em caminhos conhecidos, sem executar a ferramenta."""
    for candidate in candidates:
        found = shutil.which(candidate)
        if found and Path(found).suffix.lower() not in {".bat", ".cmd"}:
            return str(Path(found).resolve())
        path = Path(candidate).expanduser()
        if not path.is_absolute() or not path.is_file():
            continue
        if scripts and path.suffix.lower() in {".py", ".pl"}:
            return str(path.resolve())
        if path.suffix.lower() not in {".bat", ".cmd"} and os.access(path, os.X_OK):
            return str(path.resolve())
    # Scripts .py/.pl podem não ter bit executável ou associação PATHEXT.
    if scripts:
        for folder in os.get_exec_path():
            if not folder:
                continue
            for candidate in candidates:
                if Path(candidate).name != candidate or Path(candidate).suffix.lower() not in {
                    ".py",
                    ".pl",
                }:
                    continue
                path = Path(folder) / candidate
                if path.is_file():
                    return str(path.resolve())
    return None


def script_command(path: str) -> list[str] | None:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return [sys.executable, path]
    if suffix == ".pl":
        perl = find_executable(PERL_PATHS)
        return [perl, path] if perl else None
    if os.name == "nt" and suffix != ".exe":
        # Nikto costuma ser um script Perl sem extensão em distribuições Unix.
        perl = find_executable(PERL_PATHS)
        return [perl, path] if perl else None
    return [path]


def dependency_status() -> list[tuple[str, bool, str]]:
    rows = [("Python", True, sys.version.split()[0])]
    for module, label in (("nmap", "python-nmap"), ("colorama", "colorama")):
        present = importlib.util.find_spec(module) is not None
        rows.append((label, present, "disponível" if present else "instale requirements.txt"))
    for label, paths in (("Nmap", NMAP_PATHS), ("Nikto", NIKTO_PATHS), ("ZAP Baseline", ZAP_PATHS)):
        path = find_executable(paths, scripts=label != "Nmap")
        ready = bool(path and (label == "Nmap" or script_command(path)))
        detail = path or "não encontrado"
        if path and not ready:
            detail = "script encontrado, mas Perl não foi encontrado"
        if ready and label == "ZAP Baseline":
            detail += " (script localizado; requer ambiente ZAP configurado)"
        rows.append((label, ready, detail))
    return rows


def process_options() -> dict:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def stop_process(process: subprocess.Popen) -> bool:
    """Encerra a árvore iniciada por esta sessão em cancelamentos/timeouts."""
    if process.poll() is not None:
        return True
    try:
        if os.name == "nt":
            taskkill = (
                Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
            )
            subprocess.run(
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            return False
    return True


def run_command(command: list[str], *, timeout: int = TOOL_TIMEOUT) -> dict:
    """Exibe saída no terminal e registra somente o estado, sem conteúdo sensível."""
    result = {"started_at": now_iso(), "status": "erro", "returncode": None}
    process = None
    try:
        process = subprocess.Popen(command, shell=False, **process_options())
        result["returncode"] = process.wait(timeout=timeout)
        result["status"] = "concluído" if result["returncode"] == 0 else "erro"
        result["message"] = f"Processo encerrado com código {result['returncode']}."
    except FileNotFoundError:
        result["message"] = "Executável ou interpretador não encontrado. Verifique a instalação."
    except PermissionError:
        result["message"] = "Permissão insuficiente para executar a ferramenta."
    except subprocess.TimeoutExpired:
        result.update(status="timeout", message=f"Tempo limite de {timeout} segundos excedido.")
    except KeyboardInterrupt:
        result.update(status="cancelado", message="Análise cancelada com Ctrl+C.")
    except OSError as exc:
        result["message"] = f"Não foi possível iniciar a ferramenta: {exc}"
    finally:
        if process is not None:
            if not stop_process(process):
                result["message"] += (
                    " Não foi possível encerrar o processo; confira os processos ativos."
                )
        result["finished_at"] = now_iso()
    return result


def run_nikto(target: str, port: int, service: str | dict = "") -> dict:
    url = build_web_url(target, port, service)
    path = find_executable(NIKTO_PATHS, scripts=True)
    command = script_command(path) if path else None
    if not command:
        return {
            "tool": "Nikto",
            "port": port,
            "started_at": now_iso(),
            "status": "indisponível",
            "message": "Nikto não encontrado ou Perl ausente. Instale o Nikto e tente novamente. Essa função é opcional.",
        }
    # Somente testes de configuração e identificação; sem plugins de ataque.
    result = run_command(
        [*command, "-h", url, "-Tuning", "2b", "-Plugins", "headers;tests", "-nointeractive"]
    )
    return {
        **result,
        "tool": "Nikto",
        "port": port,
        "url": url,
        "profile": "configuração e identificação (2b)",
    }


def run_zap(target: str, port: int, service: str | dict = "") -> dict:
    url = build_web_url(target, port, service)
    path = find_executable(ZAP_PATHS, scripts=True)
    if not path:
        return {
            "tool": "ZAP Baseline",
            "port": port,
            "started_at": now_iso(),
            "status": "indisponível",
            "message": "ZAP Baseline não encontrado. Você ainda pode utilizar Nmap, Banner Grabbing, NSE e Nikto, se instalado.",
        }
    command = script_command(path)
    # -h carrega os módulos do Baseline, mas não inicia ZAP nem acessa o alvo.
    try:
        check = subprocess.run(
            [*command, "-h"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "tool": "ZAP Baseline",
            "port": port,
            "started_at": now_iso(),
            "status": "indisponível",
            "message": f"Não foi possível verificar o ambiente do ZAP Baseline: {exc}",
        }
    if check.returncode != 0:
        return {
            "tool": "ZAP Baseline",
            "port": port,
            "started_at": now_iso(),
            "status": "indisponível",
            "message": "Script Baseline encontrado, mas seu ambiente não está pronto. Confira zap_common.py e as dependências do ZAP no Python usado pelo OFF ANGELL.",
        }
    result = run_command([*command, "-t", url, "-m", "1", "-T", "5"])
    if result["returncode"] in {1, 2} and result["status"] == "erro":
        result.update(
            status="alertas",
            message="ZAP retornou alertas; revise a saída. Isso não confirma vulnerabilidades.",
        )
    return {**result, "tool": "ZAP Baseline", "port": port, "url": url}
