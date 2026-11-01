import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path, PureWindowsPath
import yaml

from core.reports import clean_text, now_iso
from core.validation import build_web_url, validate_web_url
from core.config import PERL_PATHS as CONFIG_PERL_PATHS

NMAP_PATHS = (
    "nmap.exe",
    "nmap",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
)
NIKTO_PATHS = (
    "nikto.exe",
    "nikto.pl",
    "nikto.bat",
    "nikto.cmd",
    "nikto.ps1",
    "nikto",
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
ZAP_EXECUTABLE_PATHS = ("ZAP.exe", "zap.exe", "zap.bat", "zap.cmd", r"C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe")
NUCLEI_PATHS = ("nuclei.exe", "nuclei", r"C:\Program Files\Nuclei\nuclei.exe", r"C:\Program Files (x86)\Nuclei\nuclei.exe", r"C:\Nuclei\nuclei.exe", "/usr/bin/nuclei", "/usr/local/bin/nuclei")
PERL_PATHS = ("perl.exe", "perl", *CONFIG_PERL_PATHS, "/usr/bin/perl", "/usr/local/bin/perl")
JAVA_PATHS = ("java.exe", "java", r"C:\Program Files\Java\bin\java.exe", r"C:\Program Files\Eclipse Adoptium\jdk\bin\java.exe", r"C:\Program Files\Eclipse Adoptium\jre-17.0.20.101-hotspot\bin\java.exe")
ZAP_LAUNCHER_PATHS = ("zap.bat", "zap.cmd", "zap.sh")
ZAP_JAR_PATHS = ("zap.jar",)
POWERSHELL_PATHS = ("pwsh.exe", "powershell.exe", "pwsh", "powershell")
MSF_PATHS = ("msfconsole.exe", "msfconsole", r"C:\Program Files\msf\bin\msfconsole.exe", "/opt/metasploit-framework/bin/msfconsole")
TOOL_CANDIDATES = {"nmap": NMAP_PATHS, "nuclei": NUCLEI_PATHS, "zap_baseline": ZAP_PATHS, "zap": ZAP_EXECUTABLE_PATHS, "zap_launcher": ZAP_LAUNCHER_PATHS, "zap_jar": ZAP_JAR_PATHS, "nikto": NIKTO_PATHS, "java": JAVA_PATHS, "perl": PERL_PATHS, "powershell": POWERSHELL_PATHS, "metasploit": MSF_PATHS}
MAX_TOOLS_SEARCH_DEPTH = 5
TOOL_TIMEOUT = 600
MAX_CAPTURE_BYTES = 64 * 1024


def _perl_environment(perl: str) -> dict[str, str]:
    """Expose colocated Perl/CPAN runtime DLLs to child Perl processes only."""
    from core.config import TOOLS_ROOT

    env = os.environ.copy()
    perl_path = Path(perl).resolve()
    root = perl_path.parent.parent
    tools_root = Path(TOOLS_ROOT)
    additions = [perl_path.parent, root / "c" / "bin", tools_root / "c" / "bin"]
    if tools_root.is_dir():
        try:
            # Portable distributions may keep runtime DLLs in a sibling cpan/c/bin.
            additions.extend(child / "c" / "bin" for child in tools_root.iterdir())
        except OSError:
            pass
    existing = []
    for folder in additions:
        if folder.is_dir() and str(folder).casefold() not in {item.casefold() for item in existing}:
            existing.append(str(folder))
    env["PATH"] = os.pathsep.join(existing + [env.get("PATH", "")])
    # Strawberry Perl on Windows does not recognize a POSIX C.UTF-8 locale.
    # Use a portable C locale for this child to avoid warnings corrupting reports.
    env.update({"LC_ALL": "C", "LC_CTYPE": "C", "LANG": "C"})
    return env


def _candidate_names(candidates: tuple[str, ...]) -> list[str]:
    names = []
    for candidate in candidates:
        for name in (PureWindowsPath(str(candidate)).name, Path(str(candidate)).name):
            if name and name.casefold() not in names:
                names.append(name.casefold())
    return names


def _walk_for_name(root: Path, name: str) -> str | None:
    if not root.is_dir():
        return None
    wanted = name.casefold()
    for folder, dirs, files in os.walk(root):
        current = Path(folder)
        try:
            depth = len(current.relative_to(root).parts)
        except ValueError:
            continue
        dirs[:] = [item for item in dirs if item.casefold() not in {".git", "__pycache__", "node_modules", "site-packages"}]
        if depth >= MAX_TOOLS_SEARCH_DEPTH:
            dirs[:] = []
        for item in files:
            if item.casefold() == wanted:
                return str((current / item).resolve())
    return None


def find_executable(
    candidates: tuple[str, ...], *, scripts: bool = False, configured_path: str | None = None
) -> str | None:
    """Search user configuration, controlled C:\\Tools tree, legacy locations, then PATH."""
    if configured_path and configured_path.strip():
        configured = Path(os.path.expandvars(configured_path.strip())).expanduser()
        if configured.is_file():
            return str(configured.resolve())
        if configured.is_dir():
            for name in _candidate_names(candidates):
                result = _walk_for_name(configured, name)
                if result:
                    return result

    from core.config import TOOLS_ROOT
    for name in _candidate_names(candidates):
        result = _walk_for_name(Path(TOOLS_ROOT), name)
        if result:
            return result

    for candidate in candidates:
        path = Path(os.path.expandvars(str(candidate))).expanduser()
        if path.is_absolute() and path.is_file():
            return str(path.resolve())
    for candidate in candidates:
        found = shutil.which(str(candidate))
        if found and Path(found).is_file():
            return str(Path(found).resolve())
    if scripts:
        for folder in os.get_exec_path():
            if not folder:
                continue
            for name in _candidate_names(candidates):
                path = Path(folder) / name
                if path.is_file():
                    return str(path.resolve())
    return None


def find_tool_executable(name: str, candidates: tuple[str, ...] | None = None) -> str | None:
    from core.config import load_config

    candidates = candidates or TOOL_CANDIDATES[name]
    settings = load_config()
    configured = settings.get("tools", {}).get(name, "")
    if name == "nuclei" and not configured:
        configured = settings.get("nuclei", {}).get("executable_path", "")
    return find_executable(candidates, scripts=True, configured_path=configured or None)


def script_command(path: str) -> list[str] | None:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return [sys.executable, path]
    if suffix == ".pl":
        perl = find_tool_executable("perl", PERL_PATHS)
        return [perl, path] if perl else None
    if suffix == ".ps1":
        powershell = find_tool_executable("powershell", POWERSHELL_PATHS)
        return [powershell, "-NoProfile", "-NonInteractive", "-File", path] if powershell else None
    if suffix in {".bat", ".cmd"}:
        return [path] if os.name == "nt" else None
    if os.name == "nt" and suffix != ".exe":
        perl = find_tool_executable("perl", PERL_PATHS)
        return [perl, path] if perl else None
    return [path]


def _prepare_batch_command(command: list[str]) -> list[str]:
    if os.name != "nt" or Path(command[0]).suffix.lower() not in {".bat", ".cmd"}:
        return command
    unsafe = set('&|<>^%!"\r\n')
    if any(any(char in unsafe for char in str(argument)) for argument in command):
        raise ValueError("Argumentos com metacaracteres não podem ser passados a scripts batch no Windows.")
    comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    batch_command = f'""{command[0]}"'
    if len(command) > 1:
        batch_command += " " + " ".join(f'"{argument}"' for argument in command[1:])
    return [comspec, "/d", "/s", "/c", batch_command]


def _windows_compatible_nikto_copy(path: str, workspace: Path) -> str | None:
    """Prepare a temporary patched copy for a known LibWhisker Windows connect bug.

    The installed Nikto tree is never modified. On Windows, LibWhisker 2.5's
    nonblocking Winsock connect reports WSAEWOULDBLOCK as an immediate failure
    on this Perl build; the blocking socket path works. Patch only that setting
    in a disposable copy and preserve all other upstream files byte-for-byte.
    """
    source = Path(path).resolve()
    install_root = source.parent
    module = install_root / "plugins" / "LW2.pm"
    if not source.is_file() or not module.is_file():
        return None
    try:
        module_text = module.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    patched_text, replacements = re.subn(
        r"(\$LW_NONBLOCK_CONNECT\s*=\s*)1\s*;",
        r"\g<1>0;",
        module_text,
        count=1,
    )
    if replacements != 1:
        return None
    clone_root = workspace / install_root.name
    shutil.copytree(
        install_root,
        clone_root,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "reports", "output*.txt"),
    )
    cloned_module = clone_root / "plugins" / "LW2.pm"
    cloned_module.write_text(patched_text, encoding="utf-8", newline="\n")
    return str(clone_root / source.name)


def find_zap_launcher() -> str | None:
    """Find the native ZAP startup script alongside the configured desktop app."""
    from core.config import load_config

    settings = load_config().get("tools", {})
    configured = settings.get("zap_launcher", "")
    zap = find_tool_executable("zap")
    if configured and Path(configured).is_file():
        return str(Path(configured).resolve())
    if zap:
        sibling_names = ("zap.bat", "zap.cmd", "zap.sh")
        for name in sibling_names:
            sibling = Path(zap).parent / name
            if sibling.is_file():
                return str(sibling.resolve())
    launcher = find_tool_executable("zap_launcher", ZAP_LAUNCHER_PATHS)
    if launcher:
        return launcher
    # Some ZAP distributions expose the same startup entry point as a JAR.
    if zap:
        parent = Path(zap).parent
        for jar in sorted(parent.glob("zap-*.jar")):
            return str(jar.resolve())
    return find_tool_executable("zap_jar", ZAP_JAR_PATHS)


def zap_command(launcher: str) -> list[str] | None:
    suffix = Path(launcher).suffix.lower()
    if suffix in {".bat", ".cmd", ".sh"}:
        return [launcher]
    if suffix == ".jar":
        java = find_tool_executable("java", JAVA_PATHS)
        return [java, "-jar", launcher] if java else None
    return None


def zap_automation_addon_present(launcher: str) -> bool:
    """Automation Framework is an installed ZAP add-on, separate from zap.bat."""
    from core.config import TOOLS_ROOT

    plugin_dirs = (
        Path(launcher).parent / "plugin",
        Path.home() / "ZAP" / "plugin",
        Path.home() / ".ZAP" / "plugin",
        Path(TOOLS_ROOT) / "ZAP" / "plugin",
    )
    return any(
        folder.is_dir()
        and any(list(folder.glob("automation-*.zap")) + list(folder.glob("automation-*.jar")))
        for folder in plugin_dirs
    )

def _probe_executable(command: list[str], timeout: int = 8, *, env: dict[str, str] | None = None) -> tuple[bool, str]:
    try:
        command = _prepare_batch_command(command)
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, check=False, shell=False, env=env,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return False, clean_text(str(exc))[:240]
    output = (result.stdout or b"").decode("utf-8", errors="replace").strip()
    return result.returncode == 0, clean_text(output.splitlines()[0] if output else "")[:240]


def dependency_status() -> list[tuple[str, bool | None, str]]:
    """Report real discovered paths; None means the file exists but is not runnable."""
    from core.config import load_config
    from core.nuclei import check_nuclei_templates, check_nuclei_version, find_nuclei

    rows = [("Python", True, sys.version.split()[0])]
    for module, label in (("nmap", "python-nmap"), ("colorama", "colorama")):
        present = importlib.util.find_spec(module) is not None
        rows.append((label, present, "dispon\u00edvel" if present else "instale requirements.txt"))

    nmap = find_tool_executable("nmap")
    if nmap:
        works, version = _probe_executable([nmap, "--version"])
        rows.append(("Nmap", works, f"{nmap}; {version}" if works else f"encontrado, mas n\u00e3o executa: {version}"))
    else:
        rows.append(("Nmap", False, "n\u00e3o encontrado"))

    nuclei = find_nuclei()
    if nuclei:
        checked = check_nuclei_version(nuclei)
        nuclei_settings = load_config()["nuclei"]
        templates = check_nuclei_templates(nuclei_settings["templates_directory"] or None)
        if checked["status"] != "concluído":
            rows.append(("Nuclei", False, f"{nuclei} ({checked['message']})"))
        elif not templates["found"]:
            rows.append(("Nuclei", None, f"{nuclei}; vers\u00e3o {checked['version']}; {templates['message']}"))
        else:
            rows.append(("Nuclei", True, f"{nuclei}; vers\u00e3o {checked['version']}; templates: {templates['path']}"))
    else:
        rows.append(("Nuclei", False, "não encontrado"))

    zap = find_tool_executable("zap")
    java = find_tool_executable("java")
    java_ok = bool(java and _probe_executable([java, "-version"])[0])
    if zap and Path(zap).is_file():
        rows.append(("ZAP", True, zap))
    else:
        rows.append(("ZAP", False, "n\u00e3o encontrado"))
    launcher = find_zap_launcher()
    if launcher and java_ok and zap_automation_addon_present(launcher):
        rows.append(("ZAP Automation Framework", True, launcher))
    elif launcher and not java_ok:
        rows.append(("ZAP Automation Framework", None, f"{launcher}; Java ausente ou inv\u00e1lido"))
    elif launcher:
        rows.append(("ZAP Automation Framework", False, f"{launcher}; add-on Automation Framework n\u00e3o encontrado"))
    else:
        rows.append(("ZAP Automation Framework", False, "zap.bat/zap.sh e JAR de inicializa\u00e7\u00e3o n\u00e3o encontrados"))

    nikto = find_tool_executable("nikto")
    if nikto:
        command = script_command(nikto)
        if not command:
            interpreter = "Perl" if Path(nikto).suffix.lower() == ".pl" else "PowerShell"
            rows.append(("Nikto", None, f"encontrado, mas depende da instala\u00e7\u00e3o do {interpreter}. {nikto}"))
        elif Path(nikto).suffix.lower() == ".pl":
            perl = command[0]
            works, version = _probe_executable([perl, nikto, "-Version"], env=_perl_environment(perl))
            rows.append(("Nikto", works, f"{nikto}; {version}" if works else f"{nikto}; Perl encontrado, mas Nikto n\u00e3o executa"))
        else:
            works, _ = _probe_executable([*command, "-Version"])
            rows.append(("Nikto", works, nikto if works else f"{nikto}; arquivo encontrado, mas n\u00e3o executa"))
    else:
        rows.append(("Nikto", False, "n\u00e3o encontrado"))

    perl = find_tool_executable("perl", PERL_PATHS)
    if perl:
        perl_ok, _ = _probe_executable([perl, "-v"], env=_perl_environment(perl))
        rows.append(("Perl", perl_ok, perl if perl_ok else f"{perl}; encontrado, mas n\u00e3o executa"))
        for module in ("XML::Writer", "Net::SSLeay", "IO::Socket::SSL", "Net::SSL"):
            check = _probe_executable([perl, f"-M{module}", "-e", "exit 0"], env=_perl_environment(perl))
            rows.append((f"Perl {module}", check[0], f"{perl}; {check[1] or ('dispon\u00edvel' if check[0] else 'm\u00f3dulo ausente ou DLL nativa indispon\u00edvel')}"))
        tls_modules_ok = any(row[1] is True for row in rows if row[0] in {"Perl Net::SSLeay", "Perl Net::SSL"})
        rows.append(("Nikto HTTPS", None if tls_modules_ok else False,
                     "m\u00f3dulo TLS importa; teste de conex\u00e3o HTTPS local ainda n\u00e3o executado" if tls_modules_ok else
                     "Net::SSLeay/Net::SSL indispon\u00edvel; HTTPS n\u00e3o validado"))
    else:
        rows.append(("Perl", False, "n\u00e3o instalado"))
        rows.extend((f"Perl {module}", False, "Perl n\u00e3o encontrado") for module in ("XML::Writer", "Net::SSLeay", "IO::Socket::SSL", "Net::SSL"))
        rows.append(("Nikto HTTPS", False, "Perl n\u00e3o encontrado; HTTPS n\u00e3o validado"))

    if java:
        works, _ = _probe_executable([java, "-version"])
        rows.append(("Java", works, java if works else f"{java}; arquivo encontrado, mas n\u00e3o executa"))
    else:
        rows.append(("Java", False, "n\u00e3o encontrado"))

    metasploit = find_tool_executable("metasploit")
    if metasploit:
        rows.append(("Metasploit", True, metasploit))
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


def run_command(command: list[str], *, timeout: int = TOOL_TIMEOUT, capture_output: bool = False,
                cwd: str | Path | None = None, env: dict[str, str] | None = None) -> dict:
    """Exibe saída no terminal e registra somente o estado, sem conteúdo sensível."""
    from core.analysis import duration_ms
    result = {"started_at": now_iso(), "status": "erro", "execution_status": "failed", "returncode": None}
    try:
        launch_command = _prepare_batch_command(command)
    except ValueError as exc:
        result["message"] = str(exc)
        result["finished_at"] = now_iso()
        return result
    process = None
    output_file = tempfile.TemporaryFile() if capture_output else None
    error_file = tempfile.TemporaryFile() if capture_output else None
    try:
        process = subprocess.Popen(
            launch_command,
            shell=False,
            stdout=output_file if capture_output else None,
            stderr=error_file if capture_output else None,
            cwd=cwd,
            env=env,
            **process_options(),
        )
        result["returncode"] = process.wait(timeout=timeout)
        result["status"] = "concluído" if result["returncode"] == 0 else "erro"
        result["execution_status"] = "completed" if result["returncode"] == 0 else "failed"
        result["message"] = f"Processo encerrado com código {result['returncode']}."
    except FileNotFoundError:
        result["message"] = "Executável ou interpretador não encontrado. Verifique a instalação."
    except PermissionError:
        result["message"] = "Permissão insuficiente para executar a ferramenta."
    except subprocess.TimeoutExpired:
        result.update(status="timeout", execution_status="timeout", message=f"Tempo limite de {timeout} segundos excedido.")
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
        if output_file is not None:
            output_file.seek(0)
            stdout = clean_text(output_file.read(MAX_CAPTURE_BYTES).decode("utf-8", errors="replace"))
            error_file.seek(0)
            stderr = clean_text(error_file.read(MAX_CAPTURE_BYTES).decode("utf-8", errors="replace"))
            output = stdout + (("\n" if stdout and not stdout.endswith("\n") else "") + stderr if stderr else "")
            result["stdout"], result["stderr"] = stdout, stderr
            if output:
                result["output"] = output
                print(output, end="" if output.endswith("\n") else "\n")
            output_file.close()
            error_file.close()
        result["finished_at"] = now_iso()
        result["duration_ms"] = duration_ms(result)
    return result


def run_nikto(target: str, port: int | None = None, service: str | dict = "", *, timeout: int | None = None) -> dict:
    from core.config import load_config

    url = validate_web_url(target) if port is None else build_web_url(target, port, service)
    settings = load_config()
    nikto_settings = settings.get("nikto", {})
    if not nikto_settings.get("enabled", True):
        return {"tool": "Nikto", "port": port, "url": url, "started_at": now_iso(),
                "status": "desativado", "execution_status": "skipped", "message": "Nikto está desativado na configuração."}
    path = find_tool_executable("nikto", NIKTO_PATHS)
    perl_available = bool(find_tool_executable("perl", PERL_PATHS)) if path and Path(path).suffix.lower() == ".pl" else False
    compatibility_context = tempfile.TemporaryDirectory(prefix="offangell_nikto_") if perl_available and os.name == "nt" else None
    try:
        if compatibility_context:
            workspace = Path(compatibility_context.__enter__())
            execution_path = _windows_compatible_nikto_copy(path, workspace)
        else:
            execution_path = path
    except OSError as exc:
        if compatibility_context:
            compatibility_context.cleanup()
        return {"tool": "Nikto", "port": port, "url": url, "started_at": now_iso(),
                "status": "erro", "execution_status": "failed", "message": f"N\u00e3o foi poss\u00edvel preparar a c\u00f3pia tempor\u00e1ria do Nikto: {clean_text(str(exc))[:300]}"}
    command = script_command(execution_path) if execution_path else None
    if not command:
        if compatibility_context:
            compatibility_context.cleanup()
        return {
            "tool": "Nikto",
            "port": port,
            "started_at": now_iso(),
            "status": "indisponível",
            "message": ("Nikto foi localizado, mas a c\u00f3pia Windows compat\u00edvel n\u00e3o p\u00f4de ser preparada." if path and not execution_path else
                        "[!] Nikto encontrado, mas depende da instala\u00e7\u00e3o do Perl." if path and Path(path).suffix.lower() == ".pl" else
                        "Nikto n\u00e3o encontrado. Essa fun\u00e7\u00e3o \u00e9 opcional."),
        }
    # Somente testes de configuração e identificação; sem plugins de ataque.
    args = ["-h", url, "-Tuning", "2b", "-Plugins", "headers;tests", "-nointeractive", "-nocheck"]
    try:
        runtime_env = _perl_environment(command[0]) if Path(path).suffix.lower() == ".pl" else None
        result = run_command([*command, *args], timeout=timeout or nikto_settings.get("timeout", TOOL_TIMEOUT), capture_output=True, env=runtime_env)
    except (OSError, ValueError) as exc:
        result = {"started_at": now_iso(), "finished_at": now_iso(), "returncode": None,
                  "status": "erro", "execution_status": "failed", "message": f"Falha ao preparar a execução do Nikto: {clean_text(str(exc))[:300]}"}
    finally:
        if compatibility_context:
            compatibility_context.cleanup()
    output = result.get("output", "")
    for stream_key in ("output", "stdout", "stderr"):
        if result.get(stream_key):
            result[stream_key] = re.sub(r"(?im)^.*consider using mitmproxy.*(?:\r?\n|$)",
                                        "[recommendation omitted: bypassing server controls is not advised]\n", result[stream_key])
    output = result.get("output", output)
    folded = output.casefold()
    connection_failure = any(marker in folded for marker in (
        "no web server found", "error connecting", "connection refused", "could not connect",
        "failed to connect", "unable to connect", "no route to host", "name or service not known",
        "[fail] unable to connect", "unable to establish connection",
    ))
    tls_failure = any(marker in folded for marker in ("ssl connect failed", "tls handshake", "ssl handshake", "net::ssleay", "tls/ssl support not available"))
    error_limit = bool(re.search(r"error limit\s*\(\s*\d+\s*\)\s*reached|scan terminated:\s*\d+\s+errors?", output, re.I))
    request_values = [int(value) for value in re.findall(r"(?:completed\s+)?(\d+)\s+requests?", output, re.I)]
    requests = max(request_values) if request_values else None
    error_values = [int(value) for value in re.findall(r"scan terminated:\s*(\d+)\s+errors?", output, re.I)]
    error_count = max(error_values) if error_values else (20 if error_limit else None)
    nikto_findings = []
    for match in re.finditer(r"^\+\s+\[(\d+)\]\s+([^:]+):\s*(.+)$", output, re.M):
        nikto_findings.append({"tool": "Nikto", "plugin_id": match.group(1), "url": url.rstrip("/") + match.group(2),
            "name": clean_text(match.group(3))[:500], "severity": "Unknown", "evidence": clean_text(match.group(0))[:1000],
            "validation_status": "unconfirmed"})
    state = result.get("execution_status", "completed" if str(result.get("status", "")).casefold().startswith("conclu") else "failed")
    if tls_failure or error_limit or connection_failure:
        state = "partial" if requests is not None or nikto_findings else "failed"
        reason = "limite de erros atingido" if error_limit else "falha TLS/SSL" if tls_failure else "falha de conexão"
        result.update(status="parcial" if state == "partial" else "erro", execution_status=state,
                      message=f"Nikto: {reason}; evid\u00eancias parciais preservadas.")
    result.update(execution_status=state, request_count=requests, error_count=error_count,
                  completion_percent=None, findings=nikto_findings)
    return {
        **result,
        "tool": "Nikto",
        "port": port,
        "url": url,
        "profile": "configuração e identificação (2b)",
        **({"windows_compatibility": "cópia temporária com conexão bloqueante do LibWhisker; a instalação original não foi alterada"} if compatibility_context else {}),
    }


def run_zap(target: str, port: int | None = None, service: str | dict = "") -> dict:
    url = validate_web_url(target) if port is None else build_web_url(target, port, service)
    launcher = find_zap_launcher()
    command = zap_command(launcher) if launcher else None
    if not command or not zap_automation_addon_present(launcher):
        return {
            "tool": "ZAP Automation Framework", "port": port, "started_at": now_iso(),
            "status": "indispon\u00edvel", "execution_status": "skipped",
            "message": "ZAP desktop localizado, mas o Automation Framework, o script de inicializa\u00e7\u00e3o ou Java n\u00e3o est\u00e1 dispon\u00edvel.",
        }
    with tempfile.TemporaryDirectory(prefix="offangell_zap_") as temp_dir:
        plan_path = Path(temp_dir) / "automation-plan.yaml"
        report_path = Path(temp_dir) / "zap-report.json"
        plan = {
            "env": {
                "contexts": [{"name": "offangell-authorized-target", "urls": [url]}],
                "parameters": {
                    "failOnError": False, "failOnWarning": False,
                    "continueOnFailure": False, "progressToStdout": True,
                    "maxDuration": TOOL_TIMEOUT,
                },
            },
            "jobs": [
                {"type": "spider", "parameters": {
                    "context": "offangell-authorized-target", "url": url,
                    "maxDuration": max(1, (TOOL_TIMEOUT // 60) - 2),
                }},
                {"type": "passiveScan-wait", "parameters": {"maxDuration": 2}},
                {"type": "report", "parameters": {
                    "template": "traditional-json", "reportDir": temp_dir,
                    "reportFile": report_path.name, "displayReport": False,
                }},
            ],
        }
        try:
            plan_path.write_text(yaml.safe_dump(plan, sort_keys=False, allow_unicode=True), encoding="utf-8")
            generated_plan = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
            if not isinstance(generated_plan, dict) or generated_plan.get("jobs") != plan["jobs"]:
                raise ValueError("plano YAML divergente")
            plan_validated = True
        except (OSError, ValueError, yaml.YAMLError) as exc:
            return {"tool": "ZAP Automation Framework", "port": port, "url": url, "started_at": now_iso(),
                    "finished_at": now_iso(), "status": "erro", "execution_status": "failed",
                    "message": f"Falha ao gerar o plano YAML do ZAP: {clean_text(str(exc))}", "alerts": [],
                    "operational_errors": ["plan_write_failed"]}
        result = run_command(
            [*command, "-cmd", "-autorun", str(plan_path)],
            timeout=TOOL_TIMEOUT, capture_output=True, cwd=temp_dir,
        )
        alerts = []
        report_exists = report_path.is_file()
        if report_exists:
            try:
                document = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
                if not isinstance(document, dict) or not isinstance(document.get("site"), list):
                    raise ValueError("estrutura de relatório ZAP inválida")
                for site in document.get("site", []):
                    for alert in site.get("alerts", []):
                        alerts.append({
                            "source": "OWASP ZAP Automation Framework", "status": "ind\u00edcio",
                            "severity": alert.get("riskdesc", "Informational").split(" ", 1)[0],
                            "name": clean_text(str(alert.get("name", "")))[:500],
                            "url": clean_text(str(alert.get("url", site.get("@name", ""))))[:2000],
                            "description": clean_text(str(alert.get("desc", "")))[:4000],
                            "evidence": clean_text(str(alert.get("evidence", "")))[:1000],
                            "recommendation": clean_text(str(alert.get("solution", "")))[:4000],
                            "alert_ref": clean_text(str(alert.get("alertRef", "")))[:100],
                        })
            except (OSError, ValueError, TypeError, AttributeError):
                result["report_parse"] = "N\u00e3o foi poss\u00edvel interpretar o relat\u00f3rio JSON do ZAP."
    output = (result.get("stdout", "") + "\n" + result.get("stderr", "") + "\n" + result.get("output", "")).casefold()
    path_error = "o caminho da rede n\u00e3o foi encontrado" in output or "the network path was not found" in output
    permission_error = any(term in output for term in ("access is denied", "permiss?o negada", "permission denied"))
    parse_error = bool(result.get("report_parse"))
    code = result.get("returncode")
    if result.get("execution_status") == "timeout" or result.get("status") == "timeout":
        state, message = "timeout", result.get("message", "Timeout do ZAP.")
    elif path_error or permission_error or code not in {0, 1, 2} or code is None:
        state = "partial" if report_exists and alerts else "failed"
        message = "Falha de caminho/rede no ZAP." if path_error else "Permissão insuficiente no ZAP." if permission_error else "Falha na execução do ZAP."
    elif not report_exists or parse_error:
        state, message = "failed", "O ZAP não gerou um relatório JSON válido."
    elif code == 0:
        state, message = "completed", "Plano Automation Framework conclu\u00eddo e relat\u00f3rio validado."
    else:
        state, message = "partial", f"Plano ZAP terminou com código {code}; relatório preservado para revisão."
    legacy = "conclu\u00eddo" if state == "completed" else "parcial" if state == "partial" else "timeout" if state == "timeout" else "erro"
    errors = [name for name, present in (("network_path_not_found", path_error), ("permission_denied", permission_error),
              ("report_missing_or_invalid", not report_exists or parse_error)) if present]
    return {**result, "tool": "ZAP Automation Framework", "port": port, "url": url,
            "status": legacy, "execution_status": state, "message": message, "report_exists": report_exists,
            "plan_validated": plan_validated, "operational_errors": errors,
            "alerts": alerts, "profile": "spider e an?lise passiva; sem active scan"}
