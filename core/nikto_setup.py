"""Read-only Nikto/Perl diagnostics and opt-in Windows dependency setup."""

from __future__ import annotations

import argparse
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from core.config import _read_dotenv, load_config
from core.reports import clean_text
from core.tools import PERL_PATHS, _perl_environment, find_tool_executable, run_nikto


def _run(command: list[str], *, timeout: int = 15, env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=timeout, check=False, shell=False, env=env)
        output = clean_text(result.stdout.decode("utf-8", errors="replace"))[:8000]
        return {"ok": result.returncode == 0, "returncode": result.returncode, "output": output}
    except subprocess.TimeoutExpired:
        return {"ok": False, "returncode": None, "output": f"timeout após {timeout}s"}
    except OSError as exc:
        return {"ok": False, "returncode": None, "output": clean_text(str(exc))[:1000]}


def _perl_modules(perl: str) -> dict[str, dict[str, Any]]:
    modules = ("XML::Writer", "Net::SSLeay", "IO::Socket::SSL", "Net::SSL", "IO::Socket", "JSON::PP")
    code = (
        "for my $m (@ARGV) { my $ok = eval { (my $f = $m) =~ s!::!/!g; require \"$f.pm\"; 1 }; "
        "my $v = $ok ? eval { $m->VERSION } : undef; print $m, \"\\t\", ($ok ? \"OK\" : \"FALHA: $@\"), \"\\t\", ($v // \"\"), \"\\n\"; }"
    )
    result = _run([perl, "-e", code, *modules], env=_perl_environment(perl))
    rows: dict[str, dict[str, Any]] = {name: {"ok": False, "detail": "n\u00e3o testado"} for name in modules}
    for line in result["output"].splitlines():
        name, sep, remainder = line.partition("\t")
        if not sep or name not in rows:
            continue
        status, _, version = remainder.partition("\t")
        rows[name] = {"ok": status == "OK", "version": version, "detail": status}
    if not result["ok"] and not any(item["ok"] for item in rows.values()):
        for item in rows.values():
            item["detail"] = result["output"] or "Falha ao invocar Perl."
    return rows


def _probe_runtime(perl: str) -> dict[str, Any]:
    result = _run([perl, "-V:archname", "-V:version"], env=_perl_environment(perl))
    output = result["output"]
    return {"ok": result["ok"], "architecture": next((x.split("=", 1)[1] for x in output.splitlines() if x.startswith("archname=")), "desconhecida"),
            "version": next((x.split("=", 1)[1] for x in output.splitlines() if x.startswith("version=")), "desconhecida"),
            "detail": output[:1000]}


def _configuration_files(nikto: str | None) -> list[str]:
    if not nikto:
        return []
    program = Path(nikto).parent
    candidates = [program / "nikto.conf", program / "nikto.conf.default",
        Path.home() / ".nikto" / "nikto.conf", Path.home() / "nikto.conf"]
    return [str(path.resolve()) for path in candidates if path.is_file()]


def _toolchain(perl: str | None) -> dict[str, Any]:
    names = ("gmake", "make", "gcc", "cl")
    found: dict[str, Any] = {}
    env = _perl_environment(perl) if perl else os.environ.copy()
    extra_dirs = [Path(folder) for folder in env.get("PATH", "").split(os.pathsep) if folder]
    for name in names:
        path = shutil.which(name, path=env.get("PATH"))
        if path is None:
            for folder in extra_dirs:
                for suffix in (".exe", ".bat", ""):
                    candidate = folder / f"{name}{suffix}"
                    if candidate.is_file():
                        path = str(candidate)
                        break
                if path:
                    break
        if path:
            version_args = [path, "--version"] if name not in {"cl"} else [path]
            probe = _run(version_args, timeout=8, env=env)
            found[name] = {"path": path, "runnable": probe["ok"], "detail": probe["output"][:400]}
        else:
            found[name] = {"path": None, "runnable": False, "detail": "não encontrado"}
    return found


def diagnose() -> dict[str, Any]:
    from core.config import TOOLS_ROOT

    config = load_config()
    perl = find_tool_executable("perl", PERL_PATHS)
    nikto = find_tool_executable("nikto")
    report: dict[str, Any] = {
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "perl": {"path": perl, "in_path": bool(perl and shutil.which(Path(perl).name)),
                 "runtime": _probe_runtime(perl) if perl else None,
                 "modules": _perl_modules(perl) if perl else {}},
        "nikto": {"path": nikto, "in_path": bool(nikto and shutil.which(Path(nikto).name)),
                  "version": None, "version_check": None,
                  "config_files": _configuration_files(nikto)},
        "toolchain": _toolchain(perl),
    }
    if nikto and perl:
        version = _run([perl, nikto, "-Version"], env=_perl_environment(perl))
        report["nikto"]["version_check"] = version
        for line in version["output"].splitlines():
            if line.lower().startswith("nikto "):
                report["nikto"]["version"] = line.strip()
                break
    modules = report["perl"]["modules"]
    ssl_modules_ok = modules.get("Net::SSLeay", {}).get("ok") or modules.get("Net::SSL", {}).get("ok")
    tools_root = Path(TOOLS_ROOT)
    dll_dirs = [Path(perl).resolve().parent] if perl else []
    dll_dirs.extend((tools_root / "c" / "bin", *tools_root.glob("*/c/bin")))
    dlls = []
    for folder in dll_dirs:
        if not folder.is_dir():
            continue
        for pattern in ("libssl*.dll", "libcrypto*.dll", "ssleay32.dll", "libeay32.dll"):
            dlls.extend(str(path.resolve()) for path in folder.glob(pattern) if path.is_file())
    report["https"] = {"supported_by_modules": bool(ssl_modules_ok), "local_connection_test": "pendente",
        "detail": "Net::SSLeay (ou Net::SSL) precisa carregar e o teste HTTPS local precisa concluir.",
        "openssl_dlls": sorted(set(dlls)),
        "openssl_x64_pair_found": any("x64" in Path(path).name.casefold() for path in dlls if Path(path).name.casefold().startswith("libssl")) and any("x64" in Path(path).name.casefold() for path in dlls if Path(path).name.casefold().startswith("libcrypto"))}
    if not perl:
        report["https"]["detail"] = "Perl não encontrado; não foi possível validar suporte TLS do Nikto."
    elif not ssl_modules_ok:
        report["https"]["detail"] = "Net::SSLeay/Net::SSL não carregou; verifique DLLs nativas/OpenSSL e compatibilidade x64."
    report["path_notes"] = {
        "tools_root": str(Path(r"C:\tools")),
        "perl_path_missing_from_path": bool(perl and not shutil.which(Path(perl).name)),
        "nikto_path_missing_from_path": bool(nikto and not shutil.which(Path(nikto).name)),
        "environment_overrides": {key: bool(os.environ.get(key) or _read_dotenv().get(key)) for key in ("PERL_PATH", "NIKTO_PATH", "NIKTO_TIMEOUT", "NIKTO_ENABLED")},
    }
    return report


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    requests_seen = 0
    def do_GET(self):
        type(self).requests_seen += 1
        body = b"OFF ANGELL local Nikto setup test\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_HEAD(self):
        type(self).requests_seen += 1
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, format, *args):
        return


def test_local_http() -> dict[str, Any]:
    """Run the configured Nikto binary only against a temporary 127.0.0.1 server."""
    _QuietHandler.requests_seen = 0
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            preflight_status = response.status
        result = run_nikto(url, timeout=120)
        return {"target": url, "preflight_http_status": preflight_status,
                "requests_seen": _QuietHandler.requests_seen, "result": result,
                "ok": preflight_status == 200 and result.get("status") == "concluído" and _QuietHandler.requests_seen > 1}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _run_local_https(cert_file: str, key_file: str) -> dict[str, Any]:
    report = diagnose()
    if not report["https"]["supported_by_modules"]:
        return {"ok": False, "status": "não suportado", "target": None,
                "message": report["https"]["detail"]}
    _QuietHandler.requests_seen = 0
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://127.0.0.1:{server.server_address[1]}/"
    try:
        result = run_nikto(url, timeout=120)
        ok = result.get("status") == "concluído" and _QuietHandler.requests_seen > 0
        return {"ok": ok, "status": "testado" if ok else "falha", "target": url,
                "requests_seen": _QuietHandler.requests_seen, "result": result}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _find_openssl() -> str | None:
    from core.config import TOOLS_ROOT
    root = Path(TOOLS_ROOT)
    candidates = [root / "cpan" / "c" / "bin" / "openssl.exe", root / "c" / "bin" / "openssl.exe"]
    candidates.extend(root.glob("*/c/bin/openssl.exe")) if root.is_dir() else None
    for path in candidates:
        if path.is_file():
            return str(path.resolve())
    return shutil.which("openssl")


def test_local_https(cert_file: str | None = None, key_file: str | None = None) -> dict[str, Any]:
    """Test TLS locally, using explicit certs or an ephemeral OpenSSL test cert."""
    if cert_file and key_file:
        return _run_local_https(cert_file, key_file)
    openssl = _find_openssl()
    if not openssl:
        return {"ok": False, "status": "pendente", "target": None,
                "message": "OpenSSL não foi encontrado para criar um certificado efêmero de teste local."}
    with tempfile.TemporaryDirectory(prefix="offangell_nikto_tls_") as temp_dir:
        cert = Path(temp_dir) / "localhost.crt"
        key = Path(temp_dir) / "localhost.key"
        config = Path(temp_dir) / "openssl.cnf"
        config.write_text(
            "[req]\ndistinguished_name=dn\nx509_extensions=v3_req\nprompt=no\n"
            "[dn]\nCN=127.0.0.1\n[v3_req]\nsubjectAltName=IP:127.0.0.1\n"
            "basicConstraints=CA:TRUE\nkeyUsage=digitalSignature,keyEncipherment,keyCertSign\n",
            encoding="ascii",
        )
        env = os.environ.copy()
        env["PATH"] = os.pathsep.join([str(Path(openssl).parent), env.get("PATH", "")])
        created = _run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                        "-out", str(cert), "-days", "1", "-config", str(config), "-extensions", "v3_req"],
                       timeout=30, env=env)
        if not created["ok"] or not cert.is_file() or not key.is_file():
            return {"ok": False, "status": "falha", "target": None,
                    "message": "Não foi possível gerar certificado efêmero de teste local: " + created["output"][:600]}
        return _run_local_https(str(cert), str(key))


def install_perl_dependencies(timeout: int = 1800) -> dict[str, Any]:
    """Opt-in CPAN installation from the official CPAN HTTPS mirror."""
    perl = find_tool_executable("perl", PERL_PATHS)
    if not perl or not _run([perl, "-e", "exit 0"], env=_perl_environment(perl))["ok"]:
        return {"ok": False, "message": "Perl executável não encontrado; instalação cancelada."}
    modules = _perl_modules(perl)
    xml_writer_skipped = modules.get("XML::Writer", {}).get("ok", False)
    missing = [module for module in ("XML::Writer", "Net::SSLeay", "IO::Socket::SSL")
               if not modules.get(module, {}).get("ok")]
    if not missing:
        return {"ok": True, "message": "XML::Writer e depend\u00eancias TLS j\u00e1 carregam; nenhuma instala\u00e7\u00e3o necess\u00e1ria.", "installed": []}
    if not modules.get("Net::SSLeay", {}).get("ok"):
        toolchain = _toolchain(perl)
        if (not any(toolchain[name]["runnable"] for name in ("gmake", "make"))
                or not any(toolchain[name]["runnable"] for name in ("gcc", "cl"))):
            return {"ok": False, "message": "Falta GNU Make e/ou compilador execut\u00e1vel; use uma distribuicao Perl Windows com toolchain/OpenSSL compat\u00edveis. CPAN nao foi iniciado.", "toolchain": toolchain}
    code = (
        "CPAN::HandleConfig->load; $CPAN::Config->{urllist} = ['https://www.cpan.org/']; "
        "for my $m ('XML::Writer','Net::SSLeay','IO::Socket::SSL') { "
        "my $ok = eval { (my $f=$m)=~s!::!/!g; require \"$f.pm\"; 1 }; "
        "CPAN::Shell->install($m) unless $ok; }"
    )
    env = _perl_environment(perl)
    env["PERL_MM_USE_DEFAULT"] = "1"
    installed = _run([perl, "-MCPAN", "-e", code], timeout=timeout, env=env)
    verified = _perl_modules(perl)
    return {"ok": all(verified.get(module, {}).get("ok") for module in ("XML::Writer", "Net::SSLeay", "IO::Socket::SSL")),
            "message": "CPAN oficial executado; módulos revalidados após a instalação.",
            "xml_writer_skipped": xml_writer_skipped, "requested_modules": missing,
            "installation": installed, "modules": verified}


def _format(report: dict[str, Any]) -> str:
    def state(ok: bool | None) -> str:
        return "OK" if ok else "FALHA"
    lines = ["OFF ANGELL — Diagnóstico Nikto", "=" * 48]
    perl = report["perl"]
    lines.append(f"Perl: {perl['path'] or 'não encontrado'}")
    if perl.get("runtime"):
        runtime = perl["runtime"]
        lines.append(f"  versão {runtime['version']}; arquitetura {runtime['architecture']}")
    for name, module in perl.get("modules", {}).items():
        lines.append(f"  {state(module['ok'])} {name}: {module['detail']}")
    nikto = report["nikto"]
    lines.append(f"Nikto: {nikto['path'] or 'não encontrado'}")
    lines.append(f"  versão: {nikto['version'] or 'não identificada'}")
    lines.append(f"  configurações: {', '.join(nikto['config_files']) or 'nenhuma encontrada'}")
    https = report["https"]
    lines.append(f"HTTPS: {'módulos prontos' if https['supported_by_modules'] else 'indisponível'}; teste local: {https['local_connection_test']}")
    lines.append(f"  {https['detail']}")
    lines.append(f"  DLL OpenSSL x64 em par: {https['openssl_x64_pair_found']}")
    for name, value in report["toolchain"].items():
        lines.append(f"Toolchain {name}: {value['path'] or 'não encontrado'} ({state(value['runnable'])})")
    for key, value in report["path_notes"].items():
        lines.append(f"PATH/config {key}: {value}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diagnóstico e configuração local do Nikto para OFF ANGELL")
    parser.add_argument("--local-test", action="store_true", help="executa Nikto somente contra HTTP em 127.0.0.1")
    parser.add_argument("--https-cert", help="certificado PEM local para teste HTTPS em 127.0.0.1")
    parser.add_argument("--https-key", help="chave PEM local para teste HTTPS em 127.0.0.1")
    parser.add_argument("--install-deps", action="store_true", help="instala Net::SSLeay/IO::Socket::SSL via CPAN oficial, se toolchain existir")
    parser.add_argument("--report", type=Path, help="salva o diagnóstico (JSON) neste caminho")
    args = parser.parse_args(argv)
    if bool(args.https_cert) != bool(args.https_key):
        parser.error("--https-cert e --https-key devem ser informados juntos.")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(errors="replace")
    report = diagnose()
    if args.install_deps:
        installation = install_perl_dependencies()
        report = diagnose()
        report["dependency_installation"] = installation
    if args.local_test:
        report["local_http_test"] = test_local_http()
        report["local_https_test"] = test_local_https(args.https_cert, args.https_key)
        report["https"]["local_connection_test"] = report["local_https_test"]["status"]
    if args.https_cert and args.https_key and not args.local_test:
        report["local_https_test"] = test_local_https(args.https_cert, args.https_key)
        report["https"]["local_connection_test"] = report["local_https_test"]["status"]
    if report.get("local_https_test", {}).get("ok"):
        report["https"]["detail"] = "Net::SSLeay carregou e Nikto concluiu conex\u00e3o TLS com o servidor de teste em 127.0.0.1."
    print(_format(report))
    if "dependency_installation" in report:
        installation = report["dependency_installation"]
        print("\nCPAN:", installation.get("message", "sem resultado"))
        if installation.get("xml_writer_skipped"):
            print("XML::Writer ja estava funcional; nenhuma reinstalacao foi iniciada.")
        if installation.get("installation", {}).get("output"):
            print(installation["installation"]["output"][:4000])
    if args.local_test:
        print("\nTeste HTTP local:", json.dumps(report["local_http_test"], ensure_ascii=False))
        print("\nTeste HTTPS local:", json.dumps(report["local_https_test"], ensure_ascii=False))
    if "local_https_test" in report:
        print("\nTeste HTTPS local:", json.dumps(report["local_https_test"], ensure_ascii=False))
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Relatório salvo em: {args.report.resolve()}")
    if args.local_test and not report["local_http_test"].get("ok"):
        return 1
    if "local_https_test" in report and report["local_https_test"].get("status") == "falha":
        return 1
    if report.get("dependency_installation", {}).get("ok") is False:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
