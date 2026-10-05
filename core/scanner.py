import ipaddress
import socket
import ssl
import subprocess
import time
import xml.etree.ElementTree as ET
from contextlib import ExitStack
from typing import Any

from core.reports import clean_text, now_iso
from core.tools import NMAP_PATHS, find_executable, process_options, stop_process
from core.validation import (
    build_web_url,
    is_web_service,
    uses_tls,
    validate_ports,
    validate_target,
)

SCAN_TIMEOUT = 1800
BANNER_TIMEOUT = 5
MAX_BANNER_BYTES = 8192
NSE_EXPRESSION = (
    "(vuln and safe) and not "
    "(auth or brute or dos or exploit or intrusive or fuzzer or external or broadcast or malware)"
)


class ScanError(RuntimeError):
    """Falha operacional com mensagem apropriada para o terminal."""


def resolve_target(target: str) -> str:
    target = validate_target(target)
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    try:
        addresses = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScanError("DNS não resolvido. Confira o hostname e a conexão de rede.") from exc
    if not addresses:
        raise ScanError("DNS não retornou endereços para esse hostname.")
    addresses.sort(key=lambda item: item[0] != socket.AF_INET)
    return addresses[0][4][0]


def create_scanner() -> tuple[Any, str]:
    try:
        import nmap
    except ImportError as exc:
        raise ScanError(
            "python-nmap ausente. Instale as dependências de requirements.txt."
        ) from exc
    path = find_executable(NMAP_PATHS)
    if not path:
        raise ScanError("Nmap não foi encontrado. Instale-o ou ajuste NMAP_PATHS em core/tools.py.")
    try:
        return nmap.PortScanner(nmap_search_path=(path,)), path
    except (nmap.PortScannerError, OSError) as exc:
        raise ScanError(
            "Não foi possível iniciar o Nmap. Confira a instalação e as permissões."
        ) from exc


def run_nmap(address: str, ports: str | None, *, nse: bool = False) -> dict:
    """Mantém o parser python-nmap e controla o processo para permitir cancelamento."""
    address = str(ipaddress.ip_address(address))
    if ports is not None:
        ports = validate_ports(ports)
    parser, path = create_scanner()
    command = [path, "-oX", "-", "-sT", "-sV", "-n"]
    if ":" in address:
        command.append("-6")
    if ports is None:
        command.extend(["--top-ports", "100"])
    else:
        command.extend(["-p", ports])
    if nse:
        command.extend(["--script", NSE_EXPRESSION, "--script-timeout", "60s"])
    command.append(address)
    process = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            **process_options(),
        )
        xml, errors = process.communicate(timeout=SCAN_TIMEOUT)
        if process.returncode:
            message = errors.decode("utf-8", errors="replace").strip()
            if any(word in message.lower() for word in ("permission", "privilege", "root")):
                raise ScanError(
                    "Permissão insuficiente para o Nmap. Confira Npcap e as permissões do sistema."
                )
            raise ScanError(
                f"Nmap não concluiu a análise: {clean_text(message)[:1000] or 'erro sem detalhes'}"
            )
        try:
            result = parser.analyse_nmap_xml_scan(xml)
            preserve_tls_metadata(result, xml)
        except Exception as exc:
            raise ScanError("O Nmap retornou uma resposta inválida. Confira a instalação.") from exc
        if errors:
            result["warning"] = clean_text(errors.decode("utf-8", errors="replace"))[:1000]
        return result
    except PermissionError as exc:
        raise ScanError("Permissão insuficiente para executar o Nmap.") from exc
    except FileNotFoundError as exc:
        raise ScanError("O executável do Nmap não foi encontrado.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(
            f"Timeout: o Nmap excedeu {SCAN_TIMEOUT} segundos. Tente um intervalo menor."
        ) from exc
    except OSError as exc:
        raise ScanError(f"Falha ao executar o Nmap: {exc}") from exc
    finally:
        if process is not None:
            stopped = stop_process(process)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            if not stopped:
                raise ScanError("Não foi possível encerrar o Nmap. Confira os processos ativos.")


def preserve_tls_metadata(result: dict, xml: bytes) -> None:
    """python-nmap 0.7.1 descarta o atributo tunnel do XML; preserve-o para HTTPS."""
    for host in ET.fromstring(xml).findall("host"):
        for address in host.findall("address"):
            info = result.get("scan", {}).get(address.get("addr"))
            if info is None:
                continue
            for port in host.findall("ports/port"):
                service = port.find("service")
                if service is not None and service.get("tunnel"):
                    metadata = info.get(port.get("protocol"), {}).get(int(port.get("portid")))
                    if metadata is not None:
                        metadata["tunnel"] = service.get("tunnel")


def scan_ports(target: str, ports: str | None = None) -> dict:
    if ports is not None:
        ports = validate_ports(ports)
    address = resolve_target(target)
    result = run_nmap(address, ports)
    host = result.get("scan", {}).get(address, {})
    open_ports = []
    for port, info in host.get("tcp", {}).items():
        if info.get("state") == "open":
            open_ports.append(
                {
                    "port": int(port),
                    "protocol": "tcp",
                    "state": "open",
                    "service": info.get("name") or "desconhecido",
                    "product": info.get("product") or "desconhecido",
                    "version": info.get("version") or "desconhecido",
                    "extrainfo": info.get("extrainfo") or "",
                    "tunnel": info.get("tunnel") or "",
                }
            )
    responded = bool(host) and host.get("status", {}).get("state", "up") == "up"
    return {
        "address": address,
        "status": "concluído" if responded else "sem resposta",
        "open_ports": sorted(open_ports, key=lambda item: item["port"]),
        "message": result.get("warning", "")
        if responded
        else "Alvo sem resposta na descoberta do Nmap. Confira endereço, conectividade e regras da rede.",
        "finished_at": now_iso(),
    }


def vulnerability_scan(target: str, port: int) -> dict:
    validate_ports(str(port))
    address = resolve_target(target)
    result = run_nmap(address, str(port), nse=True)
    host = result.get("scan", {}).get(address, {})
    scripts = dict(host.get("tcp", {}).get(port, {}).get("script", {}))
    for item in host.get("hostscript", []):
        scripts[item["id"]] = item.get("output", "")
    responded = bool(host) and host.get("status", {}).get("state", "up") == "up"
    return {
        "port": port,
        "at": now_iso(),
        "status": "concluído" if responded else "sem resposta",
        "scripts": {name: clean_text(output) for name, output in scripts.items()},
        "selection": NSE_EXPRESSION,
        "message": result.get("warning", "")
        if responded
        else "Alvo sem resposta durante a análise NSE.",
    }


def banner_grabbing(target: str, port: int, service: str | dict = "") -> dict:
    target = validate_target(target)
    url = build_web_url(target, port, service)
    result = {"port": port, "at": now_iso(), "status": "erro", "banner": ""}
    web = is_web_service(port, service)
    try:
        with ExitStack() as stack:
            connection = stack.enter_context(
                socket.create_connection((target, port), timeout=BANNER_TIMEOUT)
            )
            deadline = time.monotonic() + BANNER_TIMEOUT
            if web and uses_tls(port, service):
                context = ssl.create_default_context()
                connection = stack.enter_context(
                    context.wrap_socket(connection, server_hostname=target)
                )
            if web:
                authority = url.split("://", 1)[1]
                request = f"HEAD / HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
                connection.sendall(request.encode("ascii"))
            content = bytearray()
            while len(content) < MAX_BANNER_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                connection.settimeout(remaining)
                part = connection.recv(MAX_BANNER_BYTES - len(content))
                if not part:
                    break
                content.extend(part)
                if not web or b"\r\n\r\n" in content:
                    break
            if web:
                content = content.split(b"\r\n\r\n", 1)[0]
            banner = clean_text(content.decode("utf-8", errors="replace")).strip()
            result.update(
                status="concluído",
                banner=banner,
                message="Banner coletado." if banner else "Nenhum banner retornado pelo serviço.",
            )
    except ssl.SSLCertVerificationError:
        result["message"] = (
            "Certificado TLS não confiável ou incompatível com o alvo. Configure a CA do laboratório."
        )
    except ssl.SSLError:
        result["message"] = "Falha na negociação TLS. Confira o protocolo do serviço."
    except socket.gaierror:
        result["message"] = "DNS não resolvido. Confira o hostname."
    except TimeoutError:
        result.update(
            status="timeout", message="Timeout ao conectar ou aguardar o banner do serviço."
        )
    except ConnectionRefusedError:
        result["message"] = "Conexão recusada. O serviço pode não estar mais disponível."
    except PermissionError:
        result["message"] = "Permissão insuficiente para abrir a conexão."
    except OSError as exc:
        result["message"] = f"Erro de conexão: {exc}"
    return result
