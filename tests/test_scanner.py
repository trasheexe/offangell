import socket
import ssl
import subprocess
from unittest.mock import MagicMock, Mock

import pytest

from core import scanner


def nmap_response():
    return {
        "scan": {
            "127.0.0.1": {
                "status": {"state": "up"},
                "tcp": {
                    443: {"state": "open", "name": "https", "product": "nginx", "version": "1.2"},
                    22: {"state": "open", "name": "ssh"},
                    80: {"state": "closed", "name": "http"},
                },
            }
        }
    }


@pytest.fixture
def nmap_process(monkeypatch):
    parser = Mock()
    parser.analyse_nmap_xml_scan.return_value = nmap_response()
    monkeypatch.setattr(
        scanner, "create_scanner", lambda: (parser, "C:/Program Files/Nmap/nmap.exe")
    )
    process = Mock()
    process.communicate.return_value = (b"<nmaprun/>", b"")
    process.returncode = 0
    process.poll.return_value = 0
    factory = Mock(return_value=process)
    monkeypatch.setattr(scanner.subprocess, "Popen", factory)
    return parser, process, factory


def test_nmap_quick_mode_and_no_automatic_analysis(nmap_process):
    parser, process, factory = nmap_process
    scanner.run_nmap("127.0.0.1", None)
    command = factory.call_args.args[0]
    assert command[0] == "C:/Program Files/Nmap/nmap.exe"
    assert command[command.index("--top-ports") + 1] == "100"
    assert "-sT" in command and "-sV" in command and "--script" not in command
    assert factory.call_args.kwargs["shell"] is False
    process.communicate.assert_called_once_with(timeout=scanner.SCAN_TIMEOUT)
    parser.analyse_nmap_xml_scan.assert_called_once_with(b"<nmaprun/>")
    process.stdout.close.assert_called_once()


@pytest.mark.parametrize("ports", ["1-65535", "22,80,443", "1-1000"])
def test_nmap_port_modes(nmap_process, ports):
    scanner.run_nmap("127.0.0.1", ports)
    command = nmap_process[2].call_args.args[0]
    assert command[command.index("-p") + 1] == ports
    assert "--top-ports" not in command


def test_nmap_ipv6_and_nse_profile(nmap_process):
    scanner.run_nmap("::1", "443", nse=True)
    command = nmap_process[2].call_args.args[0]
    assert "-6" in command and command[-1] == "::1"
    expression = command[command.index("--script") + 1]
    assert "vuln and safe" in expression and "not" in expression
    assert all(
        category in expression for category in ("brute", "exploit", "dos", "intrusive", "auth")
    )
    assert "--script-timeout" in command


def test_nmap_rejects_input_before_starting_process(nmap_process):
    with pytest.raises(ValueError):
        scanner.run_nmap("--script", "80")
    with pytest.raises(ValueError):
        scanner.run_nmap("127.0.0.1", "80 --script vuln")
    nmap_process[2].assert_not_called()


@pytest.mark.parametrize(
    "error,expected",
    [
        (subprocess.TimeoutExpired("nmap", 1), "Timeout"),
        (PermissionError(), "Permissão"),
        (FileNotFoundError(), "não foi encontrado"),
    ],
)
def test_nmap_failures_and_cleanup(nmap_process, monkeypatch, error, expected):
    nmap_process[1].communicate.side_effect = error
    stop = Mock()
    monkeypatch.setattr(scanner, "stop_process", stop)
    with pytest.raises(scanner.ScanError, match=expected):
        scanner.run_nmap("127.0.0.1", None)
    stop.assert_called_once_with(nmap_process[1])


def test_nmap_keyboard_interrupt_cleans_up(nmap_process, monkeypatch):
    nmap_process[1].communicate.side_effect = KeyboardInterrupt
    stop = Mock()
    monkeypatch.setattr(scanner, "stop_process", stop)
    with pytest.raises(KeyboardInterrupt):
        scanner.run_nmap("127.0.0.1", None)
    stop.assert_called_once()


def test_nmap_permission_failure_from_stderr(nmap_process):
    nmap_process[1].returncode = 1
    nmap_process[1].communicate.return_value = (b"", b"requires root privileges")
    with pytest.raises(scanner.ScanError, match="Permissão"):
        scanner.run_nmap("127.0.0.1", None)


def test_invalid_xml_has_friendly_error(nmap_process):
    nmap_process[0].analyse_nmap_xml_scan.side_effect = ValueError("invalid XML")
    with pytest.raises(scanner.ScanError, match="resposta inválida"):
        scanner.run_nmap("127.0.0.1", None)


def test_scan_extracts_and_sorts_only_open_tcp_ports(monkeypatch):
    monkeypatch.setattr(scanner, "run_nmap", Mock(return_value=nmap_response()))
    result = scanner.scan_ports("127.0.0.1")
    assert result["status"] == "concluído"
    assert [item["port"] for item in result["open_ports"]] == [22, 443]
    assert result["open_ports"][0]["version"] == "desconhecido"
    assert result["open_ports"][1]["product"] == "nginx"


@pytest.mark.parametrize(
    "host,status", [({}, "sem resposta"), ({"status": {"state": "up"}}, "concluído")]
)
def test_no_response_differs_from_no_open_ports(monkeypatch, host, status):
    monkeypatch.setattr(scanner, "run_nmap", lambda *a, **kw: {"scan": {"127.0.0.1": host}})
    result = scanner.scan_ports("127.0.0.1")
    assert result["status"] == status and result["open_ports"] == []


def test_dns_failure(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", Mock(side_effect=socket.gaierror()))
    with pytest.raises(scanner.ScanError, match="DNS não resolvido"):
        scanner.resolve_target("missing.test")


def test_dns_uses_only_one_address_and_supports_ipv6(monkeypatch):
    addresses = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: list(addresses))
    assert scanner.resolve_target("localhost") == "127.0.0.1"
    addresses.pop()
    assert scanner.resolve_target("localhost") == "::1"


def test_missing_nmap(monkeypatch):
    monkeypatch.setattr(scanner, "find_executable", lambda paths: None)
    with pytest.raises(scanner.ScanError, match="Nmap não foi encontrado"):
        scanner.create_scanner()


def test_nse_port_and_host_results(monkeypatch):
    data = nmap_response()
    host = data["scan"]["127.0.0.1"]
    host["tcp"][443]["script"] = {"check": "indício"}
    host["hostscript"] = [{"id": "host-check", "output": "resultado"}]
    runner = Mock(return_value=data)
    monkeypatch.setattr(scanner, "run_nmap", runner)
    result = scanner.vulnerability_scan("127.0.0.1", 443)
    assert result["scripts"] == {"check": "indício", "host-check": "resultado"}
    runner.assert_called_once_with("127.0.0.1", "443", nse=True)


@pytest.fixture
def fake_socket(monkeypatch):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.recv.return_value = b"SSH-2.0-OpenSSH_test\r\n"
    create = Mock(return_value=connection)
    monkeypatch.setattr(socket, "create_connection", create)
    return connection, create


def test_passive_banner_uses_create_connection_and_closes(fake_socket):
    connection, create = fake_socket
    result = scanner.banner_grabbing("::1", 22, "ssh")
    create.assert_called_once_with(("::1", 22), timeout=scanner.BANNER_TIMEOUT)
    connection.sendall.assert_not_called()
    assert result["banner"] == "SSH-2.0-OpenSSH_test"
    connection.__exit__.assert_called_once()


def test_http_head_collects_only_headers_and_redacts_cookies(fake_socket):
    connection, _ = fake_socket
    connection.recv.side_effect = [
        b"HTTP/1.1 200 OK\r\nSet-Cookie: secret\r\n",
        b"Server: test\r\n\r\nBODY",
    ]
    result = scanner.banner_grabbing("localhost", 8080, "http")
    connection.sendall.assert_called_once_with(
        b"HEAD / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\n\r\n"
    )
    assert result["status"] == "concluído"
    assert "secret" not in result["banner"] and "BODY" not in result["banner"]


def test_https_wraps_socket_with_verified_tls(fake_socket, monkeypatch):
    connection, _ = fake_socket
    context = Mock()
    context.wrap_socket.return_value = connection
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    connection.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
    assert scanner.banner_grabbing("localhost", 443, "https")["status"] == "concluído"
    context.wrap_socket.assert_called_once_with(connection, server_hostname="localhost")


@pytest.mark.parametrize(
    "error,expected",
    [
        (TimeoutError(), "Timeout"),
        (ConnectionRefusedError(), "recusada"),
        (socket.gaierror(), "DNS"),
        (PermissionError(), "Permissão"),
        (ssl.SSLCertVerificationError(), "Certificado TLS"),
        (ssl.SSLError(), "TLS"),
    ],
)
def test_banner_connection_errors(monkeypatch, error, expected):
    monkeypatch.setattr(socket, "create_connection", Mock(side_effect=error))
    assert expected in scanner.banner_grabbing("localhost", 443, "https")["message"]


def test_banner_read_timeout_closes_connection(fake_socket):
    connection, _ = fake_socket
    connection.recv.side_effect = TimeoutError
    assert scanner.banner_grabbing("localhost", 22, "ssh")["status"] == "timeout"
    connection.__exit__.assert_called_once()


def test_real_python_nmap_parser_preserves_tls_on_custom_port(monkeypatch):
    xml = b"""<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="mock" version="7.99">
      <scaninfo type="connect" protocol="tcp" numservices="1" services="9443"/>
      <host><status state="up" reason="conn-refused"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="9443">
          <state state="open" reason="syn-ack"/>
          <service name="http" product="test server" version="1.0" tunnel="ssl"/>
          <script id="test-check" output="example result"/>
        </port></ports>
      </host>
      <runstats><finished timestr="test" elapsed="1.0"/>
        <hosts up="1" down="0" total="1"/></runstats>
    </nmaprun>"""
    version_process = Mock()
    version_process.communicate.return_value = (b"Nmap version 7.99 ( https://nmap.org )\n", b"")
    scan_process = Mock(returncode=0)
    scan_process.communicate.return_value = (xml, b"")
    scan_process.poll.return_value = 0
    popen = Mock(side_effect=[version_process, scan_process])
    monkeypatch.setattr(scanner.subprocess, "Popen", popen)
    monkeypatch.setattr(scanner, "find_executable", lambda paths: "/mock/nmap")
    result = scanner.scan_ports("127.0.0.1", "9443")
    service = result["open_ports"][0]
    assert service["tunnel"] == "ssl"
    assert scanner.build_web_url("127.0.0.1", 9443, service) == "https://127.0.0.1:9443"
    assert service["product"] == "test server" and service["version"] == "1.0"
    assert len(popen.call_args_list) == 2
