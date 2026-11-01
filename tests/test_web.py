import socket
import urllib.error
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core import web
from core.config import NUCLEI_DEFAULTS


def address_info(host="127.0.0.1", port=8443):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]


def test_resolve_and_connect_checks_only_one_address(monkeypatch):
    dns = Mock(
        return_value=[
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 8443, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 8443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.11", 8443)),
        ]
    )
    connection = Mock()
    connect = Mock(return_value=connection)
    monkeypatch.setattr(web.socket, "getaddrinfo", dns)
    monkeypatch.setattr(web.socket, "create_connection", connect)
    result = web.resolve_web_target("https://example.test:8443/app?q=1")
    assert result == {"host": "example.test", "address": "192.0.2.10", "port": 8443,
                      "protocol": "https", "path": "/app"}
    dns.assert_called_once_with("example.test", 8443, type=socket.SOCK_STREAM)
    connect.assert_called_once_with(("192.0.2.10", 8443), timeout=web.CONNECT_TIMEOUT)
    connection.close.assert_called_once()


def test_ipv6_connectivity_uses_the_selected_ip_and_url_port(monkeypatch):
    monkeypatch.setattr(
        web.socket,
        "getaddrinfo",
        Mock(return_value=[(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 9443, 0, 0))]),
    )
    connection = Mock()
    connect = Mock(return_value=connection)
    monkeypatch.setattr(web.socket, "create_connection", connect)
    result = web.resolve_web_target("https://[2001:db8::1]:9443/app")
    assert result["address"] == "2001:db8::1"
    connect.assert_called_once_with(("2001:db8::1", 9443), timeout=web.CONNECT_TIMEOUT)


def test_dns_and_connectivity_errors_stop_web_tools(monkeypatch):
    monkeypatch.setattr(web.socket, "getaddrinfo", Mock(side_effect=socket.gaierror()))
    zap, nikto, nuclei = Mock(), Mock(), Mock()
    monkeypatch.setattr(web, "run_zap", zap)
    monkeypatch.setattr(web, "run_nikto", nikto)
    monkeypatch.setattr(web, "run_nuclei", nuclei)
    result = web.run_web_scan("https://missing.test/path")
    assert result["status"] == "erro"
    assert "DNS" in result["message"]
    zap.assert_not_called()
    nikto.assert_not_called()
    nuclei.assert_not_called()


def test_web_flow_preserves_original_url_and_runs_tools_in_order(monkeypatch):
    monkeypatch.setattr(web.socket, "getaddrinfo", Mock(return_value=address_info()))
    monkeypatch.setattr(web.socket, "create_connection", Mock(return_value=Mock()))
    monkeypatch.setattr(web, "_http_probe", Mock(return_value={"status": "conectado", "http_status": 200,
        "final_url": "https://example.test:8443/app/path?mode=full", "redirects": [], "headers": {}, "technologies": []}))
    calls = []

    def runner(name, result):
        def run(url, *args, **kwargs):
            calls.append((name, url))
            return {"tool": name, "status": "concluído", **result}

        return run

    monkeypatch.setattr(web, "run_zap", runner("ZAP Automation Framework", {}))
    monkeypatch.setattr(web, "run_nikto", runner("Nikto", {}))
    monkeypatch.setattr(
        web,
        "run_nuclei",
        runner("Nuclei", {"findings": [{"template_id": "test"}], "severity_counts": {"High": 1}}),
    )
    url = "https://example.test:8443/app/path?mode=full"
    result = web.run_web_scan(url)
    assert calls == [("ZAP Automation Framework", url), ("Nikto", url), ("Nuclei", url)]
    assert result["target_url"] == url
    assert result["address"] == "127.0.0.1"
    assert result["nuclei_findings"] == [{"template_id": "test"}]
    assert result["nuclei_severity_counts"] == {"High": 1}
    assert result["tools"][-1]["tool"] == "Nuclei"
    assert "findings" not in result["tools"][-1]


def test_nuclei_failure_does_not_interrupt_zap_or_nikto(monkeypatch):
    monkeypatch.setattr(web.socket, "getaddrinfo", Mock(return_value=address_info()))
    monkeypatch.setattr(web.socket, "create_connection", Mock(return_value=Mock()))
    monkeypatch.setattr(web, "_http_probe", Mock(return_value={"status": "conectado", "http_status": 200,
        "final_url": "http://example.test/", "redirects": [], "headers": {}, "technologies": []}))
    zap = Mock(return_value={"tool": "ZAP Automation Framework", "status": "concluído"})
    nikto = Mock(return_value={"tool": "Nikto", "status": "concluído"})
    nuclei = Mock(return_value={"tool": "Nuclei", "status": "erro", "findings": [], "severity_counts": {}})
    monkeypatch.setattr(web, "run_zap", zap)
    monkeypatch.setattr(web, "run_nikto", nikto)
    monkeypatch.setattr(web, "run_nuclei", nuclei)
    result = web.run_web_scan("http://example.test")
    assert zap.call_count == nikto.call_count == nuclei.call_count == 1
    assert [tool["tool"] for tool in result["tools"]] == ["ZAP Automation Framework", "Nikto", "Nuclei"]
    assert result["nuclei_findings"] == []


def test_disabled_nuclei_does_not_prevent_other_web_tools(monkeypatch):
    monkeypatch.setattr(web.socket, "getaddrinfo", Mock(return_value=address_info(port=80)))
    monkeypatch.setattr(web.socket, "create_connection", Mock(return_value=Mock()))
    monkeypatch.setattr(web, "_http_probe", Mock(return_value={"status": "conectado", "http_status": 200,
        "final_url": "http://example.test/", "redirects": [], "headers": {}, "technologies": []}))
    zap = Mock(return_value={"tool": "ZAP Automation Framework", "status": "concluído"})
    nikto = Mock(return_value={"tool": "Nikto", "status": "concluído"})
    nuclei = Mock()
    monkeypatch.setattr(web, "run_zap", zap)
    monkeypatch.setattr(web, "run_nikto", nikto)
    monkeypatch.setattr(web, "run_nuclei", nuclei)
    settings = {**NUCLEI_DEFAULTS, "enabled": False}
    result = web.run_web_scan("http://example.test", nuclei_settings=settings)
    nuclei.assert_not_called()
    assert result["tools"][-1]["status"] == "desativado"
    assert result["nuclei_severity_counts"] == {}
    assert len(result["tools"]) == 3


def test_unavailable_nuclei_does_not_report_simulated_zero_counts(monkeypatch):
    monkeypatch.setattr(web.socket, "getaddrinfo", Mock(return_value=address_info(port=80)))
    monkeypatch.setattr(web.socket, "create_connection", Mock(return_value=Mock()))
    monkeypatch.setattr(web, "_http_probe", Mock(return_value={"status": "conectado", "http_status": 200,
        "final_url": "http://example.test/", "redirects": [], "headers": {}, "technologies": []}))
    monkeypatch.setattr(web, "run_zap", Mock(return_value={"tool": "ZAP Automation Framework"}))
    monkeypatch.setattr(web, "run_nikto", Mock(return_value={"tool": "Nikto"}))
    monkeypatch.setattr(
        web,
        "run_nuclei",
        Mock(return_value={"tool": "Nuclei", "status": "indisponível", "findings": [], "severity_counts": {}}),
    )
    result = web.run_web_scan("http://example.test")
    assert result["nuclei_severity_counts"] == {}


def test_external_redirect_stops_scanners(monkeypatch):
    monkeypatch.setattr(web.socket, "getaddrinfo", Mock(return_value=address_info(port=80)))
    monkeypatch.setattr(web.socket, "create_connection", Mock(return_value=Mock()))
    monkeypatch.setattr(web, "_http_probe", Mock(return_value={
        "status": "fora_escopo", "redirects": ["https://outside.test/"],
        "message": "Redirecionamento externo bloqueado.",
    }))
    zap, nikto = Mock(), Mock()
    monkeypatch.setattr(web, "run_zap", zap)
    monkeypatch.setattr(web, "run_nikto", nikto)
    result = web.run_web_scan("http://example.test")
    assert result["status"] == "fora_escopo"
    zap.assert_not_called()
    nikto.assert_not_called()


def test_scoped_redirect_rejects_external_host_and_port():
    handler = web._ScopedRedirect("example.test", 80)
    request = SimpleNamespace(full_url="http://example.test/", headers={})
    with pytest.raises(urllib.error.HTTPError, match="fora do escopo"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://outside.test/")


def test_http_probe_extracts_headers_and_technology(monkeypatch):
    response = Mock()
    response.status = 200
    response.headers = {"Server": "nginx", "X-Powered-By": "Example"}
    response.read.return_value = b'<meta name="generator" content="CMS 1.0">'
    response.geturl.return_value = "http://example.test/"
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(web.urllib.request, "build_opener", Mock(return_value=opener))
    result = web._http_probe("http://example.test/")
    assert result["status"] == "conectado"
    assert result["headers"]["Server"] == "nginx"
    assert [item["source"] for item in result["technologies"]] == [
        "server", "x-powered-by", "meta generator"
    ]
    response.read.assert_called_once_with(web.HTTP_BODY_LIMIT)
