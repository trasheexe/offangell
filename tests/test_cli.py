import builtins
import runpy
from unittest.mock import Mock

import pytest

import offangell as cli
from core.reports import new_report, save_report


@pytest.fixture
def cli_inputs(monkeypatch):
    monkeypatch.setattr(cli, "header", lambda title: None)
    monkeypatch.setattr(cli, "pause", lambda: None)
    monkeypatch.setattr(cli, "init", lambda **kwargs: None)

    def set_inputs(values):
        answers = iter(values)
        monkeypatch.setattr(builtins, "input", lambda prompt="": next(answers))

    return set_inputs


def example_report():
    report = new_report("127.0.0.1", "rápido", None)
    report["open_ports"] = [
        {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.2"}
    ]
    report["status"] = "concluído"
    return report


def test_dependency_menu_and_exit_without_optional_tools(cli_inputs, monkeypatch, capsys):
    cli_inputs(["2", "5"])
    monkeypatch.setattr(
        cli,
        "dependency_status",
        lambda: [
            ("Python", True, "3.13"),
            ("Nikto", False, "não encontrado"),
            ("ZAP Automation Framework", False, "não encontrado"),
        ],
    )
    cli.main()
    output = capsys.readouterr().out
    assert "[OK] Python" in output and "[--] Nikto" in output and "encerrado" in output


def test_menu_imports_without_python_dependencies(monkeypatch, capsys):
    real_import = builtins.__import__

    def missing_optional(name, *args, **kwargs):
        if name in {"colorama", "nmap"}:
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_optional)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "5")
    runpy.run_path("offangell.py", run_name="__main__")
    assert "encerrado" in capsys.readouterr().out


def test_invalid_target_does_not_start_scan(cli_inputs, monkeypatch, capsys):
    cli_inputs(["https://localhost/test"])
    scan = Mock()
    monkeypatch.setattr(cli, "scan_ports", scan)
    assert cli.start_scanner() is False
    scan.assert_not_called()
    assert "somente hostname/IP" in capsys.readouterr().out


def test_invalid_index_has_message_and_no_automatic_analysis(cli_inputs, monkeypatch, capsys):
    cli_inputs(["99", "-1", "443", "s"])
    action = Mock()
    monkeypatch.setattr(cli, "off_angel_menu", action)
    cli.ports_menu(example_report())
    assert capsys.readouterr().out.count("Índice inválido") == 3
    action.assert_not_called()


def test_port_menu_does_not_run_analysis_on_entry(cli_inputs, monkeypatch):
    cli_inputs(["7"])
    action = Mock()
    monkeypatch.setattr(cli, "analyze_port", action)
    report = example_report()
    assert cli.off_angel_menu(report, report["open_ports"][0]) is False
    action.assert_not_called()


@pytest.mark.parametrize(
    "choice,function,key",
    [
        ("2", "banner_grabbing", "banners"),
        ("3", "vulnerability_scan", "nse"),
        ("4", "run_nikto", "tools"),
        ("5", "run_zap", "tools"),
    ],
)
def test_analysis_requires_explicit_choice(cli_inputs, monkeypatch, choice, function, key):
    cli_inputs([choice, "7"])
    mocks = {}
    for name in ("banner_grabbing", "vulnerability_scan", "run_nikto", "run_zap"):
        mocks[name] = Mock(
            return_value={"message": "resultado", "scripts": {}, "status": "concluído"}
        )
        monkeypatch.setattr(cli, name, mocks[name])
    report = example_report()
    cli.off_angel_menu(report, report["open_ports"][0])
    mocks[function].assert_called_once()
    assert all(mock.call_count == 0 for name, mock in mocks.items() if name != function)
    assert len(report[key]) == 1


def test_end_to_end_menu_scan_and_save_uses_mocks(cli_inputs, monkeypatch, tmp_path):
    cli_inputs(["1", "127.0.0.1", "3", "22,443", "r", "2", "s", "5"])
    scan = Mock(
        return_value={
            "status": "concluído",
            "address": "127.0.0.1",
            "open_ports": example_report()["open_ports"],
        }
    )
    monkeypatch.setattr(cli, "scan_ports", scan)
    monkeypatch.setattr(cli, "save_report", lambda report, fmt: save_report(report, fmt, tmp_path))
    cli.main()
    scan.assert_called_once_with("127.0.0.1", "22,443")
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_scan_failure_can_be_saved(cli_inputs, monkeypatch, tmp_path):
    cli_inputs(["127.0.0.1", "1", "r", "1", "s"])
    monkeypatch.setattr(cli, "scan_ports", Mock(side_effect=cli.ScanError("Nmap ausente")))
    monkeypatch.setattr(cli, "save_report", lambda report, fmt: save_report(report, fmt, tmp_path))
    cli.start_scanner()
    assert "Nmap ausente" in next(tmp_path.glob("*.txt")).read_text(encoding="utf-8")


def test_ctrl_c_cancels_analysis_without_losing_report(cli_inputs, monkeypatch):
    monkeypatch.setattr(cli, "vulnerability_scan", Mock(side_effect=KeyboardInterrupt))
    report = example_report()
    cli.analyze_port("3", report, report["open_ports"][0])
    assert report["nse"][0]["status"] == "cancelado"


def test_ctrl_c_on_main_exits_cleanly(monkeypatch, capsys):
    monkeypatch.setattr(cli, "header", lambda title: None)
    monkeypatch.setattr(builtins, "input", Mock(side_effect=KeyboardInterrupt))
    cli.main()
    assert "encerrado" in capsys.readouterr().out


def test_non_web_tools_not_started(cli_inputs, monkeypatch, capsys):
    runner = Mock()
    monkeypatch.setattr(cli, "run_nikto", runner)
    cli.analyze_port("4", example_report(), {"port": 22, "service": "ssh"})
    runner.assert_not_called()
    assert "não foi identificado" in capsys.readouterr().out


def test_unexpected_error_followed_by_eof_never_shows_traceback(monkeypatch, capsys):
    monkeypatch.setattr(cli, "header", Mock(side_effect=OSError("terminal indisponível")))
    monkeypatch.setattr(builtins, "input", Mock(side_effect=EOFError))
    cli.main()
    output = capsys.readouterr().out
    assert "terminal indisponível" in output and "encerrado" in output


def test_windows_legacy_output_encoding_is_configured(monkeypatch):
    stream = Mock()
    monkeypatch.setattr(cli.sys, "stdout", stream)
    monkeypatch.setattr(cli, "init", lambda **kw: None)
    monkeypatch.setattr(cli, "header", lambda title: None)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "5")
    cli.main()
    stream.reconfigure.assert_called_once_with(encoding="utf-8", errors="replace")


def test_web_scanner_preserves_url_and_saves_nuclei_findings(cli_inputs, monkeypatch, tmp_path):
    url = "https://example.test:8443/app/path?mode=1"
    cli_inputs([url, "s", "1"])
    result = {
        "status": "concluído",
        "address": "192.0.2.1",
        "tools": [{"tool": "Nuclei", "status": "concluído"}],
        "nuclei_findings": [{"template_id": "http-missing-security-headers"}],
        "nuclei_severity_counts": {"High": 1},
    }
    runner = Mock(return_value=result)
    saved = {}
    monkeypatch.setattr(cli, "run_web_scan", runner)
    monkeypatch.setattr(cli, "load_config", lambda: {"nuclei": {"enabled": True}})
    monkeypatch.setattr(
        cli,
        "save_report",
        lambda report, fmt: saved.update(report=report, format=fmt) or tmp_path / "report.json",
    )
    cli.start_web_scanner()
    runner.assert_called_once()
    assert runner.call_args.args[0] == url
    assert saved["report"]["target"] == "example.test"
    assert saved["report"]["web_target"] == url
    assert saved["report"]["nuclei_findings"] == result["nuclei_findings"]
    assert saved["format"] == "json"


def test_web_scanner_requires_authorization_before_network(cli_inputs, monkeypatch):
    cli_inputs(["https://example.test", "n"])
    runner = Mock()
    monkeypatch.setattr(cli, "run_web_scan", runner)
    assert cli.start_web_scanner() is False
    runner.assert_not_called()


def test_controlled_load_test_requires_confirmation_and_saves_reports(cli_inputs, monkeypatch):
    url = "https://example.test/health"
    cli_inputs([url, "s", "3"])
    runner = Mock(return_value={
        "tool": "Teste HTTP controlado", "status": "conclu\u00eddo", "target": url,
        "hostname": "example.test", "started_at": "start", "finished_at": "end",
        "duration_limit_seconds": 3, "rate_limit_per_second": 1, "request_limit": 3,
        "requests_sent": 3, "http_status_counts": {"200": 3},
        "average_latency_ms": 1.0, "errors": {}, "message": "limited",
    })
    saved = []
    monkeypatch.setattr(cli, "run_controlled_http_test", runner)
    monkeypatch.setattr(cli, "save_report", lambda report, fmt: saved.append((report, fmt)) or fmt)
    cli.start_controlled_load_test()
    runner.assert_called_once_with(url, authorized=True, duration=3)
    assert [fmt for _, fmt in saved] == ["txt", "json"]
    assert saved[0][0]["tools"][0]["requests_sent"] == 3


def test_controlled_load_test_refusal_sends_no_requests(cli_inputs, monkeypatch):
    cli_inputs(["https://example.test/", "n"])
    runner = Mock()
    monkeypatch.setattr(cli, "run_controlled_http_test", runner)
    cli.start_controlled_load_test()
    runner.assert_not_called()


def test_nuclei_template_update_requires_yes_in_configuration_menu(cli_inputs, monkeypatch):
    cli_inputs(["7", "n", "8"])
    settings = {
        "enabled": True,
        "executable_path": "",
        "templates_directory": "",
        "timeout": 600,
        "rate_limit": 2,
        "concurrency": 2,
    }
    monkeypatch.setattr(cli, "load_config", lambda: {"nuclei": settings})
    update = Mock()
    monkeypatch.setattr(cli, "update_nuclei_templates", update)
    cli.nuclei_settings_menu()
    update.assert_not_called()


def test_nuclei_template_update_runs_only_after_confirmation(cli_inputs, monkeypatch):
    cli_inputs(["7", "s", "8"])
    settings = {
        "enabled": True,
        "executable_path": "",
        "templates_directory": "",
        "timeout": 600,
        "rate_limit": 2,
        "concurrency": 2,
    }
    monkeypatch.setattr(cli, "load_config", lambda: {"nuclei": settings})
    update = Mock(return_value={"status": "concluído", "message": "updated"})
    monkeypatch.setattr(cli, "update_nuclei_templates", update)
    cli.nuclei_settings_menu()
    update.assert_called_once()
    assert update.call_args.kwargs["confirm"] is True
