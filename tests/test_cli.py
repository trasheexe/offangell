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
            ("ZAP Baseline", False, "não encontrado"),
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
