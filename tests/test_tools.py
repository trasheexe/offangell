import os
import subprocess
import sys
from unittest.mock import Mock

import pytest

from core import tools


def test_find_executable_on_path(monkeypatch, tmp_path):
    path = tmp_path / "Program Files" / "Nmap" / "nmap.exe"
    monkeypatch.setattr(tools.shutil, "which", lambda value: str(path) if value == "nmap" else None)
    assert tools.find_executable(("nmap",)) == str(path.resolve())


def test_find_known_path_with_spaces(monkeypatch, tmp_path):
    path = tmp_path / "Program Files" / "nmap.exe"
    path.parent.mkdir()
    path.touch()
    path.chmod(0o755)
    monkeypatch.setattr(tools.shutil, "which", lambda value: None)
    assert tools.find_executable((str(path),)) == str(path.resolve())


def test_find_non_executable_script_on_path(monkeypatch, tmp_path):
    path = tmp_path / "zap-baseline.py"
    path.touch()
    monkeypatch.setattr(tools.shutil, "which", lambda value: None)
    monkeypatch.setattr(os, "get_exec_path", lambda: [str(tmp_path)])
    assert tools.find_executable(("zap-baseline.py",), scripts=True) == str(path.resolve())


def test_missing_executable_and_batch_files(monkeypatch, tmp_path):
    monkeypatch.setattr(tools.shutil, "which", lambda value: None)
    assert tools.find_executable((str(tmp_path / "missing.exe"),)) is None
    path = tmp_path / "tool.cmd"
    path.touch()
    assert tools.find_executable((str(path),)) is None


def test_script_interpreters(monkeypatch):
    monkeypatch.setattr(tools, "find_executable", lambda paths, **kw: "perl.exe")
    assert tools.script_command("C:/Program Files/nikto.pl") == [
        "perl.exe",
        "C:/Program Files/nikto.pl",
    ]
    assert tools.script_command("zap-baseline.py") == [sys.executable, "zap-baseline.py"]
    monkeypatch.setattr(tools, "find_executable", lambda paths, **kw: None)
    assert tools.script_command("nikto.pl") is None


def test_dependency_check_does_not_run_commands(monkeypatch):
    monkeypatch.setattr(tools, "find_executable", lambda paths, **kw: None)
    monkeypatch.setattr(tools.importlib.util, "find_spec", lambda name: None)
    rows = tools.dependency_status()
    assert rows[0][0] == "Python" and rows[0][1]
    assert all(not available for _, available, _ in rows[1:])


def test_optional_tools_missing(monkeypatch):
    monkeypatch.setattr(tools, "find_executable", lambda paths, **kw: None)
    assert tools.run_nikto("localhost", 80)["status"] == "indisponível"
    assert tools.run_zap("localhost", 443)["status"] == "indisponível"


def test_nikto_command_is_defensive_and_https(monkeypatch):
    monkeypatch.setattr(
        tools, "find_executable", lambda paths, **kw: "C:/Program Files/Nikto/nikto.exe"
    )
    runner = Mock(return_value={"status": "concluído"})
    monkeypatch.setattr(tools, "run_command", runner)
    tools.run_nikto("localhost", 8443, "https")
    command = runner.call_args.args[0]
    assert command[0] == "C:/Program Files/Nikto/nikto.exe"
    assert command[command.index("-h") + 1] == "https://localhost:8443"
    assert command[command.index("-Tuning") + 1] == "2b"
    assert command[command.index("-Plugins") + 1] == "headers;tests"


@pytest.mark.parametrize(
    "code,expected", [(0, "concluído"), (1, "alertas"), (2, "alertas"), (3, "erro")]
)
def test_zap_baseline_exit_codes(monkeypatch, code, expected):
    monkeypatch.setattr(tools, "find_executable", lambda paths, **kw: "/zap/zap-baseline.py")
    runner = Mock(return_value={"returncode": code, "status": "concluído" if code == 0 else "erro"})
    monkeypatch.setattr(tools, "run_command", runner)
    monkeypatch.setattr(tools.subprocess, "run", Mock(return_value=Mock(returncode=0)))
    assert tools.run_zap("::1", 443, "https")["status"] == expected
    command = runner.call_args.args[0]
    assert command[:2] == [sys.executable, "/zap/zap-baseline.py"]
    assert "https://[::1]:443" in command
    assert "zap-full-scan.py" not in command


def test_run_command_uses_argument_list_and_timeout(monkeypatch):
    process = Mock()
    process.wait.return_value = 0
    process.poll.return_value = 0
    popen = Mock(return_value=process)
    monkeypatch.setattr(tools.subprocess, "Popen", popen)
    result = tools.run_command(["path with spaces.exe", "-h", "http://localhost:80"], timeout=12)
    assert result["status"] == "concluído"
    assert popen.call_args.kwargs["shell"] is False
    process.wait.assert_called_once_with(timeout=12)
    assert "output" not in result


@pytest.mark.parametrize(
    "error,status",
    [
        (FileNotFoundError(), "erro"),
        (PermissionError(), "erro"),
        (subprocess.TimeoutExpired("test", 1), "timeout"),
        (KeyboardInterrupt(), "cancelado"),
    ],
)
def test_process_errors_and_cleanup(monkeypatch, error, status):
    process = Mock()
    process.wait.side_effect = error
    monkeypatch.setattr(tools.subprocess, "Popen", Mock(return_value=process))
    stop = Mock()
    monkeypatch.setattr(tools, "stop_process", stop)
    assert tools.run_command(["fake"])["status"] == status
    stop.assert_called_once_with(process)


def test_failed_process_start(monkeypatch):
    monkeypatch.setattr(tools.subprocess, "Popen", Mock(side_effect=FileNotFoundError()))
    assert tools.run_command(["missing"])["status"] == "erro"


def test_zap_broken_environment_does_not_start_scan(monkeypatch):
    monkeypatch.setattr(tools, "find_executable", lambda *a, **kw: "/zap/zap-baseline.py")
    probe = Mock(return_value=Mock(returncode=1))
    runner = Mock()
    monkeypatch.setattr(tools.subprocess, "run", probe)
    monkeypatch.setattr(tools, "run_command", runner)
    result = tools.run_zap("localhost", 443, "https")
    assert result["status"] == "indisponível"
    assert probe.call_args.args[0][-1] == "-h"
    runner.assert_not_called()


def test_process_tree_cleanup(monkeypatch):
    process = Mock(pid=12345)
    process.poll.return_value = None
    if os.name == "nt":
        kill = Mock()
        monkeypatch.setattr(tools.subprocess, "run", kill)
        tools.stop_process(process)
        assert kill.call_args.args[0][1:] == ["/PID", "12345", "/T", "/F"]
    else:
        kill = Mock()
        monkeypatch.setattr(tools.os, "killpg", kill)
        tools.stop_process(process)
        kill.assert_called_once_with(12345, tools.signal.SIGTERM)
    process.wait.assert_called_once_with(timeout=3)


def test_failed_cleanup_is_reported(monkeypatch):
    process = Mock()
    process.wait.side_effect = KeyboardInterrupt
    monkeypatch.setattr(tools.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(tools, "stop_process", lambda process: False)
    result = tools.run_command(["fake"])
    assert result["status"] == "cancelado"
    assert "Não foi possível encerrar" in result["message"]
