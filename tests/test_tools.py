import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from core import tools


def test_find_executable_on_path(monkeypatch, tmp_path):
    from core import config
    monkeypatch.setattr(config, "TOOLS_ROOT", tmp_path / "Tools")
    path = tmp_path / "Program Files" / "Nmap" / "nmap.exe"
    path.parent.mkdir(parents=True); path.touch()
    monkeypatch.setattr(tools.shutil, "which", lambda value: str(path) if value == "nmap" else None)
    assert tools.find_executable(("nmap",)) == str(path.resolve())


def test_recursive_tools_search_and_configured_path_precedence(monkeypatch, tmp_path):
    from core import config
    root = tmp_path / "Tools Root"
    monkeypatch.setattr(config, "TOOLS_ROOT", root)
    actual = root / "Nuclei" / "nested folder" / "nuclei.exe"
    actual.parent.mkdir(parents=True); actual.touch()
    path_tool = tmp_path / "Path" / "nuclei.exe"
    path_tool.parent.mkdir(); path_tool.touch()
    monkeypatch.setattr(tools.shutil, "which", lambda value: str(path_tool))
    assert tools.find_executable(("nuclei.exe",)) == str(actual.resolve())
    configured = tmp_path / "Custom Path" / "nuclei.exe"
    configured.parent.mkdir(); configured.touch()
    assert tools.find_executable(("nuclei.exe",), configured_path=str(configured)) == str(configured.resolve())


def test_path_fallback_and_missing_tool(monkeypatch, tmp_path):
    from core import config
    monkeypatch.setattr(config, "TOOLS_ROOT", tmp_path / "Tools")
    candidate = tmp_path / "Path" / "nuclei.exe"
    candidate.parent.mkdir(); candidate.touch()
    monkeypatch.setattr(tools.shutil, "which", lambda value: str(candidate) if value == "nuclei.exe" else None)
    assert tools.find_executable(("nuclei.exe",)) == str(candidate.resolve())
    monkeypatch.setattr(tools.shutil, "which", lambda value: None)
    assert tools.find_executable(("missing.exe",)) is None


def test_configured_tool_paths_are_used(tmp_path, monkeypatch):
    from core import config
    settings = tmp_path / "settings.json"
    configured = tmp_path / "Custom Tools" / "nuclei.exe"
    configured.parent.mkdir(); configured.touch()
    monkeypatch.setattr(config, "CONFIG_PATH", settings)
    monkeypatch.setattr(config, "TOOLS_ROOT", tmp_path / "Tools")
    config.save_config({"tools": {"nuclei": str(configured)}}, settings)
    assert tools.find_tool_executable("nuclei") == str(configured.resolve())


def test_script_interpreters_and_spaces(monkeypatch):
    monkeypatch.setattr(tools, "find_tool_executable", lambda name, *a, **kw: "C:/Strawberry/perl.exe" if name == "perl" else None)
    assert tools.script_command("C:/Program Files/nikto.pl") == ["C:/Strawberry/perl.exe", "C:/Program Files/nikto.pl"]
    assert tools.script_command("zap-baseline.py") == [sys.executable, "zap-baseline.py"]
    monkeypatch.setattr(tools, "find_tool_executable", lambda *a, **kw: None)
    assert tools.script_command("nikto.pl") is None


def test_find_zap_launcher_and_java_jar_fallback(monkeypatch, tmp_path):
    launcher = tmp_path / "ZAP Install" / "zap.bat"
    launcher.parent.mkdir(); launcher.touch()
    from core import config
    monkeypatch.setattr(config, "load_config", lambda: {"tools": {"zap_launcher": ""}})
    monkeypatch.setattr(tools, "find_tool_executable", lambda name, *a, **kw: str(launcher) if name == "zap_launcher" else None)
    assert tools.find_zap_launcher() == str(launcher.resolve())
    monkeypatch.setattr(tools, "find_tool_executable", lambda name, *a, **kw: "C:/Java/java.exe" if name == "java" else None)
    assert tools.zap_command("C:/ZAP/zap-2.17.0.jar") == ["C:/Java/java.exe", "-jar", "C:/ZAP/zap-2.17.0.jar"]
    monkeypatch.setattr(tools, "find_tool_executable", lambda *a, **kw: None)
    assert tools.zap_command("C:/ZAP/zap-2.17.0.jar") is None


def test_missing_zap_launcher_is_unavailable(monkeypatch):
    monkeypatch.setattr(tools, "find_zap_launcher", lambda: None)
    assert tools.run_zap("http://localhost")["status"] == "indispon\u00edvel"


def test_zap_automation_addon_detection(tmp_path, monkeypatch):
    from core import config
    monkeypatch.setattr(config, "TOOLS_ROOT", tmp_path / "empty-tools")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    install = tmp_path / "ZAP Install"
    launcher = install / "zap.bat"
    plugin_dir = install / "plugin"
    plugin_dir.mkdir(parents=True)
    launcher.touch()
    assert not tools.zap_automation_addon_present(str(launcher))
    (plugin_dir / "automation-beta-test.zap").touch()
    assert tools.zap_automation_addon_present(str(launcher))


@pytest.mark.parametrize("code,status", [(0, "erro"), (1, "erro"), (2, "erro"), (3, "erro")])
def test_zap_automation_exit_codes(monkeypatch, code, status):
    monkeypatch.setattr(tools, "find_zap_launcher", lambda: r"C:\Tools\ZAP\zap.bat")
    monkeypatch.setattr(tools, "zap_automation_addon_present", lambda path: True)
    runner = Mock(return_value={"returncode": code, "status": "erro"})
    monkeypatch.setattr(tools, "run_command", runner)
    result = tools.run_zap("https://localhost:8443")
    assert result["status"] == status
    assert runner.call_args.args[0][:3] == [r"C:\Tools\ZAP\zap.bat", "-cmd", "-autorun"]
    assert runner.call_args.kwargs["capture_output"] is True
    assert runner.call_args.kwargs["timeout"] == tools.TOOL_TIMEOUT


def test_zap_yaml_jobs_target_report_timeout_and_no_active_scan(monkeypatch):
    import yaml
    monkeypatch.setattr(tools, "find_zap_launcher", lambda: r"C:\Program Files\ZAP\zap.bat")
    monkeypatch.setattr(tools, "zap_automation_addon_present", lambda path: True)
    seen = {}
    def runner(command, **kwargs):
        seen["cwd"] = kwargs["cwd"]
        seen["plan"] = yaml.safe_load(Path(command[-1]).read_text(encoding="utf-8"))
        return {"returncode": 0, "status": "conclu\u00eddo"}
    monkeypatch.setattr(tools, "run_command", runner)
    result = tools.run_zap("https://example.test:8443/app")
    assert result["execution_status"] == "failed"  # exit zero without a generated report is incomplete
    assert "Program Files" not in seen["cwd"]
    assert seen["plan"]["env"]["contexts"][0]["urls"] == ["https://example.test:8443/app"]
    assert [job["type"] for job in seen["plan"]["jobs"]] == ["spider", "passiveScan-wait", "report"]
    assert seen["plan"]["jobs"][-1]["parameters"]["template"] == "traditional-json"
    assert seen["plan"]["env"]["parameters"]["maxDuration"] == tools.TOOL_TIMEOUT


def test_nikto_requires_perl_and_uses_interpreter(monkeypatch):
    nikto = r"C:\tools\nikto-2.6.1\program\nikto.pl"
    monkeypatch.setattr(tools, "find_tool_executable", lambda name, *a, **kw: None if name == "perl" else nikto)
    missing = tools.run_nikto("http://localhost")
    assert missing["status"] == "indispon\u00edvel"
    assert "Perl" in missing["message"]
    monkeypatch.setattr(tools, "find_tool_executable", lambda name, *a, **kw: "C:/Strawberry/perl/bin/perl.exe" if name == "perl" else nikto)
    monkeypatch.setattr(tools, "_windows_compatible_nikto_copy", lambda path, workspace: path)
    runner = Mock(return_value={"status": "conclu\u00eddo"})
    monkeypatch.setattr(tools, "run_command", runner)
    tools.run_nikto("https://localhost")
    assert runner.call_args.args[0][:2] == ["C:/Strawberry/perl/bin/perl.exe", nikto]


def test_nikto_exe_command_keeps_url_arguments_separate(monkeypatch):
    monkeypatch.setattr(tools, "find_tool_executable", lambda *a, **kw: "C:/Program Files/Nikto/nikto.exe")
    runner = Mock(return_value={"status": "conclu\u00eddo"})
    monkeypatch.setattr(tools, "run_command", runner)
    tools.run_nikto("localhost", 8443, "https")
    command = runner.call_args.args[0]
    assert command[0] == "C:/Program Files/Nikto/nikto.exe"
    assert command[command.index("-h") + 1] == "https://localhost:8443"
    assert command[command.index("-Tuning") + 1] == "2b"


def test_nikto_uses_configured_timeout_and_runtime_path(monkeypatch):
    from core import config
    monkeypatch.setattr(config, "load_config", lambda: {"tools": {}, "nikto": {"enabled": True, "timeout": 45}})
    monkeypatch.setattr(tools, "find_tool_executable", lambda *a, **kw: "C:/Tools/Nikto/nikto.exe")
    runner = Mock(return_value={"status": "conclu\u00eddo"})
    monkeypatch.setattr(tools, "run_command", runner)
    tools.run_nikto("http://localhost")
    assert runner.call_args.kwargs["timeout"] == 45
    assert runner.call_args.kwargs["capture_output"] is True


def test_nikto_does_not_treat_connection_failure_as_positive(monkeypatch):
    from core import config
    monkeypatch.setattr(config, "load_config", lambda: {"tools": {}, "nikto": {"enabled": True, "timeout": 45}})
    monkeypatch.setattr(tools, "find_tool_executable", lambda *a, **kw: "C:/Tools/Nikto/nikto.exe")
    monkeypatch.setattr(tools, "run_command", Mock(return_value={
        "status": "conclu\u00eddo", "output": "+ [FAIL] Unable to connect to localhost:80."
    }))
    result = tools.run_nikto("http://localhost")
    assert result["status"] == "erro"
    assert "falha de conex" in result["message"]


def test_disabled_nikto_does_not_start_process(monkeypatch):
    from core import config
    monkeypatch.setattr(config, "load_config", lambda: {"tools": {}, "nikto": {"enabled": False, "timeout": 45}})
    runner = Mock()
    monkeypatch.setattr(tools, "run_command", runner)
    assert tools.run_nikto("http://localhost")["status"] == "desativado"
    runner.assert_not_called()


def test_dependency_status_reports_optional_tools_without_running_scans(monkeypatch):
    monkeypatch.setattr(tools, "find_tool_executable", lambda *a, **kw: None)
    monkeypatch.setattr(tools, "_probe_executable", lambda *a, **kw: (False, ""))
    monkeypatch.setattr("core.nuclei.find_nuclei", lambda *a, **kw: None)
    monkeypatch.setattr(tools.importlib.util, "find_spec", lambda name: None)
    rows = tools.dependency_status()
    assert rows[0][0] == "Python" and rows[0][1]
    assert {row[0] for row in rows} >= {"Nmap", "Nuclei", "ZAP", "ZAP Automation Framework", "Nikto", "Perl", "Java"}
    assert all(not status for _, status, _ in rows[1:])


def test_run_command_uses_args_timeout_and_shell_false(monkeypatch):
    process = Mock(); process.wait.return_value = 0; process.poll.return_value = 0
    popen = Mock(return_value=process)
    monkeypatch.setattr(tools.subprocess, "Popen", popen)
    result = tools.run_command(["path with spaces.exe", "-h", "http://localhost:80"], timeout=12)
    assert result["status"] == "conclu\u00eddo"
    assert popen.call_args.kwargs["shell"] is False
    process.wait.assert_called_once_with(timeout=12)


@pytest.mark.parametrize("error,status", [(FileNotFoundError(), "erro"), (PermissionError(), "erro"), (subprocess.TimeoutExpired("test", 1), "timeout"), (KeyboardInterrupt(), "cancelado")])
def test_process_errors_and_cleanup(monkeypatch, error, status):
    process = Mock(); process.wait.side_effect = error
    monkeypatch.setattr(tools.subprocess, "Popen", Mock(return_value=process))
    stop = Mock(); monkeypatch.setattr(tools, "stop_process", stop)
    assert tools.run_command(["fake"])["status"] == status
    stop.assert_called_once_with(process)


def test_missing_executable_and_batch_files(monkeypatch, tmp_path):
    monkeypatch.setattr(tools.shutil, "which", lambda value: None)
    assert tools.find_executable((str(tmp_path / "missing.exe"),)) is None
    batch = tmp_path / "tool.cmd"; batch.touch()
    assert tools.find_executable((str(batch),)) == str(batch.resolve())


def test_batch_commands_are_passed_through_cmd_with_argument_guard(monkeypatch, tmp_path):
    batch = tmp_path / "Program Files (x86)" / "Nikto" / "nikto.bat"
    batch.parent.mkdir(parents=True)
    batch.touch()
    process = Mock(); process.wait.return_value = 0; process.poll.return_value = 0
    popen = Mock(return_value=process)
    monkeypatch.setattr(tools.subprocess, "Popen", popen)
    result = tools.run_command([str(batch), "-h", "http://localhost:8080"], timeout=7)
    assert result["status"] == "conclu\u00eddo"
    command = popen.call_args.args[0]
    assert Path(command[0]).name.casefold() == "cmd.exe"
    assert command[1:4] == ["/d", "/s", "/c"]
    assert "Program Files" in command[4]
    assert popen.call_args.kwargs["shell"] is False


def test_batch_commands_reject_shell_metacharacters(monkeypatch, tmp_path):
    batch = tmp_path / "nikto.cmd"
    batch.touch()
    popen = Mock()
    monkeypatch.setattr(tools.subprocess, "Popen", popen)
    result = tools.run_command([str(batch), "-h", "http://localhost/?x=1&y=2"])
    assert result["status"] == "erro"
    assert "metacaracteres" in result["message"]
    popen.assert_not_called()
