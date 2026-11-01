import json
import subprocess
from unittest.mock import Mock

import pytest

from core import nuclei


def _fake_help():
    return " ".join(f"-{flag}" for flag in nuclei.REQUIRED_SCAN_FLAGS)


def _finding(**extra):
    value = {
        "template-id": "http-missing-security-headers",
        "type": "http",
        "host": "https://example.test:8443",
        "matched-at": "https://example.test:8443/app?token=secret",
        "info": {
            "name": "HTTP Missing Security Headers",
            "severity": "medium",
            "tags": ["misconfig", "headers"],
            "description": "Check response token=secret",
            "reference": ["https://example.test/advisory"],
        },
        "extracted-results": ["api_key=secret"],
        "request": "Authorization: Bearer secret",
        "response": "Set-Cookie: secret",
    }
    value.update(extra)
    return value


@pytest.fixture
def safe_template(tmp_path):
    path = tmp_path / "http" / "misconfiguration" / "http-missing-security-headers.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(
        """id: http-missing-security-headers
info:
  name: HTTP Missing Security Headers
  severity: info
  tags: misconfig,headers
  metadata:
    max-request: 1
http:
  - method: GET
    path:
      - '{{BaseURL}}'
    matchers:
      - type: status
        status: [200]
""",
        encoding="utf-8",
    )
    return path


def test_find_nuclei_uses_custom_or_standard_executable(monkeypatch):
    calls = []

    def find(paths, **kwargs):
        calls.append((paths, kwargs))
        return "C:/tools/nuclei.exe"

    monkeypatch.setattr(nuclei.tool_utils, "find_executable", find)
    assert nuclei.find_nuclei(r"C:\scan tools\nuclei.exe") == "C:/tools/nuclei.exe"
    assert calls[-1][1]["configured_path"] == r"C:\scan tools\nuclei.exe"
    monkeypatch.setattr(nuclei.tool_utils, "find_tool_executable", lambda name, paths: "C:/tools/nuclei.exe")
    assert nuclei.find_nuclei() == "C:/tools/nuclei.exe"
    assert nuclei.NUCLEI_PATHS == nuclei.tool_utils.NUCLEI_PATHS


def test_missing_nuclei_is_reported_without_starting_process(monkeypatch):
    monkeypatch.setattr(nuclei, "find_nuclei", lambda path=None: None)
    result = nuclei.run_nuclei("https://example.test")
    assert result["status"] == "indisponível"
    assert "não encontrado" in result["message"]


def test_missing_templates_use_required_message(tmp_path):
    result = nuclei.check_nuclei_templates(tmp_path / "missing")
    assert result["found"] is False
    assert result["message"] == "[!] Templates do Nuclei não encontrados."


def test_check_templates_finds_yaml_files(safe_template):
    result = nuclei.check_nuclei_templates(safe_template.parents[2])
    assert result["found"] is True
    assert result["count"] == 1


def test_template_policy_allows_reviewed_ids_and_rejects_active_yaml(safe_template):
    assert nuclei._safe_template_files(safe_template.parents[2]) == [safe_template.resolve()]
    content = safe_template.read_text(encoding="utf-8").replace(
        "    matchers:", "    payloads:\n      q: ['x']\n    matchers:"
    )
    safe_template.write_text(content, encoding="utf-8")
    assert nuclei._safe_template_files(safe_template.parents[2]) == []


def test_jsonl_parser_normalizes_and_omits_raw_data():
    text = "\n".join(
        [
            "not json",
            json.dumps(_finding()),
            json.dumps({"error": "this is not a finding"}),
            json.dumps(_finding(**{"template-id": "other", "info": {"severity": "unlisted"}})),
        ]
    )
    results = nuclei.parse_nuclei_results(text)
    assert len(results) == 2
    assert results[0]["tool"] == "Nuclei"
    assert results[0]["severity"] == "Medium"
    assert results[1]["severity"] == "Unknown"
    assert results[0]["status"].startswith("indício")
    assert "secret" not in json.dumps(results)
    assert "request" not in results[0] and "response" not in results[0]
    counts = nuclei.severity_counts(results)
    assert counts["Medium"] == 1 and counts["Unknown"] == 1


def test_jsonl_empty_and_invalid_lines_are_ignored():
    assert nuclei.parse_nuclei_results("") == []
    assert nuclei.parse_nuclei_results("{bad json}\n[]\n{\"info\":{}}") == []


def test_version_checks_installed_flags(monkeypatch):
    run = Mock(
        side_effect=[
            Mock(returncode=0, stdout=b"Nuclei Engine Version: v3.5.0"),
            Mock(returncode=0, stdout=_fake_help().encode()),
        ]
    )
    monkeypatch.setattr(nuclei.subprocess, "run", run)
    result = nuclei.check_nuclei_version("/mock/nuclei")
    assert result["status"] == "concluído"
    assert result["version"] == "v3.5.0"
    assert len(run.call_args_list) == 2
    assert all(call.kwargs["shell"] is False for call in run.call_args_list)


def test_version_refuses_profile_if_required_option_is_missing(monkeypatch):
    run = Mock(
        side_effect=[
            Mock(returncode=0, stdout=b"v3.0.0"),
            Mock(returncode=0, stdout=b"-jsonl -omit-raw"),
        ]
    )
    monkeypatch.setattr(nuclei.subprocess, "run", run)
    result = nuclei.check_nuclei_version("nuclei")
    assert result["status"] == "incompatível"
    assert "disable-unsigned-templates" in result["missing_flags"]


def test_run_builds_conservative_command_and_parses_findings(monkeypatch, safe_template):
    monkeypatch.setattr(nuclei, "find_nuclei", lambda path=None: "C:/tools/nuclei.exe")
    monkeypatch.setattr(
        nuclei,
        "check_nuclei_version",
        lambda path: {"status": "concluído", "version": "v3.5.0"},
    )
    monkeypatch.setattr(
        nuclei,
        "check_nuclei_templates",
        lambda directory=None: {"found": True, "path": str(safe_template.parents[2]), "count": 1},
    )
    process = Mock(returncode=0)
    process.communicate.return_value = (
        (json.dumps(_finding()) + "\n").encode(),
        b"Templates loaded for current scan: 1",
    )
    process.poll.return_value = 0
    popen = Mock(return_value=process)
    monkeypatch.setattr(nuclei.subprocess, "Popen", popen)
    stopped = Mock(return_value=True)
    monkeypatch.setattr(nuclei.tool_utils, "stop_process", stopped)

    result = nuclei.run_nuclei("https://example.test:8443/app?x=1", timeout=72)
    command = popen.call_args.args[0]
    assert result["status"] == "concluído"
    assert result["severity_counts"]["Medium"] == 1
    assert command[command.index("-u") + 1] == "https://example.test:8443/app?x=1"
    assert command[command.index("-templates") + 1] == str(safe_template.resolve())
    assert command[command.index("-rate-limit") + 1] == "2"
    assert command[command.index("-concurrency") + 1] == "2"
    assert command[command.index("-bulk-size") + 1] == "1"
    assert command[command.index("-timeout") + 1] == "8"
    assert command[command.index("-retries") + 1] == "1"
    assert command[command.index("-max-host-error") + 1] == "5"
    for flag in ("-no-interactsh", "-disable-update-check", "-disable-unsigned-templates", "-disable-redirects", "-omit-raw"):
        assert flag in command
    assert "-as" not in command and "-headless" not in command and "-fuzz" not in command
    assert "-update-templates" not in command
    assert popen.call_args.kwargs["shell"] is False
    process.communicate.assert_called_once_with(timeout=72)
    stopped.assert_called_once_with(process)


def test_out_of_scope_jsonl_results_are_dropped(monkeypatch, safe_template):
    monkeypatch.setattr(nuclei, "find_nuclei", lambda path=None: "nuclei.exe")
    monkeypatch.setattr(nuclei, "check_nuclei_version", lambda path: {"status": "concluído", "version": "v3"})
    monkeypatch.setattr(
        nuclei,
        "check_nuclei_templates",
        lambda directory=None: {"found": True, "path": str(safe_template.parents[2]), "count": 1},
    )
    process = Mock(returncode=0)
    process.communicate.return_value = (
        (json.dumps(_finding(**{"matched-at": "https://other.test/"})) + "\n").encode(),
        b"Templates loaded for current scan: 1",
    )
    process.poll.return_value = 0
    monkeypatch.setattr(nuclei.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(nuclei.tool_utils, "stop_process", Mock(return_value=True))
    result = nuclei.run_nuclei("https://example.test")
    assert result["findings"] == []
    assert result["out_of_scope_findings"] == 1


def test_timeout_preserves_only_valid_partial_jsonl(monkeypatch, safe_template):
    monkeypatch.setattr(nuclei, "find_nuclei", lambda path=None: "nuclei.exe")
    monkeypatch.setattr(nuclei, "check_nuclei_version", lambda path: {"status": "concluído", "version": "v3"})
    monkeypatch.setattr(
        nuclei,
        "check_nuclei_templates",
        lambda directory=None: {"found": True, "path": str(safe_template.parents[2]), "count": 1},
    )
    process = Mock(returncode=None)
    process.communicate.side_effect = subprocess.TimeoutExpired(
        "nuclei", 5, output=(json.dumps(_finding()) + "\n").encode()
    )
    process.poll.return_value = None
    monkeypatch.setattr(nuclei.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(nuclei.tool_utils, "stop_process", Mock(return_value=True))
    result = nuclei.run_nuclei("https://example.test:8443", timeout=5)
    assert result["status"] == "timeout"
    assert len(result["findings"]) == 1


def test_process_errors_are_not_reported_as_findings(monkeypatch, safe_template):
    monkeypatch.setattr(nuclei, "find_nuclei", lambda path=None: "nuclei.exe")
    monkeypatch.setattr(nuclei, "check_nuclei_version", lambda path: {"status": "concluído", "version": "v3"})
    monkeypatch.setattr(
        nuclei,
        "check_nuclei_templates",
        lambda directory=None: {"found": True, "path": str(safe_template.parents[2]), "count": 1},
    )
    monkeypatch.setattr(nuclei.subprocess, "Popen", Mock(side_effect=FileNotFoundError))
    assert nuclei.run_nuclei("https://example.test")["findings"] == []
    assert nuclei.run_nuclei("https://example.test")["status"] == "indisponível"


def test_update_templates_requires_confirmation_and_uses_official_command(monkeypatch, tmp_path):
    run = Mock(return_value=Mock(returncode=0, stdout=b"Templates updated"))
    monkeypatch.setattr(nuclei.subprocess, "run", run)
    monkeypatch.setattr(nuclei, "find_nuclei", lambda path=None: "nuclei.exe")
    cancelled = nuclei.update_nuclei_templates(confirm=False)
    assert cancelled["status"] == "cancelado"
    run.assert_not_called()

    monkeypatch.setattr(nuclei, "_call_help", lambda path: ("-update-template-dir", None))
    result = nuclei.update_nuclei_templates(
        confirm=True, templates_dir=tmp_path, timeout=40
    )
    assert result["status"] == "concluído"
    command = run.call_args.args[0]
    assert command[:2] == ["nuclei.exe", "-update-templates"]
    assert command[command.index("-update-template-dir") + 1] == str(tmp_path)
    assert run.call_args.kwargs["shell"] is False


def test_invalid_target_and_unsafe_configuration_do_not_execute(monkeypatch):
    popen = Mock()
    monkeypatch.setattr(nuclei.subprocess, "Popen", popen)
    assert nuclei.run_nuclei("file:///etc/passwd")["status"] == "erro"
    assert nuclei.run_nuclei("https://example.test", rate_limit=6)["status"] == "erro"
    popen.assert_not_called()
