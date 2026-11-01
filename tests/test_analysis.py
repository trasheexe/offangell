import json
from pathlib import Path
from unittest.mock import Mock

from core import nuclei, tools
from core.analysis import consolidate_findings, execution_state
from core.nuclei import deduplicate_nuclei_findings


def test_execution_state_does_not_treat_zero_as_success():
    assert execution_state({"returncode": 0, "execution_status": "partial"}) == "partial"
    assert execution_state({"status": "timeout"}) == "timeout"
    assert execution_state({"status": "indisponível"}) == "skipped"
    assert execution_state({"status": "concluído"}) == "completed"


def test_nuclei_duplicates_merge_and_keep_distinct_evidence():
    same = {"tool": "Nuclei", "template_id": "http-missing-security-headers", "host": "example.test",
            "matched_at": "https://example.test/", "type": "http", "severity": "Informational",
            "extracted_results": [], "timestamp": "t1"}
    merged = deduplicate_nuclei_findings([same, {**same, "timestamp": "t2"},
                                          {**same, "extracted_results": ["content-security-policy"]}])
    assert len(merged) == 2
    assert merged[0]["occurrence_count"] == 2
    assert merged[0]["occurrences"] == ["t1", "t2"]
    assert merged[1]["extracted_results"] == ["content-security-policy"]


def test_correlated_findings_keep_severity_evidence_and_validation_status():
    records = [
        {"tool": "Nikto", "url": "https://example.test/", "name": "Suggested security header missing: Content-Security-Policy",
         "severity": "Unknown", "evidence": "header check", "validation_status": "unconfirmed"},
        {"tool": "OWASP ZAP", "url": "https://example.test/", "name": "Content Security Policy (CSP) Header Not Set",
         "severity": "Medium", "evidence": "CSP absent", "validation_status": "unconfirmed"},
    ]
    groups = consolidate_findings(records)
    assert len(groups) == 1
    group = groups[0]
    assert group["tools"] == ["Nikto", "OWASP ZAP"]
    assert group["original_severities"] == ["Unknown", "Medium"]
    assert len(group["evidences"]) == 2
    assert group["validation_status"] == "unconfirmed"
    assert group["confidence"] == "corroborated"


def test_conflicting_findings_are_not_merged_by_template_alone():
    items = [
        {"tool": "Nuclei", "template_id": "same", "host": "example.test", "matched_at": "https://example.test/a",
         "type": "http", "name": "Issue A", "severity": "Low"},
        {"tool": "ZAP", "template_id": "same", "host": "example.test", "matched_at": "https://example.test/b",
         "type": "http", "name": "Issue B", "severity": "High"},
    ]
    groups = consolidate_findings(items)
    assert len(groups) == 2
    assert {item["original_severities"][0] for item in groups} == {"Low", "High"}


def test_nikto_tls_error_limit_keeps_partial_evidence_and_request_count(monkeypatch):
    from core import config
    monkeypatch.setattr(config, "load_config", lambda: {"tools": {}, "nikto": {"enabled": True, "timeout": 30}})
    monkeypatch.setattr(tools, "find_tool_executable", lambda *args, **kwargs: "C:/Tools/Nikto/nikto.exe")
    output = ("+ [013587] /: Suggested security header missing: content-security-policy\n"
              "- STATUS: Completed 53 requests (~4% complete)\n"
              "+ ERROR: Error limit (20) reached for host\n"
              "+ Scan terminated: 21 errors and 1 items reported on the remote host\n"
              "ssl connect failed: Inappropriate I/O control operation")
    monkeypatch.setattr(tools, "run_command", Mock(return_value={"status": "concluído", "returncode": 0,
        "output": output, "started_at": "2026-10-31T10:00:00-03:00", "finished_at": "2026-10-31T10:00:01-03:00"}))
    result = tools.run_nikto("https://example.test")
    assert result["execution_status"] == "partial"
    assert result["request_count"] == 53
    assert result["error_count"] == 21
    assert result["findings"][0]["tool"] == "Nikto"
    assert "mitmproxy" not in result.get("output", "").casefold()


def test_zap_path_failure_is_failed_even_with_exit_code_one(monkeypatch):
    monkeypatch.setattr(tools, "find_zap_launcher", lambda: r"C:\Tools\ZAP\zap.bat")
    monkeypatch.setattr(tools, "zap_automation_addon_present", lambda path: True)
    monkeypatch.setattr(tools, "run_command", Mock(return_value={"returncode": 1, "status": "erro",
        "stdout": "O caminho da rede não foi encontrado.", "stderr": "", "output": "O caminho da rede não foi encontrado."}))
    result = tools.run_zap("https://localhost")
    assert result["execution_status"] == "failed"
    assert "network_path_not_found" in result["operational_errors"]
    assert result["report_exists"] is False


def test_zap_requires_valid_report_even_when_exit_code_is_zero(monkeypatch):
    monkeypatch.setattr(tools, "find_zap_launcher", lambda: r"C:\Tools\ZAP\zap.bat")
    monkeypatch.setattr(tools, "zap_automation_addon_present", lambda path: True)
    monkeypatch.setattr(tools, "run_command", Mock(return_value={"returncode": 0, "status": "concluído"}))
    result = tools.run_zap("https://localhost")
    assert result["execution_status"] == "failed"
    assert "report_missing_or_invalid" in result["operational_errors"]


def test_zap_valid_report_with_warning_exit_is_partial(monkeypatch):
    monkeypatch.setattr(tools, "find_zap_launcher", lambda: r"C:\Tools\ZAP\zap.bat")
    monkeypatch.setattr(tools, "zap_automation_addon_present", lambda path: True)
    def runner(command, **kwargs):
        report = Path(command[-1]).parent / "zap-report.json"
        report.write_text(json.dumps({"site": [{"@name": "https://localhost/", "alerts": []}]}), encoding="utf-8")
        return {"returncode": 1, "status": "erro", "stdout": "warning", "stderr": ""}
    monkeypatch.setattr(tools, "run_command", runner)
    result = tools.run_zap("https://localhost")
    assert result["execution_status"] == "partial"
    assert result["report_exists"] is True


def test_zap_success_requires_a_parsed_report(monkeypatch):
    monkeypatch.setattr(tools, "find_zap_launcher", lambda: r"C:\Tools\ZAP\zap.bat")
    monkeypatch.setattr(tools, "zap_automation_addon_present", lambda path: True)
    def runner(command, **kwargs):
        Path(command[-1]).parent.joinpath("zap-report.json").write_text(
            json.dumps({"site": []}), encoding="utf-8")
        return {"returncode": 0, "status": "concluído", "stdout": "", "stderr": ""}
    monkeypatch.setattr(tools, "run_command", runner)
    result = tools.run_zap("https://localhost")
    assert result["execution_status"] == "completed"
    assert result["report_exists"] is True
    assert result["plan_validated"] is True


def test_nuclei_code_zero_with_internal_error_is_not_completed(monkeypatch, tmp_path):
    template_root = tmp_path / "templates"
    template_root.mkdir()
    template = template_root / "safe.yaml"
    template.write_text("id: safe", encoding="utf-8")
    monkeypatch.setattr(nuclei, "find_nuclei", lambda path=None: "nuclei.exe")
    monkeypatch.setattr(nuclei, "check_nuclei_version", lambda path: {"status": "concluído", "version": "v3"})
    monkeypatch.setattr(nuclei, "check_nuclei_templates", lambda directory=None: {"found": True, "path": str(template_root), "count": 1})
    monkeypatch.setattr(nuclei, "_safe_template_files", lambda root: [template])
    process = Mock(returncode=0)
    process.communicate.return_value = (b"", b"ERROR: internal worker failure")
    process.poll.return_value = 0
    monkeypatch.setattr(nuclei.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(nuclei.tool_utils, "stop_process", Mock(return_value=True))
    result = nuclei.run_nuclei("https://example.test")
    assert result["returncode"] == 0
    assert result["execution_status"] == "failed"
    assert "erro interno" in result["message"]

