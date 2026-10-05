import json

import pytest

from core import reports


def example_report():
    report = reports.new_report("::1", "personalizado", "443")
    report.update(
        status="concluído",
        address="::1",
        open_ports=[
            {
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "product": "nginx",
                "version": "1.2",
            }
        ],
    )
    report["banners"].append(
        {"banner": "HTTP/1.1 200 OK\r\nSet-Cookie: secret-cookie\r\nServer: nginx"}
    )
    report["nse"].append({"scripts": {"test": "Possível problema; token=secret-value"}})
    report["tools"].append({"tool": "ZAP Baseline", "status": "alertas", "returncode": 2})
    return report


@pytest.mark.parametrize("format_name", ["txt", "json"])
def test_save_and_read_report(tmp_path, format_name):
    report = example_report()
    path = reports.save_report(report, format_name, tmp_path / "reports")
    content = reports.read_report(path, tmp_path / "reports")
    assert path.name.startswith("scan___1_")
    assert path.suffix == "." + format_name
    assert "OFF ANGELL" in content and "nginx" in content and "ZAP Baseline" in content
    assert "secret-cookie" not in content and "secret-value" not in content
    assert "secret-cookie" in report["banners"][0]["banner"]  # exportação não altera a sessão
    if format_name == "json":
        data = json.loads(content)
        assert data["target"] == "::1" and data["saved_at"]
        assert data["open_ports"][0]["version"] == "1.2"


def test_reports_do_not_overwrite(tmp_path):
    first = reports.save_report(example_report(), "json", tmp_path)
    second = reports.save_report(example_report(), "json", tmp_path)
    assert first != second
    assert len(reports.list_reports(tmp_path)) == 2


def test_invalid_report_format_and_target(tmp_path):
    with pytest.raises(ValueError):
        reports.save_report(example_report(), "html", tmp_path)
    with pytest.raises(ValueError):
        reports.save_report({**example_report(), "target": "../../escape"}, "json", tmp_path)


def test_list_and_read_stay_in_reports_directory(tmp_path):
    assert reports.list_reports(tmp_path / "missing") == []
    (tmp_path / ".gitkeep").touch()
    (tmp_path / "scan_bad.exe").touch()
    assert reports.list_reports(tmp_path) == []
    with pytest.raises(ValueError):
        reports.read_report(tmp_path / "outside.json", tmp_path / "reports")


def test_redaction_and_terminal_control_characters():
    text = '\x1b[31mPassword: "abc def"\nAuthorization: Bearer abc\nSet-Cookie: xyz\n continuation\nServer: test\x00'
    clean = reports.clean_text(text)
    assert "abc" not in clean and "xyz" not in clean and "continuation" not in clean
    assert "\x1b" not in clean and "\x00" not in clean and "Server: test" in clean
    assert reports.sanitize({"password": "abc"}) == {"password": "[REMOVIDO]"}


def test_report_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "MAX_REPORT_BYTES", 20)
    with pytest.raises(ValueError, match="limite"):
        reports.save_report(example_report(), "json", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_save_permission_error_is_propagated(tmp_path, monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError("sem permissão")

    monkeypatch.setattr(reports.Path, "mkdir", denied)
    with pytest.raises(PermissionError):
        reports.save_report(example_report(), "txt", tmp_path)
