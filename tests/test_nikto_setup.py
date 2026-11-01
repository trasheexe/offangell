from pathlib import Path

from core import nikto_setup, tools


def test_module_diagnostics_are_based_on_import_checks(monkeypatch):
    monkeypatch.setattr(nikto_setup, "_run", lambda *a, **kw: {
        "ok": False,
        "returncode": 1,
        "output": "XML::Writer\tOK\t0.900\nNet::SSLeay\tFALHA: DLL ausente\t\nIO::Socket::SSL\tFALHA: Net::SSLeay\t\n",
    })
    modules = nikto_setup._perl_modules("perl.exe")
    assert modules["XML::Writer"]["ok"] is True
    assert modules["Net::SSLeay"]["ok"] is False
    assert modules["IO::Socket::SSL"]["ok"] is False


def test_config_file_discovery_includes_default_and_user_config(tmp_path, monkeypatch):
    nikto = tmp_path / "nikto" / "program" / "nikto.pl"
    nikto.parent.mkdir(parents=True)
    nikto.touch()
    (nikto.parent / "nikto.conf.default").touch()
    home = tmp_path / "home"
    (home / ".nikto").mkdir(parents=True)
    (home / ".nikto" / "nikto.conf").touch()
    monkeypatch.setattr(Path, "home", lambda: home)
    found = nikto_setup._configuration_files(str(nikto))
    assert len(found) == 2
    assert any(path.endswith("nikto.conf.default") for path in found)
    assert any(path.endswith(".nikto\\nikto.conf") or path.endswith(".nikto/nikto.conf") for path in found)


def test_diagnose_reports_missing_perl_and_paths(monkeypatch):
    monkeypatch.setattr(nikto_setup, "load_config", lambda: {"tools": {"perl": "", "nikto": ""}})
    monkeypatch.setattr(nikto_setup, "find_tool_executable", lambda *a, **kw: None)
    monkeypatch.setattr(nikto_setup, "_toolchain", lambda perl: {"gmake": {"path": None, "runnable": False}})
    report = nikto_setup.diagnose()
    assert report["perl"]["path"] is None
    assert report["nikto"]["path"] is None
    assert report["https"]["supported_by_modules"] is False
    assert report["path_notes"]["perl_path_missing_from_path"] is False


def test_local_http_runner_is_scoped_to_loopback_and_uses_timeout(monkeypatch):
    # Use fake server primitives: pytest's global fixture intentionally blocks sockets/processes.
    class FakeServer:
        server_address = ("127.0.0.1", 8123)
        daemon_threads = False
        def __init__(self, address, handler):
            assert address[0] == "127.0.0.1"
        def serve_forever(self):
            pass
        def shutdown(self):
            pass
        def server_close(self):
            pass

    class FakeThread:
        def __init__(self, **kwargs):
            pass
        def start(self):
            pass
        def join(self, timeout=None):
            pass

    monkeypatch.setattr(nikto_setup.http.server, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(nikto_setup.threading, "Thread", FakeThread)
    monkeypatch.setattr(nikto_setup.urllib.request, "urlopen", lambda *a, **kw: type("Response", (), {"status": 200, "__enter__": lambda self: self, "__exit__": lambda *args: None})())
    def fake_nikto(url, timeout):
        nikto_setup._QuietHandler.requests_seen = 2
        return {"status": "concluído", "url": url, "timeout": timeout}
    monkeypatch.setattr(nikto_setup, "run_nikto", fake_nikto)
    result = nikto_setup.test_local_http()
    assert result["target"].startswith("http://127.0.0.1:")
    assert result["result"]["timeout"] == 120
    assert result["ok"] is True


def test_cpan_install_skips_modules_already_working(monkeypatch):
    monkeypatch.setattr(nikto_setup, "find_tool_executable", lambda *a, **kw: "perl.exe")
    monkeypatch.setattr(nikto_setup, "_run", lambda *a, **kw: {"ok": True, "output": ""})
    monkeypatch.setattr(nikto_setup, "_perl_modules", lambda perl: {
        "XML::Writer": {"ok": True}, "Net::SSLeay": {"ok": True}, "IO::Socket::SSL": {"ok": True}
    })
    result = nikto_setup.install_perl_dependencies()
    assert result["ok"] is True
    assert result["installed"] == []


def test_cpan_installs_missing_xml_writer_without_reinstalling_ssl_modules(monkeypatch):
    monkeypatch.setattr(nikto_setup, "find_tool_executable", lambda *a, **kw: "perl.exe")
    calls = []
    def fake_run(command, **kwargs):
        calls.append(command)
        return {"ok": True, "output": "CPAN install stub"}
    monkeypatch.setattr(nikto_setup, "_run", fake_run)
    before = {
        "XML::Writer": {"ok": False}, "Net::SSLeay": {"ok": True},
        "IO::Socket::SSL": {"ok": True}, "Net::SSL": {"ok": False},
    }
    after = {**before, "XML::Writer": {"ok": True}}
    module_runs = iter((before, after))
    monkeypatch.setattr(nikto_setup, "_perl_modules", lambda perl: next(module_runs))
    result = nikto_setup.install_perl_dependencies()
    assert result["ok"] is True
    assert result["xml_writer_skipped"] is False
    assert result["requested_modules"] == ["XML::Writer"]
    assert len(calls) == 2


def test_windows_libwhisker_patch_is_applied_only_to_temporary_copy(tmp_path):
    install = tmp_path / "Nikto" / "program"
    plugins = install / "plugins"
    plugins.mkdir(parents=True)
    source_script = install / "nikto.pl"
    source_script.write_text("# test nikto\n", encoding="utf-8")
    original_module = plugins / "LW2.pm"
    original_module.write_text("    $LW_NONBLOCK_CONNECT = 1;\n", encoding="utf-8")
    original_text = original_module.read_text(encoding="utf-8")
    workspace = tmp_path / "temporary"
    workspace.mkdir()

    copied_script = tools._windows_compatible_nikto_copy(str(source_script), workspace)

    assert copied_script
    assert Path(copied_script).is_file()
    assert "$LW_NONBLOCK_CONNECT = 0;" in (Path(copied_script).parent / "plugins" / "LW2.pm").read_text(encoding="utf-8")
    assert original_module.read_text(encoding="utf-8") == original_text
