import json

import pytest

from core import config


def test_config_defaults_and_round_trip(tmp_path):
    path = tmp_path / "settings.json"
    assert config.load_config(path)["nuclei"] == config.NUCLEI_DEFAULTS
    saved = config.save_config(
        {"nuclei": {**config.NUCLEI_DEFAULTS, "enabled": False, "rate_limit": 1}}, path
    )
    loaded = config.load_config(path)
    assert saved == path
    assert loaded["nuclei"]["enabled"] is False
    assert loaded["nuclei"]["rate_limit"] == 1
    assert loaded["tools"] == config.TOOL_PATH_DEFAULTS


def test_custom_tool_paths_round_trip(tmp_path):
    path = tmp_path / "settings.json"
    custom = str(tmp_path / "Tools With Spaces" / "nuclei.exe")
    config.save_config({"tools": {"nuclei": custom}}, path)
    assert config.load_config(path)["tools"]["nuclei"] == custom


def test_tool_paths_reject_control_characters():
    with pytest.raises(ValueError, match="Caminho"):
        config.validate_tool_paths({"nikto": "C:\\Tools\\nikto.pl\n-malicious"})


@pytest.mark.parametrize(
    "setting,value",
    [("timeout", 601), ("rate_limit", 0), ("concurrency", 3)],
)
def test_config_rejects_values_outside_safe_limits(setting, value):
    with pytest.raises(ValueError):
        config.validate_nuclei_settings({setting: value})


def test_invalid_config_file_falls_back_to_safe_defaults(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"nuclei": {"concurrency": 25}}), encoding="utf-8")
    assert config.load_config(path)["nuclei"] == config.NUCLEI_DEFAULTS


def test_dotenv_nikto_overrides_are_loaded_without_changing_stored_config(tmp_path, monkeypatch):
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "PERL_PATH=C:\\Tools\\Perl With Spaces\\bin\\perl.exe\n"
        "NIKTO_PATH=\"C:\\Tools\\Nikto\\program\\nikto.pl\"\n"
        "NIKTO_TIMEOUT=120\nNIKTO_ENABLED=false\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("PERL_PATH", raising=False)
    monkeypatch.delenv("NIKTO_ENABLED", raising=False)
    monkeypatch.setenv("NIKTO_TIMEOUT", "90")
    config_obj = config._with_environment(
        {"nuclei": dict(config.NUCLEI_DEFAULTS), "nikto": dict(config.NIKTO_DEFAULTS), "tools": dict(config.TOOL_PATH_DEFAULTS)},
        dotenv,
    )
    assert config_obj["tools"]["perl"] == r"C:\Tools\Perl With Spaces\bin\perl.exe"
    assert config_obj["tools"]["nikto"] == r"C:\Tools\Nikto\program\nikto.pl"
    assert config_obj["nikto"] == {"enabled": False, "timeout": 90}


def test_save_config_does_not_persist_dotenv_overrides(tmp_path, monkeypatch):
    settings = tmp_path / "settings.json"
    dotenv_tool = str(tmp_path / "from-env" / "nikto.pl")
    monkeypatch.setattr(config, "_read_dotenv", lambda path=None: {"NIKTO_PATH": dotenv_tool})
    config.save_config({"nuclei": {**config.NUCLEI_DEFAULTS, "enabled": False}}, settings)
    saved = json.loads(settings.read_text(encoding="utf-8"))
    assert saved["tools"]["nikto"] == config.NIKTO_PATH


def test_nikto_settings_validate_timeout_and_enabled():
    assert config._validate_nikto_settings({"enabled": True, "timeout": 120}) == {"enabled": True, "timeout": 120}
    with pytest.raises(ValueError):
        config._validate_nikto_settings({"timeout": 0})
