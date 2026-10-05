import pytest

from core.validation import (
    build_web_url,
    is_web_service,
    validate_ports,
    validate_target,
)


@pytest.mark.parametrize(
    "target,expected",
    [
        ("127.0.0.1", "127.0.0.1"),
        ("192.168.0.10", "192.168.0.10"),
        ("localhost", "localhost"),
        ("meuservidor.local", "meuservidor.local"),
        ("EXAMPLE.TEST.", "example.test"),
        ("::1", "::1"),
        ("2001:0db8::1", "2001:db8::1"),
        (" host-1.local ", "host-1.local"),
        ("café.test", "xn--caf-dma.test"),
    ],
)
def test_valid_targets(target, expected):
    assert validate_target(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        "",
        " ",
        "http://site.com",
        "https://site.com/teste",
        "host/path",
        "host\\path",
        "--script",
        "-sV",
        "host --script vuln",
        "host\n",
        "host\r\n-h",
        "host\t",
        "host\0",
        "127.0.0.1;echo",
        "host&whoami",
        "$(hostname)",
        "`hostname`",
        "host|x",
        "999.1.1.1",
        "127.0.0",
        "192.168.1.0/24",
        "127.0.0.1,127.0.0.2",
        "127.0.0.*",
        "host:80",
        "[::1]",
        "2001:bad:::1",
        "fe80::1%eth0",
        "host..test",
        "host..",
        "_host",
        "host-",
        "a" * 64 + ".test",
        ".host",
        "user@host",
        "1234",
    ],
)
def test_invalid_targets(target):
    with pytest.raises(ValueError):
        validate_target(target)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1-1000", "1-1000"),
        ("80,443,8080", "80,443,8080"),
        ("22,80,443", "22,80,443"),
        ("1-65535", "1-65535"),
        ("80", "80"),
        ("00080", "80"),
        ("22,80-90", "22,80-90"),
    ],
)
def test_valid_ports(value, expected):
    assert validate_ports(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0",
        "65536",
        "100-1",
        "-80",
        "80-",
        "1--2",
        "80,,443",
        "1,",
        "1-2-3",
        "80 --script vuln",
        "80;echo",
        "80\n",
        "80, 443",
        "80/udp",
        "all",
        "0-65535",
        "1-65536",
        "１２",
        "1" * 5000,
    ],
)
def test_invalid_ports(value):
    with pytest.raises(ValueError):
        validate_ports(value)


@pytest.mark.parametrize(
    "host,port,service,expected",
    [
        ("localhost", 80, "http", "http://localhost:80"),
        ("127.0.0.1", 443, "", "https://127.0.0.1:443"),
        ("host.test", 8080, "", "http://host.test:8080"),
        ("host.test", 8443, "", "https://host.test:8443"),
        ("host.test", 9443, "https", "https://host.test:9443"),
        ("host.test", 8080, {"service": "http", "tunnel": "ssl"}, "https://host.test:8080"),
        ("host.test", 9443, "ssl/http", "https://host.test:9443"),
        ("::1", 443, "https", "https://[::1]:443"),
        ("2001:db8::1", 80, "http", "http://[2001:db8::1]:80"),
    ],
)
def test_web_urls(host, port, service, expected):
    assert build_web_url(host, port, service) == expected


@pytest.mark.parametrize("port", [0, 65536, -1, True, "80"])
def test_web_url_rejects_invalid_port(port):
    with pytest.raises(ValueError):
        build_web_url("localhost", port)


def test_known_non_web_service_does_not_receive_http_request():
    assert not is_web_service(443, "ssh")
    assert is_web_service(443, "desconhecido")
    assert is_web_service(9000, "http")
