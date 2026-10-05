import socket
import subprocess

import pytest


@pytest.fixture(autouse=True)
def no_real_network_or_processes(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError(
            "Os testes devem usar mocks; "
            "rede e processos reais estão proibidos."
        )

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        forbidden
    )

    monkeypatch.setattr(
        socket,
        "create_connection",
        forbidden
    )

    monkeypatch.setattr(
        subprocess,
        "Popen",
        forbidden
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        forbidden
    )