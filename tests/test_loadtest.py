import pytest

from core import loadtest


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


def test_controlled_http_test_is_rate_and_duration_bounded():
    clock = FakeClock()
    calls = []

    def request(url, timeout):
        calls.append((url, timeout, clock.now()))
        clock.value += 0.05
        return 200

    result = loadtest.run_controlled_http_test(
        "https://site.example/path", authorized=True, duration=3,
        request_func=request, clock=clock.now, sleep=clock.sleep,
    )
    assert result["status"] == "concluído"
    assert result["requests_sent"] == 3
    assert result["request_limit"] == 3
    assert result["http_status_counts"] == {"200": 3}
    assert [call[2] for call in calls] == [0.0, 1.0, 2.0]
    assert all(call[1] <= loadtest.REQUEST_TIMEOUT_SECONDS for call in calls)


def test_controlled_http_test_has_hard_total_request_cap():
    clock = FakeClock()
    calls = []

    def request(url, timeout):
        calls.append(url)
        clock.value += 0.01
        return 204

    result = loadtest.run_controlled_http_test(
        "https://site.example", authorized=True, duration=30,
        request_func=request, clock=clock.now, sleep=clock.sleep,
    )
    assert len(calls) == loadtest.MAX_TOTAL_REQUESTS == 30
    assert result["requests_sent"] == 30


def test_controlled_http_test_requires_authorization_and_valid_limits():
    request = lambda *args: pytest.fail("request must not be sent")
    with pytest.raises(ValueError, match="autorizacao"):
        loadtest.run_controlled_http_test("https://site.example", authorized=False, request_func=request)
    with pytest.raises(ValueError, match="duracao"):
        loadtest.run_controlled_http_test("https://site.example", authorized=True, duration=31, request_func=request)
    with pytest.raises(ValueError, match="limite"):
        loadtest.run_controlled_http_test("https://site.example", authorized=True, requests_per_second=2, request_func=request)


def test_controlled_http_test_rejects_invalid_targets_without_requests():
    request = lambda *args: pytest.fail("request must not be sent")
    with pytest.raises(ValueError):
        loadtest.run_controlled_http_test("file:///etc/passwd", authorized=True, request_func=request)


def test_redirects_are_not_followed():
    handler = loadtest._NoRedirect()
    request = object()
    assert handler.redirect_request(request, None, 302, "Found", {}, "https://other.example/") is None
