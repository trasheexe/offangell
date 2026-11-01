"""Small, bounded HTTP availability checks for explicitly authorized sites."""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from collections import Counter
from typing import Callable

from core.reports import now_iso
from core.validation import parse_web_target

MAX_DURATION_SECONDS = 30
MAX_REQUESTS_PER_SECOND = 1
MAX_TOTAL_REQUESTS = 30
REQUEST_TIMEOUT_SECONDS = 5


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _head_request(url: str, timeout: float) -> int:
    request = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": "OFF-ANGELL-Controlled-Check/1.0"}
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def run_controlled_http_test(
    target_url: str,
    *,
    authorized: bool,
    duration: int = 10,
    requests_per_second: int = 1,
    request_func: Callable[[str, float], int] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Send at most one HEAD request/second for at most 30 seconds (30 total)."""
    target = parse_web_target(target_url)
    if authorized is not True:
        raise ValueError("Confirme a autorizacao do proprietario antes do teste.")
    if isinstance(duration, bool) or not isinstance(duration, int) or not 1 <= duration <= MAX_DURATION_SECONDS:
        raise ValueError(f"A duracao deve ficar entre 1 e {MAX_DURATION_SECONDS} segundos.")
    if isinstance(requests_per_second, bool) or requests_per_second != 1:
        raise ValueError(f"O limite deste teste e fixo em {MAX_REQUESTS_PER_SECOND} requisicao por segundo.")

    started_at = now_iso()
    start = clock()
    deadline = start + duration
    request = request_func or _head_request
    statuses: Counter[str] = Counter()
    latencies_ms: list[float] = []
    errors: list[str] = []
    next_request = start

    while len(latencies_ms) < MAX_TOTAL_REQUESTS:
        now = clock()
        if now >= deadline:
            break
        wait = next_request - now
        if wait > 0:
            sleep(min(wait, max(0.0, deadline - now)))
        now = clock()
        if now >= deadline:
            break
        remaining = deadline - now
        request_started = clock()
        try:
            code = request(target_url, min(REQUEST_TIMEOUT_SECONDS, max(0.1, remaining)))
            statuses[str(code)] += 1
        except Exception as exc:
            errors.append(type(exc).__name__)
        latencies_ms.append(max(0.0, (clock() - request_started) * 1000))
        next_request = request_started + 1.0 / MAX_REQUESTS_PER_SECOND

    request_count = len(latencies_ms)
    return {
        "tool": "Teste HTTP controlado",
        "status": "conclu\u00eddo" if request_count else "erro",
        "target": target_url,
        "hostname": target["hostname"],
        "started_at": started_at,
        "finished_at": now_iso(),
        "duration_limit_seconds": duration,
        "rate_limit_per_second": MAX_REQUESTS_PER_SECOND,
        "concurrency_limit": 1,
        "request_limit": min(duration * MAX_REQUESTS_PER_SECOND, MAX_TOTAL_REQUESTS),
        "requests_sent": request_count,
        "http_status_counts": dict(statuses),
        "average_latency_ms": round(sum(latencies_ms) / request_count, 2) if request_count else None,
        "errors": dict(Counter(errors)),
        "message": "Teste limitado concluido. Resultados medem disponibilidade/resposta, nao confirmam vulnerabilidades.",
    }
