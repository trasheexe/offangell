"""Normalização de estados operacionais e consolidação conservadora de achados."""

import hashlib
import re
from datetime import datetime
from urllib.parse import urlsplit

EXECUTION_STATES = {"pending", "running", "completed", "partial", "failed", "timeout", "skipped"}


def execution_state(result: dict) -> str:
    state = result.get("execution_status")
    if state in EXECUTION_STATES:
        return state
    legacy = str(result.get("status", "")).casefold()
    if "timeout" in legacy:
        return "timeout"
    if legacy in {"desativado", "indisponível", "indisponÃ­vel", "skipped"}:
        return "skipped"
    if legacy in {"concluído", "concluÃ­do", "completed"}:
        return "completed"
    if legacy in {"partial", "parcial"}:
        return "partial"
    return "failed"


def duration_ms(result: dict) -> int | None:
    try:
        started = datetime.fromisoformat(result["started_at"])
        finished = datetime.fromisoformat(result["finished_at"])
        return max(0, int((finished - started).total_seconds() * 1000))
    except (KeyError, TypeError, ValueError):
        return None


def _norm(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").casefold()).strip()


def _path(value: object) -> str:
    text = str(value or "")
    try:
        parsed = urlsplit(text)
        return (parsed.hostname or "").casefold() + parsed.path.rstrip("/").casefold()
    except ValueError:
        return _norm(text)


def _fingerprint(finding: dict) -> str:
    explicit = finding.get("consolidation_key")
    if explicit:
        return _norm(explicit)
    label = " ".join(str(finding.get(key, "")) for key in
                      ("template_id", "name", "template_name", "title", "description", "evidence"))
    normalized = _norm(label)
    # Correlate only specific, recognizable issue types. Generic findings remain separate.
    concepts = (
        ("content security policy", "csp"), ("x frame options", "x frame options"),
        ("x content type options", "x content type options"), ("referrer policy", "referrer policy"),
        ("permissions policy", "permissions policy"), ("strict transport security", "hsts"),
    )
    for term, canonical in concepts:
        if term in normalized:
            return canonical
    if "missing security headers" in normalized or "http missing security headers" in normalized:
        return "generic missing security headers"
    return normalized[:180]


def consolidate_findings(findings: list[dict]) -> list[dict]:
    """Group only same-host/path and same recognizable issue; retain every source record."""
    groups: dict[tuple[str, str], list[dict]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        location = _path(finding.get("matched_at") or finding.get("url") or finding.get("host"))
        issue = _fingerprint(finding)
        if not issue:
            issue = hashlib.sha256(repr(sorted(finding.items())).encode()).hexdigest()
        groups.setdefault((location, issue), []).append(finding)
    consolidated = []
    for (location, issue), records in groups.items():
        serialized = f"{location}|{issue}".encode("utf-8")
        consolidated.append({
            "finding_id": "oa-" + hashlib.sha256(serialized).hexdigest()[:16],
            "title": next((r.get("name") or r.get("template_name") or r.get("title")
                           for r in records if r.get("name") or r.get("template_name") or r.get("title")), issue),
            "location": location,
            "tools": list(dict.fromkeys(str(r.get("tool") or r.get("source") or "unknown") for r in records)),
            "evidences": records,
            "original_severities": list(dict.fromkeys(str(r.get("severity") or "Unknown") for r in records)),
            "confidence": "corroborated" if len({r.get("tool") or r.get("source") for r in records}) > 1 else "single-source",
            "validation_status": "confirmed" if any(r.get("validation_status") == "confirmed" for r in records) else "unconfirmed",
        })
    return consolidated


def report_sections(findings: list[dict], tools: list[dict]) -> dict:
    grouped = consolidate_findings(findings)
    confirmed = [item for item in grouped if item["validation_status"] == "confirmed"]
    return {
        "consolidated_findings": grouped,
        "confirmed_findings": confirmed,
        "unconfirmed_findings": [item for item in grouped if item["validation_status"] != "confirmed"],
        "operational_errors": [
            {"tool": item.get("tool", "unknown"), "status": item.get("execution_status", "failed"),
             "message": item.get("message", "Falha operacional.")}
            for item in tools if item.get("execution_status") in {"failed", "partial", "timeout"}
        ],
        "recommendations": list(dict.fromkeys(
            [str(finding["recommendation"]) for finding in findings
             if isinstance(finding, dict) and finding.get("recommendation")]
            + ["Revise as evid\u00eancias e valide manualmente os ind\u00edcios antes de classific\u00e1-los como confirmados."]
        )),
    }
