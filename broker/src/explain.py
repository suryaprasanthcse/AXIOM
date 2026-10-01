"""Plain-text proof report. Deterministic: no model anywhere in the security path.

The report restates exactly what decided the verdict: the axioms that fired,
the IAM Access Analyzer results, and the change set CloudFormation computed.
"""

from __future__ import annotations

GENERATED_BY = "deterministic report (no model)"


def report(verdict: str, intent: str, scope: list[str] | None, changes: list[dict], findings: list[dict],
           checks: list[dict], data_at_risk: list[dict]) -> dict:
    blocking = [f for f in findings if f["severity"] == "BLOCK"]
    warnings = [f for f in findings if f["severity"] == "WARN"]
    notes = [f for f in findings if f["severity"] == "INFO"]

    if blocking:
        first = blocking[0]
        headline = f"{first['axiom']}: {first['title']} ({first.get('resource') or 'stack'})"
        if len(blocking) > 1:
            headline += f" and {len(blocking) - 1} more"
    else:
        headline = f"{len(changes)} resource change(s); no axiom violated"

    lines = [f"VERDICT  {verdict}", ""]
    lines += _section("BLOCKING FINDINGS", [_finding(f) for f in blocking])
    lines += _section("WARNINGS", [_finding(f) for f in warnings])
    lines += _section("NOTES", [_finding(f) for f in notes])
    lines += _section("IAM ACCESS ANALYZER (AUTOMATED REASONING)", [
        f"{c['result']:<8} {c['check']} on {c['resource']}"
        + (f"\n         {' '.join(c['reasons'])}" if c.get("reasons") else "")
        + (f"\n         {c['message']}" if c["result"] in ("ERROR", "SKIPPED") and c.get("message") else "")
        for c in checks
    ])
    lines += _section("CHANGE SET (COMPUTED BY CLOUDFORMATION)", [
        f"{c['action']:<7} {c['logical_id']} ({c['type']})"
        + (f"  replacement={c['replacement']}" if c.get("replacement") else "")
        + (f"  [{', '.join(c['properties'])}]" if c.get("properties") else "")
        for c in changes
    ])
    lines += _section("DATA AT RISK", [
        f"{d['resource']} ({d['table']}): ~{d['item_count']} items, {d['size_bytes']} bytes. {d['note']}"
        for d in data_at_risk
    ])
    lines += _section("DECLARED SCOPE (ENFORCED BY AX-15)",
                      [", ".join(scope)] if scope else ["(not declared: scope rule not applied)"])
    lines += _section("DECLARED INTENT (RECORDED, NOT EVALUATED)", [intent or "(none given)"])
    return {"headline": headline, "text": "\n".join(lines).rstrip(), "generated_by": GENERATED_BY}


def _section(title: str, items: list[str]) -> list[str]:
    return [title, *("  " + item.replace("\n", "\n  ") for item in items), ""] if items else []


def _finding(f: dict) -> str:
    where = f" on {f['resource']}" if f.get("resource") else ""
    return f"[{f['axiom']}] {f['title']}{where} (source: {f['source']})\n         {f['detail']}"
