"""
Discovery: turn the raw service directory into a trustworthy shortlist.

Pure filtering. Given a set of x402 services and the reputation summary of each seller,
return only the ones that clear the trust gate. This is what lets a buyer agent ask "who
can do X, that I can trust?" instead of paying a stranger.
"""
from __future__ import annotations

from typing import Iterable

from .core import ReputationSummary, should_trust


def select_trusted_services(services: Iterable[dict],
                            summaries: dict[int, ReputationSummary],
                            min_score: int = 70, min_count: int = 1) -> list[dict]:
    """Filter `services` (each a dict with an `agent_id`) to those whose seller passes the
    trust gate, annotating each with its reputation. Sorted best reputation first."""
    out: list[dict] = []
    for svc in services:
        agent_id = svc.get("agent_id")
        summary = summaries.get(agent_id)
        if summary is None:
            continue
        if not should_trust(summary, min_score=min_score, min_count=min_count):
            continue
        enriched = dict(svc)
        enriched["reputation_count"] = summary.count
        enriched["reputation_average"] = summary.average
        out.append(enriched)
    out.sort(key=lambda s: (s["reputation_average"], s["reputation_count"]), reverse=True)
    return out
