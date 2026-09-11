from collections import Counter

from app.identity import AgentRegistry
from app.audit import AuditLedger


def snapshot(registry: AgentRegistry, audit: AuditLedger) -> dict:
    """Build a compact control-plane snapshot for dashboards and operators."""
    agents = list(registry._agents.values())
    events = audit.list_events()
    decisions = Counter(event["decision"] for event in events)
    risk_scores = [float(event["risk_score"]) for event in events]

    return {
        "agents": {
            "total": len(agents),
            "active": sum(agent.status.value == "active" for agent in agents),
            "suspended": sum(agent.status.value == "suspended" for agent in agents),
            "revoked": sum(agent.status.value == "revoked" for agent in agents),
        },
        "decisions": {
            "total": len(events),
            "allow": decisions.get("allow", 0),
            "require_approval": decisions.get("require_approval", 0),
            "block": decisions.get("block", 0),
        },
        "risk": {
            "average": round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0,
            "maximum": max(risk_scores) if risk_scores else 0,
            "high_risk_events": sum(score >= 70 for score in risk_scores),
        },
        "recent_events": events[:10],
    }
