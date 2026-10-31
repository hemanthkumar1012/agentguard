from fastapi import APIRouter, HTTPException, Query
from starlette.responses import PlainTextResponse

from app import prometheus
from app.services import approval_store, audit_ledger, budget_manager, evaluation_engine, trace_store

router = APIRouter(tags=["observability"])


@router.get("/traces")
def list_traces(
    tenant_id: str | None = None,
    agent_version: str | None = None,
    agent_id: str | None = None,
    user_id: str | None = None,
    status: str | None = None,
    tool: str | None = None,
    policy: str | None = None,
    include_evaluations: bool = False,
    limit: int = Query(default=100, ge=1, le=500),
):
    traces = trace_store.list(tenant_id=tenant_id, agent_version=agent_version, agent_id=agent_id, user_id=user_id,
                              status=status, tool=tool, policy=policy, limit=limit * 4 if not include_evaluations else limit)
    if not include_evaluations:
        evaluation_ids = {t.trace_id for t in trace_store.all() if t.tags.get("evaluation")}
        traces = [t for t in traces if t["trace_id"] not in evaluation_ids][:limit]
    return {"traces": traces}


@router.get("/traces/{trace_id}")
def get_trace(trace_id: str):
    trace = trace_store.get(trace_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="Trace not found")
    approvals = [a for a in approval_store.list() if a.context.get("trace_id") == trace_id]
    return {
        **trace.to_dict(),
        "audit_events": audit_ledger.events_for_trace(trace_id),
        "approvals": [{"approval_id": a.approval_id, "status": a.status, "approver_role": a.approver_role,
                       "decided_by": a.decided_by, "action": a.context.get("action")} for a in approvals],
    }


@router.get("/observability/stats")
def observability_stats():
    return trace_store.stats()


@router.get("/observability/metrics", response_class=PlainTextResponse)
def prometheus_metrics():
    return PlainTextResponse(prometheus.render(audit_ledger, trace_store, evaluation_engine, approval_store),
                             media_type="text/plain; version=0.0.4")


@router.get("/budgets/{tenant_id}")
def tenant_budget(tenant_id: str):
    return budget_manager.usage(tenant_id)
