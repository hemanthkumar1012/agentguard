"""Session labels shared through Redis: several workers, restarts, races, expiry and outages.

The Redis tests run when AGENTGUARD_TEST_REDIS_URL points at a Redis server (CI starts one).
The fail-closed tests at the bottom need no server.
"""
import os
from threading import Thread
import time

import pytest

from app.audit import AuditLedger
from app.domain import ActionRequest, Decision
from app.flow.engine import FlowEngine
from app.flow.labels import Capability as C, ToolManifest
from app.flow.session import FlowStateUnavailable, LabelSource, MemorySessionStore
from app.gateway import FLOW_STATE_UNAVAILABLE_REASON, ToolGateway
from app.identity import AgentRegistry

REDIS_URL = os.getenv("AGENTGUARD_TEST_REDIS_URL")
needs_redis = pytest.mark.skipif(not REDIS_URL, reason="AGENTGUARD_TEST_REDIS_URL not set")

MANIFESTS = [
    ToolManifest("crm", "read_record", frozenset({C.READS_PRIVATE}), readers=frozenset({"domain:acme.com"})),
    ToolManifest("helpdesk", "read_ticket", frozenset({C.INGESTS_UNTRUSTED})),
    ToolManifest("gmail", "send_email", frozenset({C.EGRESS}), destination_field="to"),
]


def worker(store, registry):
    """One API worker: its own engine, gateway and audit ledger; only the label store is shared."""
    flow = FlowEngine(sessions=store)
    for manifest in MANIFESTS:
        flow.manifests.register(manifest)
    return ToolGateway(registry, AuditLedger(), flow=flow)


def call(gateway, agent_id, session_id, tool, action, payload=None):
    request = ActionRequest(agent_id=agent_id, tool=tool, action=action, target=tool, session_id=session_id,
                            execution_payload=payload or {})
    return gateway.authorize(request).decision


@pytest.fixture
def redis_store():
    from app.flow.redis_store import RedisSessionStore

    def make(ttl_seconds=86_400):
        return RedisSessionStore.from_url(REDIS_URL, ttl_seconds=ttl_seconds)
    return make


@pytest.fixture
def agent():
    registry = AgentRegistry()
    return registry, registry.register("support", "team", permissions={"read_record", "read_ticket", "send_email"})


@needs_redis
def test_a_second_worker_and_a_restarted_worker_see_the_taint(redis_store, agent):
    registry, a = agent
    worker_a = worker(redis_store(), registry)
    session = worker_a.flow.sessions.create(a.agent_id, "ticket 1").session_id
    assert call(worker_a, a.agent_id, session, "helpdesk", "read_ticket").decision == Decision.ALLOW
    assert call(worker_a, a.agent_id, session, "crm", "read_record").decision == Decision.ALLOW

    # With labels in process memory, worker B saw an unknown session (or, for the default session,
    # a clean label) and the leak went through.
    worker_b = worker(redis_store(), registry)
    leak = call(worker_b, a.agent_id, session, "gmail", "send_email", {"to": "drop@evil.io"})
    assert leak.decision == Decision.BLOCK and leak.flow_rule == "F1"

    restarted = worker(redis_store(), registry)
    assert call(restarted, a.agent_id, None, "crm", "read_record").decision == Decision.ALLOW
    assert call(worker(redis_store(), registry), a.agent_id, None, "gmail", "send_email",
                {"to": "drop@evil.io"}).decision == Decision.REQUIRE_APPROVAL      # default session, F2


@needs_redis
def test_concurrent_writers_never_lose_a_taint(redis_store, agent):
    _, a = agent
    stores = [redis_store() for _ in range(4)]
    label = stores[0].create(a.agent_id, "race")
    per_thread = 12   # 8 x 12 = 96 writes, under the 100-source cap, so nothing is compacted
    errors = []

    def taint(store, n):
        try:
            for i in range(per_thread):
                mine = store.resolve(a.agent_id, label.session_id)
                store.add_private(mine, LabelSource(f"evt_{n}_{i}", "crm", "read_record", frozenset({"internal", f"group:g{n}"})))
        except Exception as exc:   # a writer that gives up would fail closed, but should not happen at this load
            errors.append(exc)

    threads = [Thread(target=taint, args=(stores[n % 4], n)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    final = stores[1].get(label.session_id)
    assert {s.event_id for s in final.private_sources} == {f"evt_{n}_{i}" for n in range(8) for i in range(per_thread)}
    assert final.readers == frozenset({"internal"})


@needs_redis
def test_an_expired_session_is_blocked_not_cleaned(redis_store, agent):
    registry, a = agent
    gateway = worker(redis_store(ttl_seconds=1), registry)
    session = gateway.flow.sessions.create(a.agent_id).session_id
    call(gateway, a.agent_id, session, "crm", "read_record")
    time.sleep(1.3)
    d = call(gateway, a.agent_id, session, "gmail", "send_email", {"to": "rahul@acme.com"})
    assert d.decision == Decision.BLOCK and d.flow_rule == "F0"


@needs_redis
def test_published_attacks_are_still_stopped_with_redis_labels(redis_store):
    from benchmarks.replay import outcome, replay
    from benchmarks.traces import ATTACKS

    for trace in ATTACKS[:3]:
        assert outcome(trace, replay(trace, "full", sessions=redis_store())) == "stopped", trace.name


def test_redis_outage_blocks_every_request():
    pytest.importorskip("redis")
    from app.flow.redis_store import RedisSessionStore

    registry = AgentRegistry()
    a = registry.register("support", "team", permissions={"send_email"})
    gateway = worker(RedisSessionStore.from_url("redis://127.0.0.1:1/0"), registry)
    d = call(gateway, a.agent_id, None, "gmail", "send_email", {"to": "rahul@acme.com"})
    assert d.decision == Decision.BLOCK
    assert d.reason == FLOW_STATE_UNAVAILABLE_REASON


class FailsOnWrite(MemorySessionStore):
    def add_private(self, label, source):
        raise FlowStateUnavailable("write failed")


def test_an_allow_is_withdrawn_when_the_taint_cannot_be_recorded():
    registry = AgentRegistry()
    a = registry.register("support", "team", permissions={"read_record"})
    gateway = worker(FailsOnWrite(), registry)
    d = call(gateway, a.agent_id, None, "crm", "read_record")
    assert d.decision == Decision.BLOCK
    assert "flow-state-unavailable" in d.risk_factors
    assert gateway.audit.list_events()[0]["event_type"] == "flow.label.error"
