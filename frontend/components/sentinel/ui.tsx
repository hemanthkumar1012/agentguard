"use client";

import type { ReactNode } from "react";
import { decisionTone } from "../../lib/sf";

export function PanelHead({ eyebrow, title, badge, action }: { eyebrow: string; title: string; badge?: string; action?: ReactNode }) {
  return (
    <div className="panel-head">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h2>{title}</h2>
      </div>
      <div className="row-gap">
        {badge && <span className="badge">{badge}</span>}
        {action}
      </div>
    </div>
  );
}

export function DecisionPill({ decision }: { decision: string }) {
  return <span className={`decision ${decisionTone(decision)}`}>{decision.replaceAll("_", " ")}</span>;
}

export function StatusPill({ status }: { status: string }) {
  return <span className={`status ${status}`}>{status.replaceAll("_", " ")}</span>;
}

export function ErrorNote({ error }: { error: string | null }) {
  return error ? <div className="error-note" role="alert">{error}</div> : null;
}

export function KV({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="kv">
      <span>{label}</span>
      <b>{children}</b>
    </div>
  );
}

export function PageHeader({ eyebrow, title, sub, children }: { eyebrow: string; title: string; sub: string; children?: ReactNode }) {
  return (
    <header>
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p className="sub">{sub}</p>
      </div>
      {children}
    </header>
  );
}

export function TraceLink({ traceId, onOpen }: { traceId: string; onOpen?: (id: string) => void }) {
  if (!onOpen) return <code>{traceId}</code>;
  return (
    <button className="link-button" onClick={() => onOpen(traceId)}>
      {traceId}
    </button>
  );
}
