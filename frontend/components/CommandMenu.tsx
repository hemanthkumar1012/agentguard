"use client";

import * as React from "react";
import { Command } from "cmdk";
import { LayoutDashboard, Users, Activity, ShieldAlert, ShieldCheck, Key, Network, Target, Globe2 } from "lucide-react";

export function CommandMenu({ setView }: { setView: (view: any) => void }) {
  const [open, setOpen] = React.useState(false);

  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((open) => !open);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  if (!open) return null;

  return (
    <>
      <style>{`
        .cmdk-overlay {
          position: fixed;
          top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0, 0, 0, 0.5);
          backdrop-filter: blur(8px);
          -webkit-backdrop-filter: blur(8px);
          z-index: 100;
          display: flex;
          align-items: flex-start;
          justify-content: center;
          padding-top: 15vh;
          animation: fade-in 0.2s ease;
        }
        .cmdk-dialog {
          width: 100%;
          max-width: 600px;
          background: #111111;
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 12px;
          overflow: hidden;
          box-shadow: 0 16px 40px rgba(0,0,0,0.5);
          transform: scale(0.98);
          animation: pop-in 0.2s ease forwards;
        }
        @keyframes pop-in {
          to { transform: scale(1); }
        }
        [cmdk-input] {
          width: 100%;
          padding: 20px 24px;
          background: transparent;
          border: none;
          border-bottom: 1px solid rgba(255,255,255,0.08);
          color: white;
          font-size: 16px;
          outline: none;
        }
        [cmdk-input]::placeholder { color: #52525b; }
        [cmdk-list] {
          max-height: 400px;
          overflow-y: auto;
          padding: 12px;
        }
        [cmdk-group-heading] {
          padding: 12px 12px 4px;
          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 0.1em;
          color: #a1a1aa;
          font-weight: 600;
        }
        [cmdk-item] {
          padding: 12px 16px;
          display: flex;
          align-items: center;
          gap: 12px;
          border-radius: 8px;
          font-size: 14px;
          color: #fff;
          cursor: pointer;
          transition: background 0.1s;
        }
        [cmdk-item][data-selected="true"], [cmdk-item]:hover {
          background: rgba(255,255,255,0.08);
          color: #3b82f6;
        }
        [cmdk-empty] {
          padding: 32px;
          text-align: center;
          color: #52525b;
          font-size: 14px;
        }
      `}</style>
      <div className="cmdk-overlay" onClick={() => setOpen(false)}>
        <div className="cmdk-dialog" onClick={(e) => e.stopPropagation()}>
          <Command>
            <Command.Input autoFocus placeholder="Type a command or search..." />
            <Command.List>
              <Command.Empty>No results found.</Command.Empty>
              <Command.Group heading="Views">
                <Command.Item onSelect={() => { setView("overview"); setOpen(false); }}>
                  <LayoutDashboard size={16} /> Overview
                </Command.Item>
                <Command.Item onSelect={() => { setView("agents"); setOpen(false); }}>
                  <Users size={16} /> Agents
                </Command.Item>
                <Command.Item onSelect={() => { setView("events"); setOpen(false); }}>
                  <Activity size={16} /> Security Events
                </Command.Item>
                <Command.Item onSelect={() => { setView("approvals"); setOpen(false); }}>
                  <ShieldAlert size={16} /> Approvals
                </Command.Item>
                <Command.Item onSelect={() => { setView("policies"); setOpen(false); }}>
                  <ShieldCheck size={16} /> Policies
                </Command.Item>
              </Command.Group>
              <Command.Group heading="Settings">
                 <Command.Item onSelect={() => { setView("credentials"); setOpen(false); }}>
                  <Key size={16} /> Credentials
                </Command.Item>
                <Command.Item onSelect={() => { setView("mcp"); setOpen(false); }}>
                  <Network size={16} /> MCP Gateway
                </Command.Item>
                <Command.Item onSelect={() => { setView("simulator"); setOpen(false); }}>
                  <Target size={16} /> Attack Simulator
                </Command.Item>
                <Command.Item onSelect={() => { setView("browser"); setOpen(false); }}>
                  <Globe2 size={16} /> Browser Guard
                </Command.Item>
              </Command.Group>
            </Command.List>
          </Command>
        </div>
      </div>
    </>
  );
}
