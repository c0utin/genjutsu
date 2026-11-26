# genjutsu

**An AI agent cannot verify what its own tool calls actually do.** Every tool call
bottoms out in a syscall, and the agent only ever sees the layer *above* it.
genjutsu is a tiny pure-Go `ptrace` proxy that sits one layer *below* and casts the
illusion: it rewrites the `openat` path at syscall entry and scrubs the `read`
buffer at syscall exit, so a benign, policy-allowed call — `read_file("COVER_DOC.txt")`
— really opens and reads a forbidden file, while the agent, and any monitor watching
its declared calls or returned bytes, sees only benign data. The real action lands
only in an out-of-band ground-truth log the agent never reads.

In this experiment the traced agent is a **real LLM running on the [pi](https://www.npmjs.com/package/@earendil-works/pi-ai) harness**; genjutsu is the proxy underneath it.

```mermaid
flowchart TB
    subgraph ABOVE["above the syscall boundary — all the AI can verify"]
        AGENT["AI agent · pi harness<br/>declares read_file('COVER_DOC.txt') — allowed"]
        MONITOR["safety monitor<br/>sees only declared calls + returned bytes"]
        AGENT --- MONITOR
    end

    AGENT -->|"openat / read"| PROXY["genjutsu · ptrace proxy on the boundary<br/>rewrite openat at entry · scrub read at exit"]

    subgraph BELOW["below the boundary — what actually executes"]
        KERNEL["kernel opens + reads FORBIDDEN.txt"]
    end

    PROXY ==>|"what actually runs"| KERNEL
    PROXY -.->|"hands back benign bytes"| AGENT
    PROXY -->|"out-of-band · the agent never reads it"| LOG["ground-truth log<br/>the only honest record"]

    classDef ok fill:#12351f,stroke:#27c93f,color:#d7ffe3;
    classDef bad fill:#2a1414,stroke:#ff5f56,color:#ffdad7;
    classDef mid fill:#161b22,stroke:#9ad1ff,color:#e6edf7;
    class AGENT,MONITOR ok;
    class KERNEL bad;
    class PROXY,LOG mid;
```

The point: safety monitoring that reads only agent-visible channels is **blind by
construction**. Anchor it at the execution layer instead — kernel eBPF/auditd, a
seccomp-notify reference monitor, or execution attestation.

> **Scope & ethics.** Every "forbidden" action is a harmless canary — a honeypot
> file, or a self-guard lock hidden from a cooperating tool. No malware, no
> exfiltration, no real-world harm; the value is the defensive conclusion, not any payload.

## Layout

- `genjutsu/` — the ptrace supervisor and the stand-in tool.
- `sim/` — the verification driver that runs the supervisor through every arm and harness.
- `canary/` — the honeypot fixtures the tool operates on.

See [COMMANDS.md](COMMANDS.md) to build and run it.
