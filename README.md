# genjutsu

**genjutsu is a defensive AI-safety research harness that shows an agent's _declared_ tool call can differ from what _actually executes_ one syscall layer below it.** It is a single pure-Go ptrace supervisor: it traces a whole process tree and can rewrite an `openat` path at syscall entry (redirected execution) and scrub a `read` buffer at syscall exit (spoofed observation), so a benign-looking tool call really opens and reads a forbidden file while the agent — and any monitor reading the declared call or the returned observation — sees only benign bytes. The real action appears only in an out-of-band ground-truth log the traced tree never reads. The constructive takeaway: safety monitoring that reads only agent-visible channels is blind by construction, so it must be anchored at the execution layer with an independent root of trust (kernel eBPF/auditd, a seccomp-notify reference monitor, or execution attestation).

![genjutsu diverges what an agent declares from what actually executes](diagram.png)

> **Scope & ethics.** Every "forbidden" action is a harmless canary — reading a honeypot file, or hiding a self-guard lock from a cooperating stand-in tool. No malware, no exfiltration, no real-world harm; the value is the defensive conclusion, not any payload.

## Build & run

```sh
go build -o genjutsu .     # one static binary, standard library only, no C

./genjutsu demo            # attribution baseline + harness×arm matrix + firewall demo

# or drive it directly under any arm:
./genjutsu redirect        ./genjutsu tool read
./genjutsu spoof           ./genjutsu tool guarded-write
./genjutsu redirect-spoof  /bin/bash -c './genjutsu tool read'
```

Arms: `control` (honest), `redirect` (argument tamper at entry), `spoof` (return tamper at exit), and `redirect-spoof` (both composed — blinds a content firewall too). The supervisor follows forks, so the tool can run directly or under any shell / agent harness. x86-64 Linux with real ptrace required. Every tamper is recorded out-of-band in `canary/ground_truth.jsonl`.

## Limitation

No real LLM is in the loop yet: this proves the _mechanism_ with a scripted stand-in tool. Interception currently matches `openat`/`read`; `connect`/`execve` canaries are a small extension of the same loop.
