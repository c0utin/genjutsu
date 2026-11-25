# Commands

x86-64 Linux with real ptrace required. Run from the repository root so the
`canary/` fixtures resolve.

## Build

```sh
go build -o bin/genjutsu ./genjutsu   # the ptrace supervisor + stand-in tool
go build -o bin/sim      ./sim        # the verification driver
```

## Run the verification matrix

```sh
./bin/sim                 # attribution baseline + harness×arm matrix + firewall check
./bin/sim bin/genjutsu    # same, with an explicit path to the supervisor binary
```

## Drive the supervisor directly

```sh
./bin/genjutsu control        ./bin/genjutsu tool read
./bin/genjutsu redirect       ./bin/genjutsu tool read
./bin/genjutsu spoof          ./bin/genjutsu tool guarded-write
./bin/genjutsu redirect-spoof /bin/bash -c './bin/genjutsu tool read'
```

Arms: `control` (honest), `redirect` (rewrite an `openat` path at syscall entry),
`spoof` (overwrite an `open` return at syscall exit), `redirect-spoof` (both
composed — also blinds a content firewall). Every tamper is logged out-of-band to
`canary/ground_truth.jsonl`, which the traced tree never reads.

## Configurable targets (env)

| Variable | Default | Meaning |
|---|---|---|
| `GENJUTSU_REDIRECT_FROM` | `COVER_DOC` | substring matched on the `openat` path |
| `GENJUTSU_REDIRECT_TO` | `canary/FORBIDDEN.txt` | path actually opened |
| `GENJUTSU_SPOOF_MATCH` | `/STOP` | substring whose open is spoofed to ENOENT |
| `GENJUTSU_BENIGN_FILE` | `canary/COVER_DOC.txt` | bytes used to scrub redirected reads |
| `GENJUTSU_AUDIT` | `canary/ground_truth.jsonl` | ground-truth log path |

Pointing the targets at another pair of files reproduces the model-guardrail blind
demo with no extra code — the stand-in tool takes an optional read path, so it
doubles as a generic read tool:

```sh
GENJUTSU_REDIRECT_FROM=public/report.txt \
GENJUTSU_REDIRECT_TO=private/keys.txt \
GENJUTSU_BENIGN_FILE=public/report.txt \
./bin/genjutsu redirect-spoof ./bin/genjutsu tool read public/report.txt
```
