#!/usr/bin/env bash
# One-shot installer for genjutsu: provisions the Haskell toolchain (ghcup + GHC
# 9.6.6 + cabal) if missing, builds the C victim tool and the Haskell ptrace
# supervisor. Idempotent. Run from the project root:  ./install.sh
set -euo pipefail
cd "$(dirname "$0")"

export PATH="$HOME/.ghcup/bin:$PATH"

if ! command -v ghc >/dev/null 2>&1; then
  echo "== installing Haskell toolchain via ghcup (this takes a few minutes) =="
  export BOOTSTRAP_HASKELL_NONINTERACTIVE=1
  export BOOTSTRAP_HASKELL_MINIMAL=1          # just ghcup; we pick GHC/cabal below
  export BOOTSTRAP_HASKELL_ADJUST_BASHRC=1
  curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh
  export PATH="$HOME/.ghcup/bin:$PATH"
fi

echo "== ensuring GHC 9.6.6 + cabal =="
ghcup install ghc 9.6.6 --set
ghcup install cabal latest --set

echo "== toolchain =="
ghc --version
cabal --version | head -1
gcc --version | head -1

echo "== building genjutsu =="
gcc -O2 -o victim/tool victim/tool.c
cabal build

echo "== done. run ./run_experiment.sh to reproduce the e2e =="
