#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
gcc -O2 -o readfile readfile.c
gcc -O2 -o iomap iomap.c
echo "built readfile + iomap"
