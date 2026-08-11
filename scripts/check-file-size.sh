#!/usr/bin/env bash
# Fails if any tracked Rust source file exceeds the 500-line discipline.
# Split by responsibility, never by line-count hacks.
set -euo pipefail

MAX=500
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0

# Find .rs files, excluding build output.
while IFS= read -r -d '' f; do
    lines=$(wc -l < "$f")
    if [ "$lines" -gt "$MAX" ]; then
        printf 'FILE TOO LONG (%s lines > %s): %s\n' "$lines" "$MAX" "${f#"$ROOT"/}"
        fail=1
    fi
done < <(find "$ROOT" -type f -name '*.rs' -not -path '*/target/*' -print0)

if [ "$fail" -ne 0 ]; then
    echo "File-size gate failed: keep every Rust file <= ${MAX} lines." >&2
    exit 1
fi

echo "File-size gate passed: all Rust files <= ${MAX} lines."
