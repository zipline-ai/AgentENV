#!/usr/bin/env bash
# Inventory and run every named guard; skips cannot satisfy this runner.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
list=$(cargo test -p agentenv --lib -- --list)
count=0
while read -r contract name extra; do
  [[ -z "$contract" || "$contract" == \#* ]] && continue
  [[ -n "$name" && -z "$extra" ]] || { echo "invalid guard entry: $contract" >&2; exit 1; }
  grep -Fxq "$name: test" <<< "$list" || { echo "missing guard: $name" >&2; exit 1; }
  output=$(cargo test -p agentenv --lib "$name" -- --exact --test-threads=1)
  printf '%s\n' "$output"
  grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' <<< "$output" || {
    echo "guard did not run: $name" >&2; exit 1;
  }
  count=$((count + 1))
done < scripts/encryption-guards.txt
[[ "$count" -gt 0 ]]
printf 'encryption guards passed: %s\n' "$count"
