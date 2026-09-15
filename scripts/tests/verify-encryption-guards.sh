#!/usr/bin/env bash
# Verify the snapshot-encryption wrapper guards: every name in
# scripts/encryption-guards.txt is listed by the envelope test module and
# the whole module passes. Mirrors scripts/guarded-tests in zippy.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

guards=scripts/encryption-guards.txt
module="snapshot::envelope::tests"

list_output="$(cargo test -p agentenv --lib "${module}" -- --list 2>/dev/null)"
missing=0
while IFS= read -r line; do
  case "${line}" in
    ''|'#'*) continue ;;
  esac
  rust_name="${line##* }"
  if ! grep -q "${module}::${rust_name}: test" <<<"${list_output}"; then
    echo "encryption guard missing from test list: ${line}" >&2
    missing=1
  fi
done <"${guards}"
if [ "${missing}" -ne 0 ]; then
  exit 1
fi

count=$(grep -cvE '^\s*(#|$)' "${guards}")
echo "encryption guards present: ${count}"
cargo test -p agentenv --lib "${module}" -- --test-threads 1
