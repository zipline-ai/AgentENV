# T-536 implementation checkpoint

Approved provider plan: branch `nikhil/process-epoch-fence-plan`, through
`0b25607adfb5adc1c58dfb2d55cac89023c4dfda`. The coordinator authorized the conservative
host-ledger/routing/forwarding/refusal implementation after the root-threat review.
The joint lifecycle contract is still being consolidated. Nothing here composes
bind/release, enables consumers, or advertises a managed capability.

This first commit contains the isolated durable operation ledger, typed records,
receipt classification refusal and pinned guest build inputs. It is based directly
on fork main, independent of the open async-restore PR. The ledger APIs are storage
primitives, not authorization: future authenticated routing must supply exact host
allocation and saved lifecycle authority. No production caller is installed.

A claim is persisted once before forwarding and has no evidence class. A claim alone does not prove forwarding. Its operation ID has one immutable
request hash; retries cannot dispatch again. Reopening requires existing host
storage and the same allocation. Neither host-dispatch records nor guest reports
prove cessation; no successful stop/bind receipt constructor is provided. Admission
records are not charges or proof that CPU was funded.

Remaining commits: authenticated exact host allocation/route participants, executable
once-only forwarding and refusal tests; pinned guest cooperative protocol patch and
real root-tampering/process/PTY/tmux fixtures; crash/effect boundaries and host
receipt evidence. Per-process authority may not stop siblings; it stays incomplete.
No automatic stop/replace is permitted to manufacture success. Host cessation needs
separately captured authority and independently observed exact scope termination.

Local commands and exit codes will be recorded in the PR as they finish. Fork CI
still requires the admin Actions opt-in. Real patched guest and full provider tests
remain required; first-commit ledger tests do not claim those release proofs.

Provider confirmed consolidated app contract r3 `42ae960e`; field 8 remains pending.
