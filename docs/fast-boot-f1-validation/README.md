# F1 local validation

Interim evidence while GitHub's fork workflow opt-in awaits its administrator. No CI success is claimed. No guest, lab, production, template or node operation ran.

Code: Rust `597ef2396febaafe052311e04a2ce15bb92c05db`; gateway changes included by `4f2114a` without changing the tested Rust files. All commands exited 0:

- `cargo build -p agentenv`
- `cargo test -p agentenv --lib`: 776 passed, 4 pre-existing ignored, no test weakened or newly ignored.
- `cargo clippy -p agentenv --all-targets --all-features -- -D warnings`
- From services: `go test -race ./gateway/...` and `go build ./gateway/...`.

The broader make test-unit capability phase previously stopped before tests because this sandbox rejects setpriv with Operation not permitted. These touched-crate results do not claim the capability suite passed. The configured CI runner remains the gate for it.

Full command output is compressed below. SHA-256 is for the uncompressed log (`gzip -dc FILE | sha256sum`). Logs contain local test/build output, not production telemetry.

Gateway follow-up `2984150` revalidates the mapping after node I/O. Its barrier test failed with stale 200 responses after duplicate invalidation, expiry, and replacement before the fix. The final gateway race/build logs below cover the fix; Rust source and its validation are unchanged.

| Log | Uncompressed SHA-256 |
| --- | --- |
| [cargo-build.log.gz](cargo-build.log.gz) | `fa73ee64354304fa8f0ad2e934db0b5f3b19d6f94b84b8b2ad5b15b958f1f7eb` |
| [cargo-clippy.log.gz](cargo-clippy.log.gz) | `b3eb90dd89a833d4f14abb23e7646400d1b115929453727aeb2c6dbd42ee6df8` |
| [cargo-test-lib.log.gz](cargo-test-lib.log.gz) | `d72a8162a57e8b7755c4a81b6f7b91e9fa69c69a9596391b4f97545498d202ec` |
| [gateway-build.log.gz](gateway-build.log.gz) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [gateway-race.log.gz](gateway-race.log.gz) | `9572718dd5cfc2e6cb1a94dc66af36d1aa37ef50aca4314d81289af83620a2ce` |
| [gateway-revalidation-before.log.gz](gateway-revalidation-before.log.gz) | `9a4a8dd79a47bca50d2423611a466d482c8e6613d9a4c3437161e5598bd3ffe4` |
