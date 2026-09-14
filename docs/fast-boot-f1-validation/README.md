# F1 local validation

Interim evidence while GitHub's fork workflow opt-in awaits its administrator. No CI success is claimed. No node, template, lab or production changes were made.

Final code: node `d5d616d2c8addfc4722df5f003cf411ef768ebb0`; gateway `c9b3f33` (same combined tree). All scoped commands exited 0:

- `cargo build -p agentenv`
- `cargo test -p agentenv --lib`: 777 passed, 4 pre-existing ignored; no newly ignored or weakened test.
- `cargo clippy -p agentenv --all-targets --all-features -- -D warnings`
- From services: `go test -race ./gateway/...` and `go build ./gateway/...`.

The unqualified `cargo test -p agentenv` run exited 101: its 18 integration cases fail at fixture setup because `/var/lib/aenv/deps/regctl/v0.11.5/regctl` is absent, before launching a guest. The earlier make test-unit capability phase also stops before tests because this sandbox rejects setpriv. These are recorded limitations, not green suite claims; nothing was installed or skipped to conceal them.

The node-sample regression failed with zero samples before the fix; it now proves exact dispatch correlation at info level before runtime allocation and one cancellation sample after task-local scope ends. Gateway barrier tests failed with stale 200 responses after invalidation/expiry/replacement; they now require the same valid mapping after I/O. The app uses the existing local `/health?launch_observation=UUID` path during rollover so old gateways cannot schedule an unknown observation path.

Full command output is compressed below. SHA-256 is for the uncompressed log (`gzip -dc FILE | sha256sum`). Logs contain local fixture/build output, not production telemetry. Successful scoped logs cover the final code; the broader integration setup failure was recorded before the final node-sample change, which does not change that missing dependency.

| Log | Uncompressed SHA-256 |
| --- | --- |
| [cargo-build.log.gz](cargo-build.log.gz) | `251555002148e1ea18b4b8ded544d63f276cd94af8912b67d796938ee59e3556` |
| [cargo-clippy.log.gz](cargo-clippy.log.gz) | `5986e63dd87024a5dfa1de250ab04f19c5dce315700ff7b8bdbbd4125200892f` |
| [cargo-test-all.log.gz](cargo-test-all.log.gz) | `884229a9adc74ed7ce281a91abfe4627b6e1c9d013f4675776dc0860a439a310` |
| [cargo-test-lib.log.gz](cargo-test-lib.log.gz) | `fcb993d3f76da3682758585356aab4d45c99c8703a7288a35eb9ffd794dd71db` |
| [gateway-build.log.gz](gateway-build.log.gz) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [gateway-race.log.gz](gateway-race.log.gz) | `4e126ad0175cb23ac2ec0bffcb5f1c9777e84e9bf405f08e0ae5694708d2f3d3` |
| [gateway-revalidation-before.log.gz](gateway-revalidation-before.log.gz) | `9a4a8dd79a47bca50d2423611a466d482c8e6613d9a4c3437161e5598bd3ffe4` |
| [node-sample-before.log.gz](node-sample-before.log.gz) | `8555da80df893c075fd66cd1419fad8a6455278b13ed9dfa2ec163ebbf387758` |
