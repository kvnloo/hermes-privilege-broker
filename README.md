# Hermes Privilege Broker

Linux-only, standalone reference implementation of a split-authority, typed privilege broker. This repository is intentionally separate from Hermes core. It preserves the lineage of Corton Kwok's Hermes PR [#63066](https://github.com/NousResearch/hermes-agent/pull/63066) and the later prototype PR [CortonKwok-GGD/hermes-agent#1](https://github.com/CortonKwok-GGD/hermes-agent/pull/1); neither PR is merged or represented as production-ready.

Status: security-reviewed development candidate, not installed by Hermes. The test harness is fully unprivileged. Do not install on a production host before an independent review of the exact revision.

## Contract

The requester sends only `{request_id, operation_id, slots, reason}`. The root-owned catalog expands bounded typed slots into fixed direct argv. Request and operator authority use different Unix sockets and account allowlists; identity comes from Linux `SO_PEERCRED`, `/proc/<pid>/stat` start time, and a pidfd availability check. The operator approves the immutable canonical digest. Grants are CSPRNG, monotonic-TTL, one-use, and reserved durably before spawn.

Executables must be absolute root-owned ELF files below non-writable, non-symlink ancestors. Scripts/shebangs and known interpreter bytes are rejected. Execution uses the verified open descriptor through `/proc/self/fd/<n>` with fixed cwd/environment, null stdin, no TTY, bounded combined output, timeout, and process-group kill. The SQLite WAL ledger uses FULL synchronous transitions. Restart revokes all grants and converts reserved/running records to `ambiguous`; it never silently reruns them.

The separately packaged Telegram renderer emits bounded inert JSON text. It does not hold requester credentials and cannot alter the approved request.

## Development

```sh
python -m pip install -e .
python -m pytest -v
python -m hermes_privilege_broker.cli plan
```

No test invokes sudo or installs files. See `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/INSTALL.md`, and `docs/TEST_EVIDENCE.md`.

## Donors and licenses

This implementation is original Apache-2.0 code informed by public architecture, not copied donor source. Primary architectural donor: [unYOLO sudo broker](https://github.com/osolmaz/unyolo/tree/38f17426354cef7ba8bb8a66b867346c5b400145/brokers/sudo) (MIT). Additional concepts: [daemonsudo](https://github.com/daemonsudo/daemonsudo/tree/38b18550998d804439a93f9a501670a2cf3b4a31), [sudo](https://github.com/sudo-project/sudo/tree/2e18923c2e959fff57b60207a261080daa2ebee9), and [polkit](https://github.com/polkit-org/polkit/tree/6f3cec7f1cfd2b0a686ce53e97e5351c80fe4f32). Consult each linked repository for its license; no source from them is vendored here.
