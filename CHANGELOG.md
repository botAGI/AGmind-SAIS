# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

M1 — the single dedicated host milestone. The vertical slice
`signed evidence → deterministic correlation → OPA admission → durable intent →
local interactive approval → exact container netns → nftables deny with native
TTL → signed action journal → Core mirror / offline proof` is implemented and
the full test suite is green in CI.

**A `v0.1.0` release is gated on native acceptance** — a
`scripts/verify-linux-integration.sh` run producing a `"status":"PASS"` report
on a dedicated lab host. Until that report exists the project is not
production-ready and no version is tagged.

### Added
- Continuous integration (`.github/workflows/ci.yml`): the project's `make`
  gates — contracts, observer, sensor, build, the privileged-boundary tests,
  and shellcheck — run on every push and pull request.
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`.
- Architecture decision records under `docs/adr/` capturing the M1 design.
- Bilingual README (`README.md` English, `README.ru.md` Russian).

### Changed
- The model-host interface is named `hunter` throughout: the installer flags
  `--hunter-url` / `--hunter-token-file`, the `AGMIND_HUNTER_*` environment
  variables, and `deploy/config/hunter-relay.cfg`.
- The native acceptance runbook and its report schema are named
  `native-acceptance` (`agmind.native-acceptance.v1`).
- README boundary descriptions corrected against the code: OPA validates
  candidate shape and TTL bounds only; forbidden destinations and docker
  networks are enforced by Core correlation and re-checked by the actuator.

### Fixed
- Key rotation no longer leaves a freshly installed observer read-only: the
  genesis rotation boundary the archive itself routes is now admitted.
- A malformed ack from Core no longer permanently fences the observer; the
  observer verifies its own state first, then rejects the mismatched claim.
- Staged replay commit transfers descriptor ownership before closing, removing
  a double-close / descriptor-reuse hazard.
- The V1→V2 durable projection upgrade reads the held descriptor directly
  instead of a `/dev/fd` path that modern SQLite canonicalises away.
- Durable-file removal pins the target inode instead of trusting a
  device/inode/size triple that filesystems recycle.
- The Docker reconcile reason grammar accepts the routine
  `docker_inventory_event` on both the observer and Core sides.
- Restart recovery tolerates the acked, frame-less crash leftover it later
  deletes.
- Containerised Go builds no longer fail on VCS stamping or the darwin
  cross-compile.

[Unreleased]: https://github.com/botAGI/AGmind-SAIS/commits/main
