# ADR 0002: Retain the legacy generation until native acceptance passes

- Status: accepted
- Date: 2026-07-27 (recorded retroactively on 2026-08-11)

## Context

Two generations coexist in this repository by design. The legacy Python
prototype — `app/`, the root `main.py`, `config/config.yaml`, the root
`requirements.txt`, and the root `Dockerfile` — predates the proof-carrying
architecture described in [ADR 0001](0001-proof-carrying-containment.md).
While the new privileged path was unproven on real hardware, the prototype was
the only working reference implementation.

## Decision

The legacy files stay untouched until native Linux acceptance
(`scripts/verify-linux-integration.sh` producing a `"status":"PASS"` report on
the dedicated lab host) passes. Specifically:

- The prototype is **not** extended into the privileged architecture; it is
  reference material only. New features never land in the legacy tree.
- The tree is not moved into a `legacy/` directory and not deleted; migration
  or removal is its own explicitly approved decision, recorded as a
  superseding ADR — never a side effect of another change.
- Documentation must label `app/` as legacy and must not claim it participates
  in M1.

## Rejected alternatives

- **Extending the prototype into the privileged architecture** — rejected: it
  would carry the prototype's confidence-driven automation and unauthenticated
  surface into a path whose whole point is deterministic, human-approved
  containment.
- **Immediate migration/removal** — rejected as premature while the
  replacement had never passed acceptance on real Linux; deleting the only
  working reference implementation would destroy the fallback.

## Consequences

- Legacy and native generations coexist at the repo root; tooling must
  tolerate both.
- The legacy sensor serves an unauthenticated REST/WebSocket surface, and a
  plain `docker build .` at the repo root still produces it. Because this ADR
  forbids deletion, that risk was defused by gating instead: since commit
  `ccfd70a` the legacy sensor refuses to start unless `AGMIND_LEGACY_SENSOR=1`
  is set (it logs why and exits 2). The image stays buildable for
  `make test-core-detector-pin-image`.
- No shipped deployment starts the legacy sensor: the installer copies an
  explicit allowlist that excludes `app/` and `main.py`, and the compose stack
  runs `deploy/images/core.Dockerfile`.

## Supersession condition

After a native acceptance run has produced a `"status":"PASS"` report, removal
of the legacy generation may be proposed as a new ADR that references this one.
