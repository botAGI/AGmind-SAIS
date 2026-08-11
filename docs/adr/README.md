# Architecture decision records

Decisions that shaped the M1 single-host containment layer, recorded
retroactively from internal planning notes on 2026-08-11. Each record keeps
the original design date, the rationale, the rejected alternatives where they
were recorded, and its verification state against the code on the recording
date.

| ADR | Title | Design date |
| --- | --- | --- |
| [0001](0001-proof-carrying-containment.md) | Proof-carrying containment: M1 scope and invariants | 2026-07-27 |
| [0002](0002-retain-legacy-generation.md) | Retain the legacy generation until native acceptance passes | 2026-07-27 |
| [0003](0003-correlation-proof.md) | Deterministic correlation proof | 2026-07-29 |
| [0004](0004-proof-production-and-transport.md) | Proof production and transport | 2026-07-29 |
| [0005](0005-historical-projection-authority.md) | Historical projection authority | 2026-08-01 |
| [0006](0006-trusted-linearization-boundary.md) | Trusted linearization boundary | 2026-08-03 |

A decision is changed by a new ADR that references the one it supersedes,
never by editing the old record.
