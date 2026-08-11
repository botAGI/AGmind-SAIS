# Native Beelink acceptance

This is the narrow M1 native gate for one dedicated Beelink Linux host. It
wraps the interactive target-only containment smoke, verifies the protected
Core API boundary, records an allowlisted production-topology snapshot, and
writes one canonical acceptance report. It does not install or update AGmind,
run unit/race suites, perform reboot tests, or modify the DGX host.

## Preconditions

Use a dedicated rootful Linux host with the installed M1 services active. The
host needs systemd, cgroup v2, nftables, rootful Docker, util-linux `script`, a
real TTY, and outbound TCP reachability to `1.1.1.1:443`. `AGMIND_DGX_URL` must
be the same canonical endpoint used for installation. The smoke briefly stops
and restores Core and the actuator while proving native kernel TTL expiry, and
local approval still requires typing the plan-hash suffix shown by
`agmindctl`.

Create only the parent directory. Every run must use a new child path:

```sh
sudo install -d -o root -g root -m 0700 /var/lib/agmind-sais/acceptance
sudo env \
  AGMIND_DEDICATED_TEST_HOST=1 \
  AGMIND_DGX_URL=http://<model-host>:8000/v1 \
  /opt/agmind-sais/scripts/verify-linux-integration.sh \
  --output /var/lib/agmind-sais/acceptance/run-001
```

Do not pipe or redirect the command: both stdin and stdout must remain attached
to the TTY. The wrapper refuses an existing output path, a symlinked path, or a
parent that is not root-owned and protected from group/world writes. The new
run directory is root-owned mode `0700`.

## What is checked

Before mutation, the wrapper requires the exact five production Compose
services and requires every active image ID and mutable local tag to match the
root-owned image-ID manifest written at installation. It also verifies exact
security options, namespace modes, mount tuples, ports, and complete network
sets. Every network must use the bridge driver, have the configured
internal/external boundary, and contain only the exact intended production
container IDs. Its topology artifact
contains only allowlisted service, container, image, network, kernel, boot,
Docker-version, unit-state, and host-nft digest fields; it never records
container environment, token bytes, model text, or arbitrary labels.
The before/after documents must be identical apart from their phase marker.
The nft digest retains rules, sets, and set elements while removing only
volatile counter/quota values and element expiry countdowns, so traffic cannot
create a false difference while structural firewall changes still block.
The inner smoke repeats the same full-host digest comparison while the target
deny is active, so a transient wrong-namespace mutation cannot disappear before
the final snapshot.

The Core token is opened with `O_NOFOLLOW`, checked as a stable root-owned
single-link mode-`0640` regular file, and never appears in argv, the environment,
or an artifact. The boundary check requires an unauthenticated protected GET to
return `401`, an authenticated POST to return `405`, and an authenticated GET
to return a canonical status document. Only a SHA-256 of that status body is
stored.

The interactive smoke must finish with one canonical `PASS` JSON object binding
the exact plan, action, candidate, intent, terminal `EXPIRED` record and
`kernel_timeout_observed` basis, verified proof path/digest, and a durable
hash-bound Hunter record. Durability requires an exact canonical read, a second
explicit Core restart, and an identical read from the reopened store. Hunter may
be `available/available`, or `invalid/output_invalid` when the untrusted model
returns hostile or non-schema output and the strict boundary rejects it;
transport failure, expiry, and queue exhaustion do not pass. The same result
proves secret-canary absence and records only its non-reversible SHA-256. The
wrapper requires exactly one canonical smoke-result object in the PTY
transcript, with an exact key set and strict identifier formats. The raw
transcript is deleted after validation.

## Result

Successful output contains four root-owned mode-`0600` artifacts and the final
mode-`0600` report:

```text
topology-before.json
api-boundary.json
smoke-result.json
topology-after.json
acceptance-report.json
```

`acceptance-report.json` has schema `agmind.beelink-acceptance.v1`, status
`PASS`, the complete validated smoke result, and SHA-256 hashes of the four safe
artifacts. The proof bundle remains at the exact `proof_path` recorded in the
smoke result and is independently bound by `proof_bundle_sha256`.

Any failed gate exits nonzero and, once the output directory exists, writes a
canonical `BLOCKED` report with a stable `reason_code` and hashes of any safe
artifacts completed before failure. Treat only `status="PASS"` as native M1
evidence. Preserve a blocked directory for diagnosis and choose a new output
path for the next complete run; never reuse or overwrite it.
