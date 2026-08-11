# AGmind-SAIS

**English** · [Русский](README.ru.md)

**SAIS — Self-Adaptive Immune System.** A verifiable "cyber-immunity" layer under
development for Docker hosts.

[![CI](https://github.com/botAGI/AGmind-SAIS/actions/workflows/ci.yml/badge.svg)](https://github.com/botAGI/AGmind-SAIS/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

AGmind-SAIS collects signed security events, decides through a deterministic
policy, requires an interactive local operator approval, and only then
temporarily isolates the exact network namespace of one container.

This is not another LLM firewall: the model is given no authority to change the
system. The Hunter is a locally hosted, uncensored model on operator hardware,
used only as an untrusted, read-only layer — for hypotheses and explanations on
top of already-recorded facts.

> **M1** is the project's first phase: a single dedicated Docker host.

## The core M1 invariant

```text
signed evidence
  -> deterministic correlation
  -> OPA admission
  -> durable intent
  -> local interactive approval
  -> exact container netns
  -> nftables deny with native TTL
  -> signed action journal
  -> Core mirror / offline proof
```

Neither the model, nor Core, nor the HTTP API can approve a plan or call `nft`
directly. The privileged actuator acts only over a local Unix socket, only for
the `root` user or the `agmind-admin` group. The blocking set element carries a
kernel timeout and disappears without any control-plane involvement; the
supporting table, chain, and drop rule stay in the container netns (inert while
empty) until the netns itself is removed.

## Single-host architecture

- `agmind-observerd` — host sensor, Docker inventory, and signed events.
- Falco + redacting adapter — monitor-only detection: Falco itself remains a
  privileged syscall sensor on an isolated internal network, while the adapter
  is unprivileged and redacts events before they leave the sensor enclave;
  AGmind secrets never reach the detection channel.
- Core — evidence, correlation, OPA, durable intents, a verifiable mirror of
  actions, and an authenticated read-only API; with no Docker socket and no
  `CAP_NET_ADMIN`.
- OPA — the policy admission gate: it validates the candidate's shape and TTL
  bounds and returns only `manual_approval_required` or `deny`; it cannot form
  an execution command. Forbidden destinations and docker networks are checked
  by Core's deterministic correlation, and every hard limit — TTL, forbidden
  destinations, docker networks — is independently re-checked by the actuator
  (`host/actuatord/limits.go`), so the boundary stays fail-closed even if the
  policy is swapped.
- Hunter — an isolated request to the local model through a fixed relay; its
  result never enters policy, intent, or approval.
- `agmind-actuatord` — a minimal root boundary that re-verifies the container's
  identity and applies a targeted `nftables` timeout inside its netns.
- `agmindctl` — host-only inspection and interactive approve/reject.

## Current status

M1 targets a single dedicated Linux Docker host. The working vertical slice
evidence → policy → intent → local approval → target-only TTL is already
implemented, together with a hardened Compose/systemd installer, a verifiable
Core actuator mirror, an authenticated read-only API, a persistent manual kill
switch, and quiesced proof export with offline replay. The one open release gate
is native acceptance on a dedicated lab host. Until it passes, the project is
**not** production-ready.

Kubernetes, multi-node coordination, and a DaemonSet actuator belong to the next
phase. M1 deliberately preserves boundaries that can be carried over: Core/OPA as
ordinary unprivileged workloads, observer/actuator as a node-local layer.

## Installing M1

You need a dedicated Linux host with systemd, a rootful Docker Engine, Compose
v2, cgroup v2, and nftables. macOS, Docker Desktop, rootless Docker, WSL, and a
shared production host are not valid acceptance environments.

```sh
sudo ./scripts/install-linux.sh \
  --admin-user <existing-local-user> \
  --hunter-url http://<model-host>:8000/v1
```

Full prerequisites, fixed paths, and safe updates are described in
[`docs/runbooks/install-single-host.md`](docs/runbooks/install-single-host.md).

## Manual kill switch

```sh
agmindctl kill-switch status --json
agmindctl kill-switch enable
agmindctl kill-switch disable
```

`enable` and `disable` require an exact interactive confirmation. Turning off the
manual mode does not lift the actuator's automatic fail-closed blocks.

`agmindctl` commands are available only to `root` or a member of the
`agmind-admin` group, and after install that group membership is active only in
a new login session.

## Core API token rotation

```sh
sudo agmindctl token rotate
```

The command atomically replaces the root-owned token and prints only its fixed
path and SHA-256 key ID. The old bearer stops being accepted without restarting
Core; the token itself is never printed to the terminal.

## Native verification

A single consolidated gate creates separate target/control containers, requires
a real local approval, and ties the target-only TTL, the signed `EXPIRED`, the
offline proof, and the actual read-only response of the Hunter model (the
endpoint must serve a model with id `dspark`) into one report:

```sh
sudo install -d -o root -g root -m 0700 /var/lib/agmind-sais/acceptance
sudo env \
  AGMIND_DEDICATED_TEST_HOST=1 \
  AGMIND_HUNTER_URL=http://<model-host>:8000/v1 \
  /opt/agmind-sais/scripts/verify-linux-integration.sh \
  --output /var/lib/agmind-sais/acceptance/run-001
```

Only the final report with `"status":"PASS"` counts as native M1 evidence. See
[`docs/runbooks/native-acceptance.md`](docs/runbooks/native-acceptance.md).

## Action proof export

```sh
sudo /opt/agmind-sais/scripts/export-proof-linux.sh \
  --action-id act_<32-hex action id from the signed action journal> \
  --output /var/lib/agmind-sais/exports/act_<same-id>
```

The export briefly quiesces the AGmind services for a consistent snapshot, then
performs offline verification and restores the previously active units. The full
procedure is in [`docs/runbooks/proof-export.md`](docs/runbooks/proof-export.md).

## What the project deliberately does not do

- it does not execute text, commands, or tool calls from the LLM;
- it does not block an address on a single model confidence score;
- it does not grant Core or the web API approve/apply rights;
- it does not use `--network host` for Core;
- it does not promise to replace a perimeter/WAF firewall in every scenario;
- it does not claim Kubernetes/multi-server readiness before a separate threat
  model and native acceptance.

## Security & contributing

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). Development
rules and the review checklist are in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE). Using defensive actions in real infrastructure
remains the operator's responsibility.
