# M1 single-host deployment

This profile runs `agmind-observerd` and `agmind-actuatord` natively on one
rootful Linux Docker host. Core, OPA, the redacting adapter, and the pinned
monitor-only Falco sensor run under Docker Compose.
It is a deployment scaffold for the dedicated lab host, not native-acceptance proof.

## Fixed layout

- checkout and Compose assets: `/opt/agmind-sais`
- host binaries: `/usr/local/libexec/agmind-sais`
- trusted configuration: `/etc/agmind-sais`
- installed runtime image-ID manifest: `/etc/agmind-sais/runtime-image-ids.json`
- durable state: `/var/lib/agmind-sais`
- isolated Unix sockets: `/run/agmind-sais/<boundary>/socket`
- Core management API: `127.0.0.1:8787`

The Core container never receives the Docker socket, host namespaces,
`CAP_NET_ADMIN`, the actuator admin socket, or the observer private socket.
The Hunter model host is an untrusted read-only enrichment endpoint. Its one
pinned IPv4 address must appear in both `runtime.env` and
`management-destinations.json`.
Core has no external network: it can reach only a pinned, read-only HAProxy TCP
relay, and that relay has exactly one configured upstream, the model-host IPv4 on
port 8000. The Hunter model therefore cannot turn its output into general Core
egress.
The current M1 observer binary is host-root because its PCC safety-pin loader
and owned-socket implementation enforce a root EUID; the unit constrains that
process and does not claim the planned post-M1 non-root privilege split.
Falco receives only host proc, tracefs, and three sanitized host identity files;
it receives neither the Docker socket nor the host `/etc` tree containing
AGmind secrets.

## Host prerequisites

Use a dedicated Linux host with systemd, cgroup v2, rootful Docker Engine,
Docker Compose v2, nftables, a readable `/sys/kernel/btf/vmlinux`, and a target
container on its own Docker bridge network namespace. Do not use Docker Desktop,
rootless Docker, a shared network namespace, or a privileged target container.
The Compose profile expects tracefs at `/sys/kernel/tracing`. If the host exposes
only `/sys/kernel/debug/tracing`, change only the source of that Falco bind mount
after validating the same filesystem.

## Install and start

Run the installer from the repository checkout as root. The operator must be an
existing login account. The Hunter model-host URL must be canonical and resolve
to exactly one safe IPv4 address. The endpoint must expose the Hunter model
under the id `dspark`; the examples below write `<model-host>` where your host
goes:

```sh
sudo ./scripts/install-linux.sh \
  --admin-user <existing-login-account> \
  --hunter-url http://<model-host>:8000/v1
```

If the Hunter endpoint requires an API token, import it from a root-owned,
single-link file with mode `0400`, `0440`, `0600`, or `0640`:

```sh
sudo ./scripts/install-linux.sh \
  --admin-user <existing-login-account> \
  --hunter-url http://<model-host>:8000/v1 \
  --hunter-token-file /root/hunter-api.token
```

The installer copies only the production source/runtime allowlist, creates the
fixed users and directories, builds the four host binaries in the pinned Go
container, builds the two Python images, pulls the pinned runtime images,
creates or validates the installation identity, writes the exact model-host denylist,
runs the read-only preflight, installs the units, and waits for `/ready`.

Re-running is an update operation: it preserves the host ID, keys, tokens, and
journals, rebuilds the runtime, and restarts the target. It never rotates an
identity implicitly. `--prepare-only` performs installation and preflight but
does not reload, enable, or start systemd units.

Start a new login session after the first install so supplementary membership
in `agmind-admin` is visible. Then inspect readiness:

```sh
systemctl --no-pager --full status \
  agmind-observerd agmind-actuatord agmind-core-compose
docker compose \
  --env-file /etc/agmind-sais/runtime.env \
  -f /opt/agmind-sais/deploy/compose/compose.yaml ps
curl --fail --silent http://127.0.0.1:8787/ready
agmindctl plans pending --json --limit 10
```

Local approval remains host-only and interactive through `agmindctl`; Core and
the Hunter model cannot approve or apply a plan.

The Core management API token is read afresh for every protected request. Rotate
it locally as root without restarting the stack:

```sh
sudo agmindctl token rotate
```

Rotation publishes a new mode-`0640` `root:agmind-core` file atomically and
prints only `/etc/agmind-sais/secrets/core-api.token` plus its SHA-256 key ID,
never the bearer value. Core receives the parent secrets directory read-only so
the rename is immediately visible; its process can traverse that directory but
cannot list it or read the root-only observer/actuator private keys.

## Native M1 acceptance

Run the single consolidated gate only on the dedicated lab test host. It wraps
the target-only TTL smoke, signed Core mirror, offline proof, authenticated API,
and real `dspark` Hunter boundary into one root-owned report. Approval still
requires typing the hash suffix shown by the real CLI.

```sh
sudo install -d -o root -g root -m 0700 /var/lib/agmind-sais/acceptance
sudo env \
  AGMIND_DEDICATED_TEST_HOST=1 \
  AGMIND_HUNTER_URL=http://<model-host>:8000/v1 \
  /opt/agmind-sais/scripts/verify-linux-integration.sh \
  --output /var/lib/agmind-sais/acceptance/run-001
```

Only `acceptance-report.json` with `"status":"PASS"` is native M1 evidence.
Darwin, Docker Desktop, OrbStack, WSL, rootless Docker, a degraded preflight, or
a non-interactive invocation cannot satisfy this gate. Full operator procedure
and artifact semantics are in `docs/runbooks/native-acceptance.md`.

## Kubernetes migration boundary

The Core image already uses a read-only root filesystem, explicit config and
secret files, one PVC-shaped state directory, and no host privileges. Those map
directly to a Deployment, ConfigMaps/Secrets, and a PVC. OPA maps to a sidecar or
separate Deployment. Observer/actuator stay node-local security boundaries and
must be redesigned and natively accepted before any DaemonSet migration; this
M1 profile does not claim Kubernetes or multi-node support.
