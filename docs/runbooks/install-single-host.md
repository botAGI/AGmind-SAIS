# M1 single-host deployment

This profile runs `agmind-observerd` and `agmind-actuatord` natively on one
rootful Linux Docker host. Core, OPA, the redacting adapter, and the pinned
monitor-only Falco sensor run under Docker Compose.
It is a deployment scaffold for the Beelink lab, not native-acceptance proof.

## Fixed layout

- checkout and Compose assets: `/opt/agmind-sais`
- host binaries: `/usr/local/libexec/agmind-sais`
- trusted configuration: `/etc/agmind-sais`
- durable state: `/var/lib/agmind-sais`
- isolated Unix sockets: `/run/agmind-sais/<boundary>/socket`
- Core management API: `127.0.0.1:8787`

The Core container never receives the Docker socket, host namespaces,
`CAP_NET_ADMIN`, the actuator admin socket, or the observer private socket.
The DGX model is an untrusted read-only enrichment endpoint. Its one pinned IPv4
address must appear in both `runtime.env` and `management-destinations.json`.
Core has no external network: it can reach only a pinned, read-only HAProxy TCP
relay, and that relay has exactly one configured upstream, the DGX IPv4 on port
8000. DeepSeek therefore cannot turn model output into general Core egress.
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

## Install assets

Run from the repository checkout as root. Replace `agmindops` with the existing
local operator account.

```sh
install -d -o root -g root -m 0755 /opt/agmind-sais
cp -a . /opt/agmind-sais/

systemd-sysusers /opt/agmind-sais/deploy/sysusers.d/agmind-sais.conf
systemd-tmpfiles --create /opt/agmind-sais/deploy/tmpfiles.d/agmind-sais.conf
usermod -aG agmind-admin agmindops

install -d -o root -g root -m 0755 /usr/local/libexec/agmind-sais
go build -trimpath -o /usr/local/libexec/agmind-sais/agmind-observerd ./host/observerd/cmd/agmind-observerd
go build -trimpath -o /usr/local/libexec/agmind-sais/agmind-actuatord ./host/actuatord/cmd/agmind-actuatord
go build -trimpath -o /usr/local/bin/agmindctl ./cmd/agmindctl

install -o root -g root -m 0444 deploy/config/observer.json /etc/agmind-sais/observer.json
install -o root -g root -m 0444 deploy/config/actuator.json /etc/agmind-sais/actuator.json
install -o root -g root -m 0444 deploy/config/core.json /etc/agmind-sais/core.json
install -o root -g root -m 0444 deploy/config/hunter.json /etc/agmind-sais/hunter.json
install -o root -g root -m 0444 deploy/config/operator-denylist.json /etc/agmind-sais/operator-denylist.json
install -d -o root -g root -m 0755 /etc/falco/rules.d /usr/share/agmind-sais
install -o root -g root -m 0444 deploy/falco/rules.d/agmind-pcc.yaml /etc/falco/rules.d/agmind-pcc.yaml
install -o root -g root -m 0444 contracts/v1/ipv4-special-use.csv /usr/share/agmind-sais/ipv4-special-use.csv
```

Provision these installation-unique files before starting any unit:

```text
/var/lib/agmind-sais/identity/host-id                 root:root 0400, lowercase UUIDv4
/etc/agmind-sais/secrets/observer-ed25519.key         root:root 0400, raw Ed25519 private key (64 bytes)
/etc/agmind-sais/secrets/actuator-ed25519.key         root:root 0400, raw Ed25519 private key (64 bytes)
/etc/agmind-sais/public/actuator-ed25519.pub           root:root 0444, matching raw public key (32 bytes)
/etc/agmind-sais/observer-trust-root.json              root:root 0444, matching observer key/host ID
/etc/agmind-sais/secrets/core-api.token                root:agmind-core 0640
/etc/agmind-sais/secrets/dgx-api.token                 root:agmind-core 0640
```

Never copy fixture keys into those paths. Key generation must be local and
non-destructive: if a key already exists, stop instead of replacing it.

Resolve `dgx-spark.agmind.lan` to exactly one approved management IPv4. Write a
canonical denylist using that address; the checked-in placeholder is
intentionally invalid so the actuator fails closed until this is done.

```sh
install -o root -g root -m 0444 /dev/stdin /etc/agmind-sais/management-destinations.json <<'EOF'
{"denied_addresses":["10.0.0.50"],"denied_networks":[]}
EOF

core_uid="$(id -u agmind-core)"
core_gid="$(getent group agmind-core | cut -d: -f3)"
sensor_uid="$(id -u agmind-sensor)"
sensor_gid="$(getent group agmind-sensor | cut -d: -f3)"
install -o root -g root -m 0444 /dev/stdin /etc/agmind-sais/runtime.env <<EOF
AGMIND_CORE_UID=${core_uid}
AGMIND_CORE_GID=${core_gid}
AGMIND_SENSOR_UID=${sensor_uid}
AGMIND_SENSOR_GID=${sensor_gid}
AGMIND_CORE_IMAGE=agmind-sais-core:0.1.0
AGMIND_ADAPTER_IMAGE=agmind-sais-falco-adapter:0.1.0
AGMIND_FALCO_IMAGE=falcosecurity/falco:0.44.1@sha256:d0cfe422d6ac0e0f20857798f46c7d7273210e1b064b22821e4e6e7f843cde6b
AGMIND_OPA_IMAGE=openpolicyagent/opa:1.18.2-static@sha256:57f7d06808fff6de3ea1d698e6430990973ca1370be0e54975f0083d615521da
AGMIND_HAPROXY_IMAGE=haproxy:3.2.21-alpine3.24@sha256:66e25cc9a8332635f4e897f7f4b1e5622c25f09f0ee23cddc6ce9bdb3a24772a
AGMIND_DGX_IPV4=10.0.0.50
EOF
```

Replace `10.0.0.50` in both documents with the same verified DGX address. For a
release, replace the local Core tag with its content-digest reference.

## Build and start

```sh
docker build -f deploy/images/core.Dockerfile -t agmind-sais-core:0.1.0 .
docker build -f deploy/images/falco-adapter.Dockerfile -t agmind-sais-falco-adapter:0.1.0 .
docker pull falcosecurity/falco:0.44.1@sha256:d0cfe422d6ac0e0f20857798f46c7d7273210e1b064b22821e4e6e7f843cde6b
docker pull openpolicyagent/opa:1.18.2-static@sha256:57f7d06808fff6de3ea1d698e6430990973ca1370be0e54975f0083d615521da
docker pull haproxy:3.2.21-alpine3.24@sha256:66e25cc9a8332635f4e897f7f4b1e5622c25f09f0ee23cddc6ce9bdb3a24772a

/opt/agmind-sais/scripts/preflight-linux.sh \
  --dgx-url http://dgx-spark.agmind.lan:8000/v1 \
  --runtime-env /etc/agmind-sais/runtime.env \
  --management-denylist /etc/agmind-sais/management-destinations.json || exit 1

install -o root -g root -m 0644 deploy/systemd/*.service deploy/systemd/agmind-sais.target /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now agmind-sais.target
```

Check only the runtime boundaries and mutation readiness:

```sh
systemctl --no-pager --full status agmind-observerd agmind-actuatord agmind-core-compose
docker compose --env-file /etc/agmind-sais/runtime.env -f /opt/agmind-sais/deploy/compose/compose.yaml ps
test -S /run/agmind-sais/observer-core/socket
test -S /run/agmind-sais/observer-ingest/socket
test -S /run/agmind-sais/actuator-intent/socket
test -S /run/agmind-sais/actuator-admin/socket
curl --fail --silent http://127.0.0.1:8787/ready
```

Local approval remains host-only through `agmindctl`; Core and DeepSeek cannot
approve or apply a plan.

## Kubernetes migration boundary

The Core image already uses a read-only root filesystem, explicit config and
secret files, one PVC-shaped state directory, and no host privileges. Those map
directly to a Deployment, ConfigMaps/Secrets, and a PVC. OPA maps to a sidecar or
separate Deployment. Observer/actuator stay node-local security boundaries and
must be redesigned and natively accepted before any DaemonSet migration; this
M1 profile does not claim Kubernetes or multi-node support.
