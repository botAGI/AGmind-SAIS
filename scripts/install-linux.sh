#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly install_root="/opt/agmind-sais"
readonly libexec_root="/usr/local/libexec/agmind-sais"
readonly config_root="/etc/agmind-sais"
readonly secrets_root="/etc/agmind-sais/secrets"
readonly public_root="/etc/agmind-sais/public"
readonly state_root="/var/lib/agmind-sais"
readonly runtime_root="/run/agmind-sais"
readonly share_root="/usr/share/agmind-sais"
readonly docker_endpoint="unix:///var/run/docker.sock"
readonly core_image="agmind-sais-core:0.1.0"
readonly adapter_image="agmind-sais-falco-adapter:0.1.0"

usage() {
  cat <<'EOF'
Usage:
  install-linux.sh --admin-user EXISTING --dgx-url http://host:8000/v1 [options]

Required:
  --admin-user USER       Existing local operator account to add to agmind-admin
  --dgx-url URL           Exact HTTP endpoint; must resolve to one safe IPv4

Options:
  --dgx-token-file PATH   Import a protected, root-owned DGX API token
  --prepare-only          Install and preflight, but do not reload/start systemd
  -h, --help              Show this help and exit without changing the host
EOF
}

die() {
  printf 'install-linux.sh: %s\n' "$*" >&2
  exit 1
}

status() {
  printf '[agmind-sais] %s\n' "$*"
}

admin_user=""
dgx_url=""
dgx_token_file=""
prepare_only=0
seen_admin=0
seen_dgx_url=0
seen_dgx_token=0

while (($# > 0)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --admin-user)
      (($# >= 2)) || die "--admin-user requires a value"
      ((seen_admin == 0)) || die "--admin-user may be specified only once"
      admin_user="$2"
      seen_admin=1
      shift 2
      ;;
    --dgx-url)
      (($# >= 2)) || die "--dgx-url requires a value"
      ((seen_dgx_url == 0)) || die "--dgx-url may be specified only once"
      dgx_url="$2"
      seen_dgx_url=1
      shift 2
      ;;
    --dgx-token-file)
      (($# >= 2)) || die "--dgx-token-file requires a value"
      ((seen_dgx_token == 0)) || die "--dgx-token-file may be specified only once"
      dgx_token_file="$2"
      seen_dgx_token=1
      shift 2
      ;;
    --prepare-only)
      ((prepare_only == 0)) || die "--prepare-only may be specified only once"
      prepare_only=1
      shift
      ;;
    --)
      shift
      (($# == 0)) || die "positional arguments are not accepted"
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

((seen_admin == 1)) || die "--admin-user is required"
((seen_dgx_url == 1)) || die "--dgx-url is required"

[[ "$(uname -s)" == "Linux" ]] || die "this installer supports Linux only"
((EUID == 0)) || die "EUID 0 is required"

required_commands=(
  chmod chown dirname docker env find getent go id install mktemp mv python3 rm
  stat systemd-sysusers systemd-tmpfiles uname usermod
)
if ((prepare_only == 0)); then
  required_commands+=(curl sleep systemctl)
fi
for command_name in "${required_commands[@]}"; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command unavailable: $command_name"
done
[[ "$(command -v docker)" == "/usr/bin/docker" && -x /usr/bin/docker ]] ||
  die "systemd runtime requires the Docker CLI at executable /usr/bin/docker"

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(CDPATH= cd -- "${script_dir}/.." && pwd -P)"
versions_file="${repo_root}/deploy/versions.env"

[[ -f "$versions_file" && ! -L "$versions_file" ]] || die "deploy/versions.env is missing or unsafe"

[[ "$admin_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "--admin-user is not a safe local account name"
admin_entry="$(getent passwd "$admin_user" || true)"
[[ -n "$admin_entry" && "$admin_entry" != *$'\n'* ]] || die "--admin-user must name exactly one existing account"
IFS=: read -r account_name _ account_uid _ _ account_home account_shell <<<"$admin_entry"
[[ "$account_name" == "$admin_user" ]] || die "--admin-user did not resolve exactly"
[[ "$account_uid" =~ ^[0-9]+$ ]] && ((account_uid > 0)) || die "root/system UID is not an operator account"
[[ "$account_home" == /* && "$account_home" != "/" ]] || die "operator account has no dedicated home"
case "$account_shell" in
  */false|*/nologin) die "operator account has a non-login shell" ;;
esac

if [[ -n "$dgx_token_file" ]]; then
  [[ "$dgx_token_file" == /* ]] ||
    die "--dgx-token-file must be a clean absolute path"
  python3 - "$dgx_token_file" <<'PY' || die "--dgx-token-file must be a clean absolute path"
import os
import sys

path = sys.argv[1]
raise SystemExit(0 if os.path.normpath(path) == path else 1)
PY
  [[ -f "$dgx_token_file" && ! -L "$dgx_token_file" ]] ||
    die "DGX token source must be a regular non-symlink file"
  token_metadata="$(stat -Lc '%u:%h:%a' -- "$dgx_token_file")"
  case "$token_metadata" in
    0:1:400|0:1:440|0:1:600|0:1:640) ;;
    *) die "DGX token source must be root-owned, single-link, and mode 0400/0440/0600/0640" ;;
  esac
fi

version_value() {
  local key="$1"
  python3 - "$versions_file" "$key" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
try:
    lines = path.read_text(encoding="ascii").splitlines()
except (OSError, UnicodeError) as error:
    raise SystemExit(f"cannot read versions file: {error}")
matches = []
for line in lines:
    if not line or line.startswith("#") or "=" not in line:
        continue
    candidate, value = line.split("=", 1)
    if candidate == key:
        matches.append(value)
if len(matches) != 1:
    raise SystemExit(f"versions key {key} must occur exactly once")
value = matches[0]
if not value or value != value.strip() or not value.isascii() or re.search(r"[\x00-\x20]", value):
    raise SystemExit(f"versions key {key} is malformed")
print(value)
PY
}

go_version="$(version_value GO_VERSION)"
python_image="$(version_value PYTHON_IMAGE)"
uv_image="$(version_value UV_IMAGE)"
falco_image="$(version_value FALCO_IMAGE)"
opa_image="$(version_value OPA_IMAGE)"
haproxy_image="$(version_value HAPROXY_IMAGE)"

for pinned_image in "$python_image" "$uv_image" "$falco_image" "$opa_image" "$haproxy_image"; do
  [[ "$pinned_image" =~ @sha256:[0-9a-f]{64}$ ]] || die "versions.env contains an unpinned image reference"
done
[[ "$(GOENV=off GOWORK=off go env GOVERSION)" == "go${go_version}" ]] || die "Go ${go_version} is required"

dgx_ipv4="$(python3 - "$dgx_url" <<'PY'
from __future__ import annotations

import ipaddress
import re
import socket
import sys
from urllib.parse import urlsplit

raw = sys.argv[1]
try:
    parsed = urlsplit(raw)
    port = parsed.port
except ValueError as error:
    raise SystemExit(f"invalid --dgx-url: {error}")
host = parsed.hostname or ""
canonical = f"http://{host}:{port}/v1" if host and port is not None else ""
if (
    raw != canonical
    or len(raw) > 2048
    or not raw.isascii()
    or parsed.scheme != "http"
    or port != 8000
    or parsed.username is not None
    or parsed.password is not None
    or parsed.path != "/v1"
    or parsed.query
    or parsed.fragment
    or len(host) > 253
    or not re.fullmatch(r"[a-z0-9.-]+", host)
):
    raise SystemExit("--dgx-url must be canonical http://host:8000/v1")
try:
    ipaddress.IPv4Address(host)
except ipaddress.AddressValueError:
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or label[0] == "-"
        or label[-1] == "-"
        for label in labels
    ):
        raise SystemExit("--dgx-url contains an invalid DNS name")

resolved: set[ipaddress._BaseAddress] = set()
try:
    for item in socket.getaddrinfo(
        host,
        port,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    ):
        resolved.add(ipaddress.ip_address(item[4][0]))
except (OSError, ValueError) as error:
    raise SystemExit(f"DGX resolution failed: {error}")
if len(resolved) != 1:
    raise SystemExit("DGX endpoint must resolve to exactly one address")
address = next(iter(resolved))
if not isinstance(address, ipaddress.IPv4Address):
    raise SystemExit("DGX endpoint must resolve only to IPv4")
if (
    address.is_loopback
    or address.is_link_local
    or address.is_multicast
    or address.is_unspecified
    or address.is_reserved
):
    raise SystemExit("DGX endpoint resolved to an unsafe IPv4 address")
print(address)
PY
)"
[[ "$dgx_ipv4" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "DGX resolution returned a malformed IPv4"

work_dir=""
cleanup() {
  if [[ -n "$work_dir" ]]; then
    case "$work_dir" in
      /var/tmp/agmind-sais-install.*)
        [[ -d "$work_dir" && ! -L "$work_dir" ]] && rm -rf -- "$work_dir"
        ;;
    esac
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
work_dir="$(mktemp -d /var/tmp/agmind-sais-install.XXXXXXXX)"
chmod 0700 "$work_dir"

ensure_directory() {
  local path="$1"
  local mode="$2"
  local owner="$3"
  local group="$4"
  [[ ! -L "$path" ]] || die "refusing symlink directory: $path"
  [[ ! -e "$path" || -d "$path" ]] || die "required directory path is occupied: $path"
  install -d -o "$owner" -g "$group" -m "$mode" -- "$path"
}

atomic_install_file() {
  local source="$1"
  local destination="$2"
  local mode="$3"
  local owner="$4"
  local group="$5"
  local destination_dir directory_metadata directory_uid directory_mode temporary
  [[ -f "$source" && ! -L "$source" ]] || die "source is missing or unsafe: $source"
  destination_dir="$(dirname -- "$destination")"
  [[ -d "$destination_dir" && ! -L "$destination_dir" ]] ||
    die "destination directory is missing or unsafe: $destination_dir"
  directory_metadata="$(stat -Lc '%u:%a' -- "$destination_dir")"
  directory_uid="${directory_metadata%%:*}"
  directory_mode="${directory_metadata#*:}"
  [[ "$directory_uid" == "0" && "$directory_mode" =~ ^[0-7]{3,4}$ ]] ||
    die "destination directory is not root-owned: $destination_dir"
  (((8#$directory_mode & 8#022) == 0)) ||
    die "destination directory is group/world writable: $destination_dir"
  temporary="$(mktemp "${destination_dir}/.agmind-install.XXXXXXXX")"
  if ! install -o "$owner" -g "$group" -m "$mode" -- "$source" "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! mv -fT -- "$temporary" "$destination"; then
    rm -f -- "$temporary"
    return 1
  fi
}

copy_file() {
  local relative="$1"
  local source="${repo_root}/${relative}"
  local destination="${install_root}/${relative}"
  local mode="0644"
  [[ -x "$source" ]] && mode="0755"
  ensure_directory "$(dirname -- "$destination")" 0755 root root
  atomic_install_file "$source" "$destination" "$mode" root root
}

copy_tree() {
  local relative_root="$1"
  local source_root="${repo_root}/${relative_root}"
  local source relative destination mode
  [[ -d "$source_root" && ! -L "$source_root" ]] || die "source tree is missing or unsafe: $relative_root"
  while IFS= read -r -d '' source; do
    relative="${source#"${repo_root}/"}"
    case "/${relative}/" in
      */.git/*|*/tests/*|*/testdata/*|*/__pycache__/*|*/.mypy_cache/*|*/.pytest_cache/*|*/.ruff_cache/*|*/.hypothesis/*|*/.venv/*)
        continue
        ;;
    esac
    case "${source##*/}" in
      *_test.go|test_*.py|*_test.py|*.pyc|*.pyo|.DS_Store)
        continue
        ;;
    esac
    destination="${install_root}/${relative}"
    mode="0644"
    [[ -x "$source" ]] && mode="0755"
    ensure_directory "$(dirname -- "$destination")" 0755 root root
    atomic_install_file "$source" "$destination" "$mode" root root
  done < <(find "$source_root" -type f -print0)
}

status "installing a minimal, test-free source and runtime tree"
ensure_directory "$install_root" 0755 root root
if [[ "$repo_root" != "$install_root" ]]; then
  for relative_file in .dockerignore go.mod go.sum pyproject.toml uv.lock policies/pcc.rego; do
    copy_file "$relative_file"
  done
  for relative_tree in \
    cmd host internal core/agmind_immune contracts/v1 contracts/v2 deploy docs/runbooks; do
    copy_tree "$relative_tree"
  done
  copy_file scripts/preflight-linux.sh
  copy_file scripts/install-linux.sh
fi

for required_source in \
  cmd/agmind-bootstrap/main.go \
  cmd/agmindctl/main.go \
  host/observerd/cmd/agmind-observerd/main.go \
  host/actuatord/cmd/agmind-actuatord/main.go \
  deploy/images/core.Dockerfile \
  deploy/images/falco-adapter.Dockerfile \
  scripts/preflight-linux.sh; do
  [[ -f "${install_root}/${required_source}" && ! -L "${install_root}/${required_source}" ]] ||
    die "installed build tree is incomplete: $required_source"
done

status "creating fixed system identities and directories"
ensure_directory /etc/sysusers.d 0755 root root
ensure_directory /etc/tmpfiles.d 0755 root root
atomic_install_file \
  "${install_root}/deploy/sysusers.d/agmind-sais.conf" \
  /etc/sysusers.d/agmind-sais.conf 0644 root root
atomic_install_file \
  "${install_root}/deploy/tmpfiles.d/agmind-sais.conf" \
  /etc/tmpfiles.d/agmind-sais.conf 0644 root root
systemd-sysusers /etc/sysusers.d/agmind-sais.conf
systemd-tmpfiles --create /etc/tmpfiles.d/agmind-sais.conf

core_uid="$(id -u agmind-core)"
core_gid="$(id -g agmind-core)"
sensor_uid="$(id -u agmind-sensor)"
sensor_gid="$(id -g agmind-sensor)"
admin_group_entry="$(getent group agmind-admin || true)"
[[ -n "$admin_group_entry" && "$admin_group_entry" != *$'\n'* ]] ||
  die "agmind-admin group allocation failed"
IFS=: read -r admin_group_name _ admin_gid _ <<<"$admin_group_entry"
[[ "$admin_group_name" == "agmind-admin" ]] || die "agmind-admin group did not resolve exactly"
for numeric_identity in "$core_uid" "$core_gid" "$sensor_uid" "$sensor_gid" "$admin_gid"; do
  [[ "$numeric_identity" =~ ^[0-9]+$ ]] && ((numeric_identity > 0)) || die "system identity allocation failed"
done
((core_gid != admin_gid)) || die "agmind-core and agmind-admin must have distinct GIDs"
((core_gid != sensor_gid && sensor_gid != admin_gid)) ||
  die "Core, sensor, and admin groups must have distinct GIDs"
((core_uid != sensor_uid)) || die "Core and sensor users must have distinct UIDs"

ensure_directory "$config_root" 0755 root root
ensure_directory "$secrets_root" 0700 root root
ensure_directory "$public_root" 0755 root root
ensure_directory "$state_root" 0755 root root
ensure_directory "${state_root}/identity" 0700 root root
ensure_directory "${state_root}/observer" 0700 root root
ensure_directory "${state_root}/actuator" 0700 root root
ensure_directory "${state_root}/core" 0700 agmind-core agmind-core
ensure_directory "$runtime_root" 0755 root root
ensure_directory "${runtime_root}/docker-config" 0700 root root
ensure_directory "${runtime_root}/observer-ingest" 0750 root agmind-sensor
ensure_directory "${runtime_root}/observer-core" 0750 root agmind-core
ensure_directory "${runtime_root}/observer-actuator" 0750 root root
ensure_directory "${runtime_root}/actuator-intent" 0750 root agmind-core
ensure_directory "${runtime_root}/actuator-admin" 0750 root agmind-admin
ensure_directory "$share_root" 0755 root root
ensure_directory /etc/falco 0755 root root
ensure_directory /etc/falco/rules.d 0755 root root
ensure_directory "$libexec_root" 0755 root root

status "building and atomically installing four Go executables"
build_go_binary() {
  local package="$1"
  local output_name="$2"
  (
    cd "$install_root"
    env CGO_ENABLED=0 GOENV=off GOWORK=off \
      go build -mod=readonly -buildvcs=false -trimpath \
      -o "${work_dir}/${output_name}" "$package"
  )
}
build_go_binary ./host/observerd/cmd/agmind-observerd agmind-observerd
build_go_binary ./host/actuatord/cmd/agmind-actuatord agmind-actuatord
build_go_binary ./cmd/agmindctl agmindctl
build_go_binary ./cmd/agmind-bootstrap agmind-bootstrap
atomic_install_file "${work_dir}/agmind-observerd" "${libexec_root}/agmind-observerd" 0755 root root
atomic_install_file "${work_dir}/agmind-actuatord" "${libexec_root}/agmind-actuatord" 0755 root root
atomic_install_file "${work_dir}/agmind-bootstrap" "${libexec_root}/agmind-bootstrap" 0755 root root
atomic_install_file "${work_dir}/agmindctl" /usr/local/bin/agmindctl 0755 root root

status "installing immutable configs, detector rule, policy, and registry"
for config_name in observer actuator core hunter operator-denylist; do
  atomic_install_file \
    "${install_root}/deploy/config/${config_name}.json" \
    "${config_root}/${config_name}.json" 0444 root root
done
atomic_install_file \
  "${install_root}/deploy/falco/falco.yaml" \
  /etc/falco/falco.yaml 0444 root root
atomic_install_file \
  "${install_root}/deploy/falco/rules.d/agmind-pcc.yaml" \
  /etc/falco/rules.d/agmind-pcc.yaml 0444 root root
atomic_install_file \
  "${install_root}/contracts/v1/ipv4-special-use.csv" \
  "${share_root}/ipv4-special-use.csv" 0444 root root
atomic_install_file \
  "${install_root}/policies/pcc.rego" \
  "${share_root}/pcc.rego" 0444 root root

printf '{"denied_addresses":["%s"],"denied_networks":[]}\n' "$dgx_ipv4" >"${work_dir}/management-destinations.json"
atomic_install_file \
  "${work_dir}/management-destinations.json" \
  "${config_root}/management-destinations.json" 0444 root root

printf '%s\n' \
  "AGMIND_CORE_UID=${core_uid}" \
  "AGMIND_CORE_GID=${core_gid}" \
  "AGMIND_SENSOR_UID=${sensor_uid}" \
  "AGMIND_SENSOR_GID=${sensor_gid}" \
  "AGMIND_CORE_IMAGE=${core_image}" \
  "AGMIND_ADAPTER_IMAGE=${adapter_image}" \
  "AGMIND_FALCO_IMAGE=${falco_image}" \
  "AGMIND_OPA_IMAGE=${opa_image}" \
  "AGMIND_HAPROXY_IMAGE=${haproxy_image}" \
  "AGMIND_DGX_IPV4=${dgx_ipv4}" >"${work_dir}/runtime.env"
atomic_install_file "${work_dir}/runtime.env" "${config_root}/runtime.env" 0444 root root

status "initializing or validating the existing installation identity"
bootstrap_arguments=(init)
if [[ -n "$dgx_token_file" ]]; then
  bootstrap_arguments+=(--dgx-token-file "$dgx_token_file")
fi
"${libexec_root}/agmind-bootstrap" "${bootstrap_arguments[@]}" >/dev/null

secure_artifact() {
  local path="$1"
  local mode="$2"
  local owner="$3"
  local group="$4"
  [[ -f "$path" && ! -L "$path" ]] || die "bootstrap artifact is missing or unsafe: $path"
  [[ "$(stat -Lc '%h' -- "$path")" == "1" ]] || die "bootstrap artifact has multiple links: $path"
  chown "$owner:$group" -- "$path"
  chmod "$mode" -- "$path"
}
secure_artifact "${state_root}/identity/host-id" 0400 root root
secure_artifact "${secrets_root}/observer-ed25519.key" 0400 root root
secure_artifact "${secrets_root}/actuator-ed25519.key" 0400 root root
secure_artifact "${public_root}/actuator-ed25519.pub" 0444 root root
secure_artifact "${config_root}/observer-trust-root.json" 0444 root root
secure_artifact "${secrets_root}/core-api.token" 0640 root agmind-core
secure_artifact "${secrets_root}/dgx-api.token" 0640 root agmind-core

usermod -a -G agmind-admin "$admin_user"

docker_rootful() {
  DOCKER_CONFIG="${runtime_root}/docker-config" docker --host "$docker_endpoint" "$@"
}

status "pulling pinned runtime images"
docker_rootful pull "$falco_image"
docker_rootful pull "$opa_image"
docker_rootful pull "$haproxy_image"

status "building the Core and Falco-adapter images"
docker_rootful build \
  --build-arg "PYTHON_IMAGE=${python_image}" \
  --build-arg "UV_IMAGE=${uv_image}" \
  --file "${install_root}/deploy/images/core.Dockerfile" \
  --tag "$core_image" \
  "$install_root"
docker_rootful build \
  --build-arg "PYTHON_IMAGE=${python_image}" \
  --build-arg "UV_IMAGE=${uv_image}" \
  --file "${install_root}/deploy/images/falco-adapter.Dockerfile" \
  --tag "$adapter_image" \
  "$install_root"

status "running the full read-only host and DGX preflight"
DOCKER_CONFIG="${runtime_root}/docker-config" \
  "${install_root}/scripts/preflight-linux.sh" \
  --dgx-url "$dgx_url" \
  --runtime-env "${config_root}/runtime.env" \
  --management-denylist "${config_root}/management-destinations.json"

status "installing systemd units"
for unit_name in \
  agmind-observerd.service \
  agmind-actuatord.service \
  agmind-core-compose.service \
  agmind-sais.target; do
  atomic_install_file \
    "${install_root}/deploy/systemd/${unit_name}" \
    "/etc/systemd/system/${unit_name}" 0644 root root
done

if ((prepare_only == 1)); then
  status "prepare-only complete; no units were reloaded, enabled, or started"
  status "the operator must start a new login session before using agmindctl"
  exit 0
fi

status "enabling the single-host runtime"
systemctl daemon-reload
systemctl enable agmind-sais.target
systemctl restart agmind-sais.target

status "waiting up to 120 seconds for Core mutation readiness"
ready=0
ready_deadline=$((SECONDS + 120))
while ((SECONDS < ready_deadline)); do
  if curl --fail --silent --show-error --noproxy '*' --max-time 2 \
    http://127.0.0.1:8787/ready >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ((SECONDS < ready_deadline)); then
    sleep 1
  fi
done
((ready == 1)) || die "Core did not reach /ready within 120 seconds"

status "installation ready; start a new operator login session before using agmindctl"
