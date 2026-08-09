#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C LANG=C
unset BASH_ENV CDPATH ENV PYTHONHOME PYTHONPATH

output=""
output_ready=0
transcript=""
readonly schema="agmind.beelink-acceptance.v1"
readonly docker_config="/run/agmind-sais/docker-config"
readonly proof_root="/var/lib/agmind-sais/exports"

write_report() {
  local status="$1" reason="$2"
  python3 - "${output}" "${status}" "${reason}" <<'PY'
import hashlib, json, os, re, stat, sys
root, status, reason = sys.argv[1:]
if status not in {"PASS", "BLOCKED"} or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason) is None:
    raise SystemExit(1)
root_info = os.lstat(root)
if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700:
    raise SystemExit(1)
artifacts = {}
for name in ("topology-before.json", "api-boundary.json", "smoke-result.json", "topology-after.json"):
    path = os.path.join(root, name)
    if not os.path.exists(path):
        continue
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise SystemExit(1)
    raw = open(path, "rb").read(1024 * 1024 + 1)
    if len(raw) != info.st_size or len(raw) > 1024 * 1024:
        raise SystemExit(1)
    artifacts[name] = hashlib.sha256(raw).hexdigest()
document = {"artifact_sha256": artifacts, "reason_code": reason,
            "schema_version": "agmind.beelink-acceptance.v1", "status": status}
if status == "PASS":
    if len(artifacts) != 4:
        raise SystemExit(1)
    document["smoke_result"] = json.loads(open(os.path.join(root, "smoke-result.json"), "rb").read())
raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
path = os.path.join(root, "acceptance-report.json")
temporary = os.path.join(root, ".acceptance-report.tmp")
with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600), "wb") as sink:
    sink.write(raw); sink.flush(); os.fsync(sink.fileno())
os.replace(temporary, path)
PY
}

block() {
  local reason="$1" code="${2:-78}"
  local blocked_written=0
  trap - ERR INT TERM HUP
  set +e
  [[ -z "${transcript}" ]] || rm -f -- "${transcript}"
  if ((output_ready == 1)); then
    rm -f -- "${output}/.acceptance-report.tmp" "${output}/topology-before.json.tmp" \
      "${output}/api-boundary.json.tmp" "${output}/smoke-result.json.tmp" "${output}/topology-after.json.tmp"
  fi
  if ((output_ready == 1)); then
    if write_report BLOCKED "${reason}" >/dev/null 2>&1; then
      blocked_written=1
    else
      rm -f -- "${output}/acceptance-report.json"
    fi
  fi
  if ((blocked_written == 1)); then
    cat -- "${output}/acceptance-report.json" >&2
  else
    printf '{"reason_code":"%s","schema_version":"%s","status":"BLOCKED"}\n' "${reason}" "${schema}" >&2
  fi
  exit "${code}"
}

snapshot_topology() {
  local phase="$1" target="$2"
  DOCKER_CONFIG="${docker_config}" python3 - "${phase}" "${target}" <<'PY'
import hashlib, ipaddress, json, os, re, stat, subprocess, sys
phase, target = sys.argv[1:]
env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
       "LC_ALL": "C", "DOCKER_CONFIG": "/run/agmind-sais/docker-config"}
def run(argv, maximum=4 * 1024 * 1024):
    result = subprocess.run(argv, env=env, capture_output=True, timeout=8, check=False)
    if result.returncode or len(result.stdout) > maximum:
        raise SystemExit(1)
    return result.stdout.decode("utf-8", "strict").strip()
def exact_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value
units = ["docker.service", "agmind-sais.target", "agmind-observerd.service",
         "agmind-actuatord.service", "agmind-core-compose.service"]
for unit in units:
    if run(["/usr/bin/systemctl", "is-active", unit], 64) != "active":
        raise SystemExit(1)
docker = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
docker_version = run(docker + ["version", "--format", "{{.Server.Version}}"], 128)
runtime_path = "/etc/agmind-sais/runtime.env"
runtime_info = os.lstat(runtime_path)
if (not stat.S_ISREG(runtime_info.st_mode) or runtime_info.st_uid != 0 or runtime_info.st_gid != 0 or stat.S_IMODE(runtime_info.st_mode) != 0o444 or
    runtime_info.st_nlink != 1 or runtime_info.st_size > 1024 * 1024):
    raise SystemExit(1)
runtime_raw = open(runtime_path, "rb").read(1024 * 1024 + 1)
runtime_after = os.lstat(runtime_path)
if len(runtime_raw) != runtime_info.st_size or (runtime_info.st_dev, runtime_info.st_ino, runtime_info.st_mtime_ns) != (runtime_after.st_dev, runtime_after.st_ino, runtime_after.st_mtime_ns):
    raise SystemExit(1)
runtime_lines = [line for line in runtime_raw.decode("ascii", "strict").splitlines() if line and not line.startswith("#")]
if any(line.count("=") != 1 for line in runtime_lines):
    raise SystemExit(1)
runtime_pairs = [line.split("=", 1) for line in runtime_lines]
if any(re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None or not value or value != value.strip() or
       not value.isascii() or any(ord(c) < 0x20 for c in value) for key, value in runtime_pairs):
    raise SystemExit(1)
runtime_values = dict(runtime_pairs)
if len(runtime_values) != len(runtime_pairs):
    raise SystemExit(1)
dgx_ipv4 = runtime_values.get("AGMIND_DGX_IPV4", "")
try:
    if str(ipaddress.IPv4Address(dgx_ipv4)) != dgx_ipv4:
        raise ValueError
except ValueError:
    raise SystemExit(1)
image_keys = {
    "core": "AGMIND_CORE_IMAGE",
    "dgx-relay": "AGMIND_HAPROXY_IMAGE",
    "falco": "AGMIND_FALCO_IMAGE",
    "falco-adapter": "AGMIND_ADAPTER_IMAGE",
    "opa": "AGMIND_OPA_IMAGE",
}
manifest_path = "/etc/agmind-sais/runtime-image-ids.json"
manifest_fd = os.open(manifest_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    manifest_before = os.fstat(manifest_fd)
    if (
        not stat.S_ISREG(manifest_before.st_mode)
        or manifest_before.st_uid != 0
        or manifest_before.st_gid != 0
        or stat.S_IMODE(manifest_before.st_mode) != 0o444
        or manifest_before.st_nlink != 1
        or not 1 <= manifest_before.st_size <= 4096
    ):
        raise SystemExit(1)
    manifest_raw = os.read(manifest_fd, 4097)
    manifest_after = os.fstat(manifest_fd)
    manifest_named = os.stat(manifest_path, follow_symlinks=False)
finally:
    os.close(manifest_fd)
manifest_stable = lambda value: (
    value.st_dev,
    value.st_ino,
    value.st_size,
    value.st_mtime_ns,
    value.st_ctime_ns,
    value.st_mode,
    value.st_uid,
    value.st_gid,
    value.st_nlink,
)
if (
    len(manifest_raw) != manifest_before.st_size
    or manifest_stable(manifest_before) != manifest_stable(manifest_after)
    or (manifest_after.st_dev, manifest_after.st_ino) != (manifest_named.st_dev, manifest_named.st_ino)
):
    raise SystemExit(1)
try:
    manifest = json.loads(manifest_raw, object_pairs_hook=exact_object)
except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
expected_image_ids = manifest.get("services") if isinstance(manifest, dict) else None
manifest_canonical = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
if (
    not isinstance(manifest, dict)
    or set(manifest) != {"schema_version", "services"}
    or manifest.get("schema_version") != "agmind.runtime-image-ids.v1"
    or not isinstance(expected_image_ids, dict)
    or set(expected_image_ids) != set(image_keys)
    or any(re.fullmatch(r"sha256:[0-9a-f]{64}", str(value)) is None for value in expected_image_ids.values())
    or manifest_raw != manifest_canonical
):
    raise SystemExit(1)
runtime_image_manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
image_refs = {}
for service, key in image_keys.items():
    reference = runtime_values.get(key, "")
    if (
        not 1 <= len(reference) <= 512
        or not reference.isascii()
        or reference.startswith("-")
        or any(character.isspace() or ord(character) < 0x21 for character in reference)
    ):
        raise SystemExit(1)
    image_id = run(docker + ["image", "inspect", "--format", "{{.Id}}", "--", reference], 128)
    if image_id != expected_image_ids[service]:
        raise SystemExit(1)
    image_refs[service] = reference
ids = run(docker + ["container", "ls", "--filter", "label=com.docker.compose.project=agmind-sais",
                    "--format", "{{.ID}}"], 4096).splitlines()
if len(ids) != 5:
    raise SystemExit(1)
containers, container_ids = [], {}
for short_id in ids:
    row = run(docker + ["container", "inspect", "--format",
              '{{.Id}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Running}}', short_id], 2048)
    container_id, image_id, image_ref, service, running = row.split("|")
    if (
        running != "true"
        or service not in image_keys
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or image_id != expected_image_ids[service]
        or image_ref != image_refs[service]
        or service in container_ids
    ):
        raise SystemExit(1)
    containers.append({"container_id": container_id, "image_id": image_id, "service": service})
    container_ids[service] = container_id
if {item["service"] for item in containers} != {"core", "dgx-relay", "falco", "falco-adapter", "opa"}:
    raise SystemExit(1)
def inspect(service):
    value = json.loads(run(docker + ["container", "inspect", container_ids[service]]))
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise SystemExit(1)
    return value[0]
service_values = {service: inspect(service) for service in image_keys}
core_uid = runtime_values.get("AGMIND_CORE_UID", "")
core_gid = runtime_values.get("AGMIND_CORE_GID", "")
sensor_uid = runtime_values.get("AGMIND_SENSOR_UID", "")
sensor_gid = runtime_values.get("AGMIND_SENSOR_GID", "")
if not all(
    value.isdigit() and int(value) > 0
    for value in (core_uid, core_gid, sensor_uid, sensor_gid)
):
    raise SystemExit(1)
expected_mounts = {
    "core": {
        ("bind", "/run/agmind-sais/observer-core", "/run/agmind-sais/observer-core", False, "rprivate"),
        ("bind", "/run/agmind-sais/actuator-intent", "/run/agmind-sais/actuator-intent", False, "rprivate"),
        ("bind", "/var/lib/agmind-sais/core", "/var/lib/agmind-sais/core", True, "rprivate"),
        ("bind", "/etc/agmind-sais/core.json", "/etc/agmind-sais/core.json", False, "rprivate"),
        ("bind", "/etc/agmind-sais/hunter.json", "/etc/agmind-sais/hunter.json", False, "rprivate"),
        ("bind", "/etc/agmind-sais/observer-trust-root.json", "/etc/agmind-sais/observer-trust-root.json", False, "rprivate"),
        ("bind", "/etc/agmind-sais/public/actuator-ed25519.pub", "/etc/agmind-sais/public/actuator-ed25519.pub", False, "rprivate"),
        ("bind", "/etc/agmind-sais/secrets", "/run/secrets", False, "rprivate"),
    },
    "dgx-relay": {
        ("bind", "/opt/agmind-sais/deploy/config/dgx-relay.cfg", "/usr/local/etc/haproxy/haproxy.cfg", False, "rprivate"),
    },
    "falco": {
        ("bind", "/sys/kernel/tracing", "/sys/kernel/tracing", False, "rprivate"),
        ("bind", "/proc", "/host/proc", False, "rprivate"),
        ("bind", "/etc/os-release", "/host/etc/os-release", False, "rprivate"),
        ("bind", "/etc/passwd", "/host/etc/passwd", False, "rprivate"),
        ("bind", "/etc/group", "/host/etc/group", False, "rprivate"),
        ("bind", "/opt/agmind-sais/deploy/falco/falco.yaml", "/etc/falco/falco.yaml", False, "rprivate"),
        ("bind", "/opt/agmind-sais/deploy/falco/rules.d/agmind-pcc.yaml", "/etc/falco/rules.d/agmind-pcc.yaml", False, "rprivate"),
    },
    "falco-adapter": {
        ("bind", "/run/agmind-sais/observer-ingest", "/run/agmind-sais/observer-ingest", False, "rprivate"),
    },
    "opa": {
        ("bind", "/opt/agmind-sais/policies/pcc.rego", "/policies/pcc.rego", False, "rprivate"),
    },
}
expected_users = {
    "core": f"{core_uid}:{core_gid}",
    "dgx-relay": "99:99",
    "falco": "0:0",
    "falco-adapter": f"{sensor_uid}:{sensor_gid}",
    "opa": "65532:65532",
}
expected_groups = {
    "core": {core_gid},
    "dgx-relay": set(),
    "falco": set(),
    "falco-adapter": {sensor_gid},
    "opa": set(),
}
expected_cap_add = {
    "core": set(),
    "dgx-relay": set(),
    "falco": {"SYS_ADMIN", "SYS_RESOURCE", "SYS_PTRACE"},
    "falco-adapter": set(),
    "opa": set(),
}
expected_service_networks = {
    "core": {"agmind-sais_control_internal"},
    "dgx-relay": {"agmind-sais_control_internal", "agmind-sais_inference"},
    "falco": {"agmind-sais_sensor_internal"},
    "falco-adapter": {"agmind-sais_sensor_internal"},
    "opa": {"agmind-sais_control_internal"},
}

def normalized_caps(values):
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        return None
    return {item.removeprefix("CAP_").upper() for item in values}

def exact_mount_contract(value, expected):
    mounts = value.get("Mounts")
    if not isinstance(mounts, list) or any(not isinstance(mount, dict) for mount in mounts):
        return False
    observed = [
        (
            mount.get("Type"),
            mount.get("Source"),
            mount.get("Destination"),
            mount.get("RW"),
            mount.get("Propagation"),
        )
        for mount in mounts
    ]
    return len(observed) == len(expected) and set(observed) == expected

def no_published_ports(host, network):
    ports = network.get("Ports") or {}
    return (
        not (host.get("PortBindings") or {})
        and isinstance(ports, dict)
        and all(not bindings for bindings in ports.values())
    )

core_binding = {"8787/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8787"}]}
security_boundaries = {}
for service, value in service_values.items():
    host = value.get("HostConfig")
    config = value.get("Config")
    network = value.get("NetworkSettings")
    if not all(isinstance(item, dict) for item in (host, config, network)):
        raise SystemExit(1)
    checks = {
        "exact_user": config.get("User") == expected_users[service],
        "exact_supplemental_groups": set(host.get("GroupAdd") or []) == expected_groups[service],
        "not_privileged": host.get("Privileged") is False,
        "read_only_rootfs": host.get("ReadonlyRootfs") is True,
        "cap_drop_all": normalized_caps(host.get("CapDrop") or []) == {"ALL"},
        "exact_cap_add": normalized_caps(host.get("CapAdd") or []) == expected_cap_add[service],
        "no_devices": not (host.get("Devices") or []) and not (host.get("DeviceRequests") or []),
        "exact_security_options": set(host.get("SecurityOpt") or []) == {"no-new-privileges:true"},
        "no_host_namespaces": (
            host.get("PidMode") == ""
            and host.get("IpcMode") == "private"
            and host.get("UTSMode") == ""
            and host.get("CgroupnsMode") == "private"
        ),
        "exact_mounts": exact_mount_contract(value, expected_mounts[service]),
        "exact_networks": set(network.get("Networks") or {}) == expected_service_networks[service],
    }
    if service == "core":
        checks["loopback_api_only"] = (
            host.get("PortBindings") == core_binding
            and network.get("Ports") == core_binding
        )
        checks["init_enabled"] = host.get("Init") is True
    else:
        checks["no_published_ports"] = no_published_ports(host, network)
    if service == "dgx-relay":
        relay_dgx = [
            item.split("=", 1)[1]
            for item in config.get("Env", [])
            if isinstance(item, str) and item.startswith("AGMIND_DGX_IPV4=")
        ]
        checks["dgx_ipv4_matches_runtime"] = relay_dgx == [dgx_ipv4]
    if not all(checks.values()):
        raise SystemExit(1)
    security_boundaries[service.replace("-", "_")] = checks
networks = []
expected_networks = {
    "agmind-sais_control_internal": {
        "internal": True,
        "members": {container_ids["core"], container_ids["dgx-relay"], container_ids["opa"]},
    },
    "agmind-sais_inference": {
        "internal": False,
        "members": {container_ids["dgx-relay"]},
    },
    "agmind-sais_sensor_internal": {
        "internal": True,
        "members": {container_ids["falco"], container_ids["falco-adapter"]},
    },
}
network_names = run(docker + ["network", "ls", "--filter", "label=com.docker.compose.project=agmind-sais",
                              "--format", "{{.Name}}"], 4096).splitlines()
if len(network_names) != 3 or set(network_names) != set(expected_networks):
    raise SystemExit(1)
for name, expected in sorted(expected_networks.items()):
    inspected = json.loads(run(docker + ["network", "inspect", name]))
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        raise SystemExit(1)
    network = inspected[0]
    network_id = network.get("Id")
    members = network.get("Containers")
    if (
        network.get("Name") != name
        or re.fullmatch(r"[0-9a-f]{64}", str(network_id)) is None
        or network.get("Driver") != "bridge"
        or network.get("Internal") is not expected["internal"]
        or not isinstance(members, dict)
        or set(members) != expected["members"]
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(member_id)) is None
            or not isinstance(member, dict)
            for member_id, member in members.items()
        )
    ):
        raise SystemExit(1)
    networks.append({
        "driver": "bridge",
        "internal": expected["internal"],
        "member_container_ids": sorted(members),
        "name": name,
        "network_id": network_id,
    })
nft = json.loads(run(["/usr/sbin/nft", "--json", "list", "ruleset"]))
def stable_nft(value, context=""):
    if isinstance(value, list):
        return [stable_nft(item, context) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if context == "counter" and key in {"packets", "bytes"}:
            continue
        if context == "quota" and key == "used":
            continue
        if key == "expires":
            continue
        result[key] = stable_nft(item, key)
    return result
nft_canonical = json.dumps(stable_nft(nft), sort_keys=True, separators=(",", ":")).encode()
document = {"boot_id": open("/proc/sys/kernel/random/boot_id").read().strip(),
 "compose_containers": sorted(containers, key=lambda item: item["service"]),
 "compose_networks": networks, "docker_server_version": docker_version,
 "host_nft_ruleset_sha256": hashlib.sha256(nft_canonical).hexdigest(),
 "host_nft_scope": "canonical_ruleset_without_volatile_counters",
 "kernel_release": os.uname().release, "machine": os.uname().machine, "phase": phase,
 "runtime_image_manifest_sha256": runtime_image_manifest_sha256,
 "security_boundaries": security_boundaries,
 "schema_version": "agmind.production-topology-snapshot.v1",
 "systemd_units": {unit: "active" for unit in units}}
raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
temporary = target + ".tmp"
with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600), "wb") as sink:
    sink.write(raw); sink.flush(); os.fsync(sink.fileno())
os.replace(temporary, target)
PY
}

compare_topology() {
  local before="$1" after="$2"
  python3 - "${before}" "${after}" <<'PY'
import json
import sys

def load(path, phase):
    with open(path, "rb") as source:
        raw = source.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise SystemExit(1)
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("phase") != phase:
        raise SystemExit(1)
    return value

before = load(sys.argv[1], "before")
after = load(sys.argv[2], "after")
before["phase"] = "snapshot"
after["phase"] = "snapshot"
if before != after:
    raise SystemExit(1)
PY
}

check_api_boundary() {
  local target="$1"
  python3 - "${target}" <<'PY'
import hashlib, http.client, json, os, stat, sys
path = "/etc/agmind-sais/secrets/core-api.token"
fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o640 or before.st_nlink != 1 or not 1 <= before.st_size <= 4098:
        raise SystemExit(1)
    token = os.read(fd, 4099); after = os.fstat(fd); named = os.stat(path, follow_symlinks=False)
finally:
    os.close(fd)
if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino):
    raise SystemExit(1)
if token.endswith(b"\n"):
    token = token[:-1].removesuffix(b"\r")
if not 1 <= len(token) <= 4096 or any(byte < 0x21 or byte > 0x7e for byte in token):
    raise SystemExit(1)
token_text = token.decode("ascii"); token = b""
def request(method, authenticated):
    connection = http.client.HTTPConnection("127.0.0.1", 8787, timeout=3)
    headers = {"Host": "127.0.0.1", "Connection": "close"}
    if authenticated:
        headers["Authorization"] = "Bearer " + token_text
    try:
        if method == "POST":
            connection.putrequest(
                method,
                "/v1/status",
                skip_host=True,
                skip_accept_encoding=True,
            )
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders()
        else:
            connection.request(method, "/v1/status", headers=headers)
        response = connection.getresponse(); body = response.read(65_537)
        return response.status, dict(response.getheaders()), body
    finally:
        connection.close()
unauthorized = request("GET", False)
wrong_method = request("POST", True)
accepted = request("GET", True)
if unauthorized[0] != 401 or unauthorized[2] != b'{"error":"unauthorized"}' or unauthorized[1].get("WWW-Authenticate") != 'Bearer realm="agmind-core"':
    raise SystemExit(1)
if wrong_method[0] != 405 or wrong_method[2] != b'{"error":"method_not_allowed"}' or wrong_method[1].get("Allow") != "GET":
    raise SystemExit(1)
if accepted[0] != 200 or len(accepted[2]) > 65_536:
    raise SystemExit(1)
status = json.loads(accepted[2])
if status.get("schema_version") != "agmind.core-runtime-status.v1" or json.dumps(status, sort_keys=True, separators=(",", ":")).encode() != accepted[2]:
    raise SystemExit(1)
document = {"authenticated_get_status": 200, "authenticated_status_sha256": hashlib.sha256(accepted[2]).hexdigest(),
 "authenticated_wrong_method_status": 405, "schema_version": "agmind.api-boundary-check.v1", "unauthenticated_get_status": 401}
raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
temporary = sys.argv[1] + ".tmp"
with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600), "wb") as sink:
    sink.write(raw); sink.flush(); os.fsync(sink.fileno())
os.replace(temporary, sys.argv[1])
PY
}

parse_smoke() {
  local source="$1" target="$2"
  python3 - "${source}" "${target}" "${proof_root}" <<'PY'
import json, os, re, stat, sys
source, target, proof_root = sys.argv[1:]
info = os.lstat(source)
if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 1 <= info.st_size <= 4 * 1024 * 1024:
    raise SystemExit(1)
raw = open(source, "rb").read(4 * 1024 * 1024 + 1).replace(b"\r\n", b"\n")
if b"\r" in raw:
    raise SystemExit(1)
lines = [line for line in raw.split(b"\n") if line]
matches = []
for line in lines:
    try:
        text = line.decode("utf-8", "strict")
        value = json.loads(text)
    except (UnicodeError, json.JSONDecodeError):
        continue
    if isinstance(value, dict) and value.get("schema_version") == "agmind.smoke-containment.v1":
        matches.append((text, value))
if len(matches) != 1:
    raise SystemExit(1)
final, document = matches[0]
fields = {"schema_version", "status", "destination_ipv4", "plan_id", "action_id", "approval_record_id",
 "action_record_id", "action_record_sha256", "transition_basis", "candidate_id", "intent_id", "target_container_id",
 "ttl_seconds", "action_state", "actuator_feedback_status", "proof_path", "proof_bundle_sha256", "hunter_model",
 "hunter_status", "hunter_reason_code", "hunter_bundle_sha256", "hunter_record_sha256", "hunter_persistence_status", "canary_sha256",
 "secret_canary_absent"}
patterns = {"plan_id": r"plan_[0-9a-f]{32}", "action_id": r"act_[0-9a-f]{32}",
 "approval_record_id": r"ar_[0-9a-f]{32}", "action_record_id": r"ar_[0-9a-f]{32}",
 "candidate_id": r"cand_[0-9a-f]{64}", "intent_id": r"int_[0-9a-f]{32}", "target_container_id": r"[0-9a-f]{64}"}
for key in ("action_record_sha256", "proof_bundle_sha256", "hunter_bundle_sha256", "hunter_record_sha256", "canary_sha256"):
    patterns[key] = r"[0-9a-f]{64}"
canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
if not isinstance(document, dict) or set(document) != fields or final != canonical or any(re.fullmatch(pattern, str(document.get(key, ""))) is None for key, pattern in patterns.items()):
    raise SystemExit(1)
if (document["schema_version"], document["status"], document["destination_ipv4"], document["action_state"],
    document["actuator_feedback_status"], document["hunter_model"],
    document["hunter_persistence_status"], document["secret_canary_absent"]) != (
    "agmind.smoke-containment.v1", "PASS", "1.1.1.1", "EXPIRED", "verified", "dspark", "durable", True):
    raise SystemExit(1)
if (document["hunter_status"], document["hunter_reason_code"]) not in {
    ("available", "available"),
    ("invalid", "output_invalid"),
}:
    raise SystemExit(1)
if type(document["ttl_seconds"]) is not int or not 30 <= document["ttl_seconds"] <= 300 or document["approval_record_id"] == document["action_record_id"] or document["transition_basis"] != "kernel_timeout_observed":
    raise SystemExit(1)
proof = proof_root + "/" + document["action_id"]
proof_info = os.lstat(proof)
if document["proof_path"] != proof or os.path.realpath(proof) != proof or not stat.S_ISDIR(proof_info.st_mode) or proof_info.st_uid != 0 or stat.S_IMODE(proof_info.st_mode) != 0o700:
    raise SystemExit(1)
temporary = target + ".tmp"
with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600), "wb") as sink:
    sink.write((canonical + "\n").encode()); sink.flush(); os.fsync(sink.fileno())
os.replace(temporary, target)
PY
}

if (($# == 1)) && [[ "$1" == "--help" || "$1" == "-h" ]]; then
  printf 'usage: verify-linux-integration.sh --output <new-absolute-directory>\n'
  exit 0
fi
(($# == 2)) && [[ "$1" == "--output" ]] || block "invalid_arguments"
output="$2"

[[ "$(uname -s)" == "Linux" ]] || block "linux_required"
((EUID == 0)) || block "root_required"
[[ -t 0 && -t 1 ]] || block "interactive_tty_required"
[[ "${AGMIND_DEDICATED_TEST_HOST:-}" == "1" ]] || block "dedicated_test_host_ack_required"
[[ -n "${AGMIND_DGX_URL:-}" && "${AGMIND_DGX_URL}" != *$'\n'* && "${AGMIND_DGX_URL}" != *$'\r'* ]] || block "dgx_url_required"
for command in cat docker nft python3 realpath rm script sha256sum stat systemctl uname; do
  command -v "${command}" >/dev/null 2>&1 || block "required_command_unavailable"
done
[[ "$(command -v docker)" == "/usr/bin/docker" && "$(command -v script)" == "/usr/bin/script" ]] || block "installed_command_path_invalid"
[[ -S /var/run/docker.sock && -d "${docker_config}" && ! -L "${docker_config}" && "$(stat -Lc '%u:%g:%a' "${docker_config}")" == "0:0:700" ]] || block "installed_runtime_unsafe"

[[ "${output}" == /* && "${output}" != "/" && "${output}" == "$(realpath --canonicalize-missing -- "${output}")" && ! -e "${output}" && ! -L "${output}" ]] || block "output_invalid"
parent="${output%/*}"; [[ -n "${parent}" ]] || parent="/"
name="${output##*/}"
[[ "${name}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ && -d "${parent}" && ! -L "${parent}" && "${parent}" == "$(realpath --canonicalize-existing -- "${parent}")" ]] || block "output_parent_unsafe"
metadata="$(stat -Lc '%u:%a' "${parent}")"; mode="${metadata#*:}"
[[ "${metadata%%:*}" == "0" && "${mode}" =~ ^[0-7]{3,4}$ ]] && (((8#${mode} & 8#022) == 0)) || block "output_parent_unsafe"
mkdir -m 0700 -- "${output}" || block "output_creation_failed"
output_ready=1
[[ "$(stat -Lc '%u:%g:%a' "${output}")" == "0:0:700" ]] || block "output_directory_unsafe"
trap 'block unexpected_failure 70' ERR
trap 'block interrupted 130' INT
trap 'block terminated 143' TERM
trap 'block hangup 129' HUP

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
smoke="${script_dir}/smoke-containment-linux.sh"
[[ "${smoke}" == "$(realpath --canonicalize-existing -- "${smoke}")" && "${smoke}" =~ ^/[A-Za-z0-9._/-]+$ && -x "${smoke}" && ! -L "${smoke}" ]] || block "smoke_script_unsafe"

snapshot_topology before "${output}/topology-before.json" || block "topology_before_failed"
check_api_boundary "${output}/api-boundary.json" || block "api_boundary_failed"
transcript="${output}/.smoke-session"
printf '[agmind-acceptance] interactive native smoke starting\n' >&2
if ! /usr/bin/env -i PATH="${PATH}" LC_ALL=C LANG=C SHELL=/bin/sh TERM=dumb \
  DOCKER_CONFIG="${docker_config}" AGMIND_DEDICATED_TEST_HOST=1 AGMIND_DGX_URL="${AGMIND_DGX_URL}" \
  /usr/bin/script --quiet --return --flush --command "${smoke}" "${transcript}"; then
  block "smoke_failed"
fi
parse_smoke "${transcript}" "${output}/smoke-result.json" || block "smoke_result_invalid"
rm -f -- "${transcript}" || block "smoke_transcript_cleanup_failed"
transcript=""
snapshot_topology after "${output}/topology-after.json" || block "topology_after_failed"
compare_topology "${output}/topology-before.json" "${output}/topology-after.json" || block "topology_changed"
write_report PASS native_smoke_verified || block "acceptance_report_failed"
[[ "$(stat -Lc '%u:%g:%a' "${output}/acceptance-report.json")" == "0:0:600" ]] || block "acceptance_report_unsafe"
trap - ERR INT TERM HUP
cat -- "${output}/acceptance-report.json"
