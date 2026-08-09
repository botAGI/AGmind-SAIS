#!/usr/bin/env bash
set -euo pipefail

readonly destination_ipv4="1.1.1.1"
readonly destination_port="443"
readonly admin_socket="/run/agmind-sais/actuator-admin/socket"
readonly pending_limit="100"

block() {
  local reason_code="$1"
  printf '{"reason_code":"%s","schema_version":"agmind.smoke-containment.v1","status":"BLOCKED"}\n' "${reason_code}" >&2
  exit 78
}

if (($# != 0)); then
  block "arguments_forbidden"
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  block "linux_required"
fi
if ((EUID != 0)); then
  block "root_required"
fi
if [[ "${AGMIND_DEDICATED_TEST_HOST:-}" != "1" ]]; then
  block "dedicated_test_host_ack_required"
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  block "interactive_tty_required"
fi
if [[ -z "${AGMIND_DGX_URL:-}" ]]; then
  block "dgx_url_required"
fi

for required_command in \
  agmindctl curl dirname docker nft nsenter python3 sleep systemctl tr uname; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    block "required_command_unavailable"
  fi
done

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
preflight_report=""
if ! preflight_report="$(
  "${script_dir}/preflight-linux.sh" \
    --dgx-url "${AGMIND_DGX_URL}" \
    --runtime-env /etc/agmind-sais/runtime.env \
    --management-denylist /etc/agmind-sais/management-destinations.json
)"; then
  block "preflight_failed"
fi
if ! python3 - "${preflight_report}" <<'PY'
import json
import sys

try:
    value = json.loads(sys.argv[1])
except (IndexError, json.JSONDecodeError):
    raise SystemExit(1)
if (
    not isinstance(value, dict)
    or value.get("schema_version") != "agmind.preflight.v1"
    or value.get("active_containment_supported") is not True
    or value.get("hard_failures") != []
    or value.get("degraded") != []
):
    raise SystemExit(1)
PY
then
  block "preflight_not_clean"
fi

target_image=""
if ! target_image="$(python3 - /etc/agmind-sais/runtime.env <<'PY'
from pathlib import Path
import sys

try:
    lines = Path(sys.argv[1]).read_text(encoding="ascii").splitlines()
except (OSError, UnicodeError):
    raise SystemExit(1)
values = []
for line in lines:
    if line.startswith("AGMIND_HAPROXY_IMAGE="):
        values.append(line.split("=", 1)[1])
if len(values) != 1 or not values[0] or values[0] != values[0].strip():
    raise SystemExit(1)
print(values[0])
PY
)"; then
  block "pinned_smoke_target_image_unavailable"
fi
readonly target_image

for required_unit in \
  docker.service \
  agmind-sais.target \
  agmind-observerd.service \
  agmind-actuatord.service \
  agmind-core-compose.service; do
  if ! systemctl is-active --quiet "${required_unit}"; then
    block "required_service_not_ready"
  fi
done
for required_socket in \
  /run/agmind-sais/observer-core/socket \
  /run/agmind-sais/observer-ingest/socket \
  /run/agmind-sais/observer-actuator/socket \
  /run/agmind-sais/actuator-intent/socket \
  "${admin_socket}"; do
  if [[ ! -S "${required_socket}" ]]; then
    block "required_socket_unavailable"
  fi
done

ready_report=""
if ! ready_report="$(curl --fail --silent --show-error --max-time 3 http://127.0.0.1:8787/ready)"; then
  block "core_not_ready"
fi
if ! python3 - "${ready_report}" <<'PY'
import json
import sys

try:
    value = json.loads(sys.argv[1])
except (IndexError, json.JSONDecodeError):
    raise SystemExit(1)
if set(value) != {"ready", "version"} or value.get("ready") is not True:
    raise SystemExit(1)
PY
then
  block "core_readiness_invalid"
fi

# Fail before creating a target when the installed local-admin binary/socket do
# not expose the bounded discovery contract required for exact before/after.
if ! agmindctl plans pending --json --limit "${pending_limit}" >/dev/null; then
  block "pending_plan_discovery_unavailable"
fi

docker_fixed() {
  docker --host unix:///var/run/docker.sock "$@"
}

while IFS= read -r existing_name; do
  if [[ "${existing_name}" == agmind-smoke-* ]]; then
    block "unrelated_smoke_container_present"
  fi
done < <(docker_fixed container ls --all --format '{{.Names}}')
while IFS= read -r existing_name; do
  if [[ "${existing_name}" == agmind-smoke-* ]]; then
    block "unrelated_smoke_network_present"
  fi
done < <(docker_fixed network ls --format '{{.Name}}')

target_image_id=""
if ! target_image_id="$(docker_fixed image inspect --format '{{.Id}}' "${target_image}" 2>/dev/null)" ||
  [[ ! "${target_image_id}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  block "local_smoke_target_image_required"
fi

run_token=""
if ! run_token="$(tr -d '-' </proc/sys/kernel/random/uuid)"; then
  block "run_identity_unavailable"
fi
if [[ ! "${run_token}" =~ ^[0-9a-f]{32}$ ]]; then
  block "run_identity_unavailable"
fi
run_id="${run_token:0:16}"
network_name="agmind-smoke-${run_id}"
container_name="agmind-smoke-${run_id}-target"
control_container_name="agmind-smoke-${run_id}-control"
network_id=""
container_id=""
control_container_id=""
services_need_restore=0

restore_services() {
  local failed=0
  if ((services_need_restore == 1)); then
    systemctl restart agmind-sais.target || failed=1
    if ((failed == 0)); then
      for restored_unit in \
        agmind-sais.target \
        agmind-observerd.service \
        agmind-actuatord.service \
        agmind-core-compose.service; do
        systemctl is-active --quiet "${restored_unit}" || failed=1
      done
    fi
  fi
  return "${failed}"
}

cleanup_resources() {
  local failed=0
  local observed_label=""
  local owned_container_id=""
  for owned_container_id in "${control_container_id}" "${container_id}"; do
    if [[ "${owned_container_id}" =~ ^[0-9a-f]{64}$ ]] &&
      docker_fixed container inspect "${owned_container_id}" >/dev/null 2>&1; then
      observed_label="$(
        docker_fixed container inspect \
          --format '{{ index .Config.Labels "agmind.sais.smoke.run" }}' \
          "${owned_container_id}" 2>/dev/null || true
      )"
      if [[ "${observed_label}" == "${run_id}" ]]; then
        docker_fixed container rm --force "${owned_container_id}" >/dev/null || failed=1
      else
        failed=1
      fi
    fi
  done
  if [[ "${network_id}" =~ ^[0-9a-f]{64}$ ]] &&
    docker_fixed network inspect "${network_id}" >/dev/null 2>&1; then
    observed_label="$(
      docker_fixed network inspect \
        --format '{{ index .Labels "agmind.sais.smoke.run" }}' \
        "${network_id}" 2>/dev/null || true
    )"
    if [[ "${observed_label}" == "${run_id}" ]]; then
      docker_fixed network rm "${network_id}" >/dev/null || failed=1
    else
      failed=1
    fi
  fi
  restore_services || failed=1
  return "${failed}"
}

on_exit() {
  local exit_code="$?"
  trap - EXIT INT TERM HUP
  if ! cleanup_resources; then
    printf '%s\n' '{"reason_code":"exact_cleanup_failed","schema_version":"agmind.smoke-containment.v1","status":"BLOCKED"}' >&2
    exit_code=70
  fi
  exit "${exit_code}"
}
trap on_exit EXIT
trap 'exit 130' INT TERM HUP

if ! network_id="$(
  docker_fixed network create \
    --driver bridge \
    --label "agmind.sais.smoke.run=${run_id}" \
    "${network_name}"
)"; then
  block "smoke_network_creation_failed"
fi
if [[ ! "${network_id}" =~ ^[0-9a-f]{64}$ ]]; then
  block "smoke_network_creation_failed"
fi

create_smoke_container() {
  local exact_name="$1"
  docker_fixed container run \
    --detach \
    --name "${exact_name}" \
    --hostname "${exact_name##*-}" \
    --network "${network_id}" \
    --label "agmind.sais.smoke.run=${run_id}" \
    --user 65534:65534 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 32 \
    --memory 64m \
    --cpus 0.25 \
    --restart no \
    --entrypoint /bin/busybox \
    "${target_image}" \
    sleep 600
}

if ! container_id="$(create_smoke_container "${container_name}")"; then
  block "smoke_container_creation_failed"
fi
if [[ ! "${container_id}" =~ ^[0-9a-f]{64}$ ]]; then
  block "smoke_container_creation_failed"
fi
if ! control_container_id="$(create_smoke_container "${control_container_name}")"; then
  block "smoke_control_creation_failed"
fi
if [[ ! "${control_container_id}" =~ ^[0-9a-f]{64}$ ||
  "${control_container_id}" == "${container_id}" ]]; then
  block "smoke_control_creation_failed"
fi

container_document=""
if ! container_document="$(
  docker_fixed container inspect "${container_id}" "${control_container_id}"
)"; then
  block "smoke_container_inspect_failed"
fi
if ! python3 - "${container_document}" "${container_id}" \
  "${control_container_id}" "${network_name}" <<'PY'
import json
import sys

try:
    documents = json.loads(sys.argv[1])
except (IndexError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(documents, list) or len(documents) != 2:
    raise SystemExit(1)
if {value.get("Id") for value in documents} != {sys.argv[2], sys.argv[3]}:
    raise SystemExit(1)
for value in documents:
    host = value.get("HostConfig", {})
    config = value.get("Config", {})
    networks = value.get("NetworkSettings", {}).get("Networks", {})
    if (
        value.get("State", {}).get("Running") is not True
        or host.get("Privileged") is not False
        or host.get("CapAdd") not in (None, [])
        or "ALL" not in (host.get("CapDrop") or [])
        or config.get("User") != "65534:65534"
        or set(networks) != {sys.argv[4]}
    ):
        raise SystemExit(1)
PY
then
  block "smoke_container_boundary_invalid"
fi

target_pid=""
if ! target_pid="$(docker_fixed container inspect --format '{{.State.Pid}}' "${container_id}")"; then
  block "smoke_target_pid_invalid"
fi
if [[ ! "${target_pid}" =~ ^[1-9][0-9]*$ ]]; then
  block "smoke_target_pid_invalid"
fi

busybox_applets=""
if ! busybox_applets="$(
  docker_fixed container exec "${container_id}" /bin/busybox --list
)"; then
  block "smoke_image_busybox_unavailable"
fi
for required_applet in nc sh sleep timeout; do
  if [[ $'\n'"${busybox_applets}"$'\n' != *$'\n'"${required_applet}"$'\n'* ]]; then
    block "smoke_image_applet_unavailable"
  fi
done

control_can_connect() {
  docker_fixed container exec "${control_container_id}" \
    /bin/sh -c 'exec /bin/busybox nc -w 5 "$1" "$2" </dev/null' \
    agmind-control "${destination_ipv4}" "${destination_port}"
}

host_pcc_table_absent() {
  local table_document=""
  if ! table_document="$(nft --json list tables)"; then
    return 1
  fi
  python3 - "${table_document}" <<'PY'
import json
import sys

try:
    document = json.loads(sys.argv[1])
except (IndexError, json.JSONDecodeError):
    raise SystemExit(1)
for item in document.get("nftables", []):
    table = item.get("table") if isinstance(item, dict) else None
    if isinstance(table, dict) and table.get("family") == "ip" and table.get("name") == "agmind_pcc":
        raise SystemExit(1)
PY
}

# Allow the event-driven observer inventory update to become admission-visible.
sleep 2
if ! control_can_connect; then
  block "control_public_destination_unreachable"
fi
if ! host_pcc_table_absent; then
  block "host_namespace_contains_agmind_pcc"
fi
before_plans=""
if ! before_plans="$(agmindctl plans pending --json --limit "${pending_limit}")"; then
  block "pending_plan_snapshot_failed"
fi

# This successful public IPv4 connect is both the lab reachability proof and the
# real pinned Falco outbound trigger.
if ! docker_fixed container exec "${container_id}" /bin/sh -c \
  'exec /bin/busybox nc -w 5 "$1" "$2" </dev/null' \
  agmind-connect "${destination_ipv4}" "${destination_port}"; then
  block "public_destination_unreachable"
fi

find_new_plan() {
  local current_plans="$1"
  python3 - "${before_plans}" "${current_plans}" \
    "${container_id}" "${destination_ipv4}" <<'PY'
import json
import sys

try:
    before = json.loads(sys.argv[1])
    current = json.loads(sys.argv[2])
except (IndexError, json.JSONDecodeError):
    raise SystemExit(2)
before_ids = {item["plan_id"] for item in before.get("plans", [])}
matches = [
    item["plan_id"]
    for item in current.get("plans", [])
    if item.get("plan_id") not in before_ids
    and item.get("docker_container_id") == sys.argv[3]
    and item.get("destination_ipv4") == sys.argv[4]
]
if not matches:
    raise SystemExit(1)
if len(matches) != 1:
    raise SystemExit(2)
print(matches[0])
PY
}

plan_id=""
plan_deadline="$((SECONDS + 45))"
while ((SECONDS < plan_deadline)); do
  current_plans=""
  if ! current_plans="$(agmindctl plans pending --json --limit "${pending_limit}")"; then
    block "pending_plan_poll_failed"
  fi
  if candidate_plan_id="$(find_new_plan "${current_plans}")"; then
    plan_id="${candidate_plan_id}"
    break
  else
    plan_match_status="$?"
    if ((plan_match_status != 1)); then
      block "pending_plan_match_ambiguous"
    fi
  fi
  sleep 1
done
if [[ ! "${plan_id}" =~ ^plan_[0-9a-f]{32}$ ]]; then
  block "pending_plan_timeout"
fi

plan_display=""
if ! plan_display="$(agmindctl proposal show "${plan_id}")"; then
  block "exact_plan_lookup_failed"
fi
ttl_seconds=""
if ! ttl_seconds="$(python3 - "${plan_display}" "${plan_id}" \
  "${container_id}" "${destination_ipv4}" <<'PY'
import sys

values = {}
for line in sys.argv[1].splitlines():
    if ": " in line:
        key, value = line.split(": ", 1)
        values.setdefault(key, []).append(value)
required = {
    "Plan ID": sys.argv[2],
    "Container ID": sys.argv[3],
    "Destination IPv4": sys.argv[4],
}
for key, expected in required.items():
    if values.get(key) != [expected]:
        raise SystemExit(1)
try:
    ttl = int(values["TTL seconds"][0])
except (KeyError, IndexError, ValueError):
    raise SystemExit(1)
if not 30 <= ttl <= 300:
    raise SystemExit(1)
print(ttl)
PY
)"; then
  block "exact_plan_display_invalid"
fi
if [[ ! "${ttl_seconds}" =~ ^[0-9]+$ ]]; then
  block "exact_plan_display_invalid"
fi
if [[ "$(docker_fixed container inspect --format '{{.Id}}:{{.State.Pid}}' "${container_id}")" != "${container_id}:${target_pid}" ]]; then
  block "target_changed_before_approval"
fi

printf 'AGmind smoke will request interactive approval for %s.\n' "${plan_id}"
if ! agmindctl proposal approve "${plan_id}"; then
  block "interactive_approval_not_completed"
fi

nft_set_state() {
  local document=""
  if ! document="$(
    nsenter --target "${target_pid}" --net \
      nft --json list set ip agmind_pcc blocked_v4 2>/dev/null
  )"; then
    return 1
  fi
  python3 - "${document}" "${destination_ipv4}" "${ttl_seconds}" <<'PY'
import json
import re
import sys

def duration_ms(value):
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"([1-9][0-9]*)(ms|s|m)", value)
    if match is None:
        return None
    factors = {"ms": 1, "s": 1_000, "m": 60_000}
    return int(match.group(1)) * factors[match.group(2)]

try:
    document = json.loads(sys.argv[1])
except (IndexError, json.JSONDecodeError):
    raise SystemExit(2)
sets = [
    item["set"]
    for item in document.get("nftables", [])
    if isinstance(item, dict) and isinstance(item.get("set"), dict)
]
if len(sets) != 1:
    raise SystemExit(2)
value = sets[0]
if (
    value.get("family") != "ip"
    or value.get("table") != "agmind_pcc"
    or value.get("name") != "blocked_v4"
    or value.get("type") != "ipv4_addr"
    or set(value.get("flags", [])) != {"timeout"}
    or value.get("comment") != "agmind:pcc:v1"
):
    raise SystemExit(2)
elements = value.get("elem", [])
if elements in (None, []):
    print("ABSENT")
    raise SystemExit(0)
if not isinstance(elements, list) or len(elements) != 1:
    raise SystemExit(2)
element = elements[0].get("elem") if isinstance(elements[0], dict) else None
if not isinstance(element, dict):
    raise SystemExit(2)
if element.get("val") != sys.argv[2] or element.get("comment") != "agmind:pcc:v1":
    raise SystemExit(2)
configured = duration_ms(element.get("timeout"))
remaining = duration_ms(element.get("expires"))
expected = int(sys.argv[3]) * 1_000
if configured != expected or remaining is None or not 0 < remaining <= configured:
    raise SystemExit(2)
print("PRESENT")
PY
}

apply_deadline="$((SECONDS + 40))"
while ((SECONDS < apply_deadline)); do
  if nft_state="$(nft_set_state)"; then
    if [[ "${nft_state}" == "PRESENT" ]]; then
      break
    fi
  else
    nft_status="$?"
    if ((nft_status != 1)); then
      block "exact_nft_element_invalid"
    fi
  fi
  sleep 1
done
if [[ "${nft_state:-}" != "PRESENT" ]]; then
  block "exact_nft_element_timeout"
fi

if docker_fixed container exec "${container_id}" /bin/sh -c \
  'exec /bin/busybox nc -w 3 "$1" "$2" </dev/null' \
  agmind-blocked "${destination_ipv4}" "${destination_port}"; then
  block "containment_not_enforced"
fi
if ! control_can_connect; then
  block "control_connection_was_contained"
fi
if ! host_pcc_table_absent; then
  block "host_namespace_mutated"
fi

# Stop both control-plane owners. Only the kernel timeout may release the deny.
services_need_restore=1
if ! systemctl stop agmind-core-compose.service; then
  block "core_stop_failed"
fi
if ! systemctl stop agmind-actuatord.service; then
  block "actuator_stop_failed"
fi
if systemctl is-active --quiet agmind-core-compose.service ||
  systemctl is-active --quiet agmind-actuatord.service; then
  block "control_plane_stop_incomplete"
fi

expiry_deadline="$((SECONDS + ttl_seconds + 15))"
expired=0
while ((SECONDS < expiry_deadline)); do
  if nft_state="$(nft_set_state)"; then
    if [[ "${nft_state}" == "ABSENT" ]]; then
      expired=1
      break
    fi
  else
    nft_status="$?"
    if ((nft_status != 1)); then
      block "nft_expiry_state_invalid"
    fi
  fi
  sleep 1
done
if ((expired != 1)); then
  block "native_ttl_expiry_timeout"
fi
if ! docker_fixed container exec "${container_id}" /bin/sh -c \
  'exec /bin/busybox nc -w 5 "$1" "$2" </dev/null' \
  agmind-expired "${destination_ipv4}" "${destination_port}"; then
  block "connectivity_not_restored_after_ttl"
fi

if ! restore_services; then
  block "service_restore_failed"
fi
services_need_restore=0
if ! curl --fail --silent --show-error --max-time 30 \
  http://127.0.0.1:8787/ready >/dev/null; then
  block "core_not_ready_after_restore"
fi

trap - EXIT INT TERM HUP
if ! cleanup_resources; then
  printf '%s\n' '{"reason_code":"exact_cleanup_failed","schema_version":"agmind.smoke-containment.v1","status":"BLOCKED"}' >&2
  exit 70
fi
printf '{"destination_ipv4":"%s","plan_id":"%s","schema_version":"agmind.smoke-containment.v1","status":"PASS","target_container_id":"%s","ttl_seconds":%s}\n' \
  "${destination_ipv4}" "${plan_id}" "${container_id}" "${ttl_seconds}"
