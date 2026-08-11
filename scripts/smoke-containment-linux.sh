#!/usr/bin/env bash
set -euo pipefail

readonly destination_ipv4="1.1.1.1"
readonly destination_port="443"
readonly admin_socket="/run/agmind-sais/actuator-admin/socket"
readonly pending_limit="100"
readonly proof_export_root="/var/lib/agmind-sais/exports"

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
if [[ -z "${AGMIND_HUNTER_URL:-}" ]]; then
  block "hunter_url_required"
fi

for required_command in \
  agmindctl curl dirname docker install nft nsenter python3 sleep stat systemctl tee tr uname; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    block "required_command_unavailable"
  fi
done

# Keep the real terminal visible while retaining the bounded approval receipt.
exec 3>&1

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
preflight_report=""
if ! preflight_report="$(
  "${script_dir}/preflight-linux.sh" \
    --hunter-url "${AGMIND_HUNTER_URL}" \
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

core_ready_document() {
  local document="$1"
  python3 - "${document}" <<'PY'
import json
import sys

try:
    value = json.loads(sys.argv[1])
except (IndexError, json.JSONDecodeError):
    raise SystemExit(1)
if set(value) != {"ready"} or value.get("ready") is not True:
    raise SystemExit(1)
PY
}

ready_report=""
if ! ready_report="$(curl --fail --silent --show-error --noproxy '*' --max-time 3 http://127.0.0.1:8787/ready)" ||
  ! core_ready_document "${ready_report}"; then
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
secret_canary="agmind_secret_${run_token}"
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
  local include_secret_canary="${2:-0}"
  local -a secret_arguments=()
  if [[ "${include_secret_canary}" == "1" ]]; then
    # Docker receives only the variable name in argv; the canary value remains
    # in the process environment and must never appear in evidence or reports.
    secret_arguments+=(--env AGMIND_SMOKE_SECRET_CANARY)
  elif [[ "${include_secret_canary}" != "0" ]]; then
    return 2
  fi
  AGMIND_SMOKE_SECRET_CANARY="${secret_canary}" docker_fixed container run \
    --detach \
    --name "${exact_name}" \
    --hostname "${exact_name##*-}" \
    --network "${network_id}" \
    --label "agmind.sais.smoke.run=${run_id}" \
    "${secret_arguments[@]}" \
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
    sleep 3600
}

if ! container_id="$(create_smoke_container "${container_name}" 1)"; then
  block "smoke_container_creation_failed"
fi
if [[ ! "${container_id}" =~ ^[0-9a-f]{64}$ ]]; then
  block "smoke_container_creation_failed"
fi
if ! control_container_id="$(create_smoke_container "${control_container_name}" 0)"; then
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
if ! CONTAINER_DOCUMENT="${container_document}" \
  AGMIND_EXPECTED_CANARY="${secret_canary}" \
  python3 - "${container_id}" \
  "${control_container_id}" "${network_name}" <<'PY'
import json
import os
import sys

try:
    documents = json.loads(os.environ["CONTAINER_DOCUMENT"])
    canary = os.environ["AGMIND_EXPECTED_CANARY"]
except (IndexError, KeyError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(documents, list) or len(documents) != 2 or not canary.isascii() or not canary:
    raise SystemExit(1)
if {value.get("Id") for value in documents} != {sys.argv[1], sys.argv[2]}:
    raise SystemExit(1)
for value in documents:
    host = value.get("HostConfig", {})
    config = value.get("Config", {})
    networks = value.get("NetworkSettings", {}).get("Networks", {})
    environment = config.get("Env") or []
    canary_entries = [
        item
        for item in environment
        if isinstance(item, str) and item.startswith("AGMIND_SMOKE_SECRET_CANARY=")
    ]
    expected_canary_entries = (
        ["AGMIND_SMOKE_SECRET_CANARY=" + canary]
        if value.get("Id") == sys.argv[1]
        else []
    )
    if (
        value.get("State", {}).get("Running") is not True
        or host.get("Privileged") is not False
        or host.get("CapAdd") not in (None, [])
        or "ALL" not in (host.get("CapDrop") or [])
        or config.get("User") != "65534:65534"
        or set(networks) != {sys.argv[3]}
        or not isinstance(environment, list)
        or canary_entries != expected_canary_entries
    ):
        raise SystemExit(1)
PY
then
  block "smoke_container_boundary_invalid"
fi
container_document=""

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

host_ruleset_digest() {
  nft --json list ruleset | python3 /dev/fd/4 4<<'PY'
import hashlib
import json
import sys

def stable(value, context=""):
    if isinstance(value, list):
        return [stable(item, context) for item in value]
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
        result[key] = stable(item, key)
    return result

document = json.load(sys.stdin)
canonical = json.dumps(stable(document), sort_keys=True, separators=(",", ":")).encode()
print(hashlib.sha256(canonical).hexdigest())
PY
}

# Docker has finished creating the isolated lab network and both containers.
# Pin the complete host ruleset before any reachability probe, Falco trigger, or
# plan preparation can exercise the containment path.
host_ruleset_after_lab_setup=""
if ! host_ruleset_after_lab_setup="$(host_ruleset_digest)" ||
  [[ ! "${host_ruleset_after_lab_setup}" =~ ^[0-9a-f]{64}$ ]]; then
  block "host_ruleset_snapshot_failed"
fi

target_pcc_table_absent() {
  local table_document=""
  if ! table_document="$(
    nsenter --target "${target_pid}" --net nft --json list tables
  )" 2>/dev/null; then
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

core_api_get() {
  local request_target="$1"
  python3 - "${request_target}" <<'PY'
import http.client
import os
import stat
import sys

TOKEN_PATH = "/etc/agmind-sais/secrets/core-api.token"
MAX_TOKEN_BYTES = 4_096
MAX_RESPONSE_BYTES = 64 * 1_024

try:
    target = sys.argv[1]
    if (
        not target.startswith("/v1/")
        or len(target) > 2_048
        or not target.isascii()
        or any(ord(character) < 0x21 or ord(character) > 0x7e for character in target)
    ):
        raise ValueError("invalid target")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise ValueError("nofollow unavailable")
    descriptor = os.open(TOKEN_PATH, os.O_RDONLY | os.O_CLOEXEC | nofollow)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o640
            or not 1 <= before.st_size <= MAX_TOKEN_BYTES + 2
        ):
            raise ValueError("unsafe token")
        raw = os.read(descriptor, MAX_TOKEN_BYTES + 3)
        after = os.fstat(descriptor)
        named = os.stat(TOKEN_PATH, follow_symlinks=False)
        stable = lambda value: (
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
            len(raw) != before.st_size
            or stable(before) != stable(after)
            or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise ValueError("token changed")
    finally:
        os.close(descriptor)
    if raw.endswith(b"\n"):
        raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
    if not 1 <= len(raw) <= MAX_TOKEN_BYTES or any(byte < 0x21 or byte > 0x7e for byte in raw):
        raise ValueError("invalid token")
    token = raw.decode("ascii", "strict")
    connection = http.client.HTTPConnection("127.0.0.1", 8787, timeout=3)
    try:
        connection.request(
            "GET",
            target,
            headers={"Authorization": "Bearer " + token, "Host": "127.0.0.1"},
        )
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
    finally:
        connection.close()
    if response.status != 200 or len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("request unavailable")
    sys.stdout.buffer.write(body)
except (OSError, ValueError, UnicodeError, http.client.HTTPException):
    raise SystemExit(1)
PY
}

expired_action_fields() {
  local action_document="$1"
  ACTION_DOCUMENT="${action_document}" python3 - "${action_id}" "${plan_id}" <<'PY'
import json
import os
import re
import sys

def exact_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value

try:
    document = json.loads(os.environ["ACTION_DOCUMENT"], object_pairs_hook=exact_object)
except (KeyError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
if not isinstance(document, dict) or set(document) != {"schema_version", "record"}:
    raise SystemExit(2)
if document.get("schema_version") != "agmind.action-record-view.v1":
    raise SystemExit(2)
record = document.get("record")
if not isinstance(record, dict):
    raise SystemExit(2)
if record.get("state") != "EXPIRED":
    raise SystemExit(1)
expected_fields = {
    "schema_version",
    "record_id",
    "action_id",
    "plan_id",
    "plan_hash",
    "state",
    "reason_code",
    "observed_at",
    "previous_record_sha256",
    "record_sha256",
    "details",
    "actuator_key_id",
    "actuator_signature",
}
details = record.get("details")
if (
    set(record) != expected_fields
    or record.get("schema_version") != "agmind.action-record.v1"
    or record.get("action_id") != sys.argv[1]
    or record.get("plan_id") != sys.argv[2]
    or record.get("reason_code") != "native_timeout_expired"
    or re.fullmatch(r"ar_[0-9a-f]{32}", str(record.get("record_id", ""))) is None
    or re.fullmatch(r"[0-9a-f]{64}", str(record.get("plan_hash", ""))) is None
    or re.fullmatch(r"[0-9a-f]{64}", str(record.get("previous_record_sha256", ""))) is None
    or re.fullmatch(r"[0-9a-f]{64}", str(record.get("record_sha256", ""))) is None
    or re.fullmatch(r"[0-9a-f]{32}", str(record.get("actuator_key_id", ""))) is None
    or re.fullmatch(r"[0-9a-f]{128}", str(record.get("actuator_signature", ""))) is None
    or not isinstance(record.get("observed_at"), str)
    or not isinstance(details, dict)
    or set(details) != {
        "previous_action_record_sha256",
        "transition_boot_id",
        "transition_boottime_ns",
        "transition_basis",
    }
    or re.fullmatch(r"[0-9a-f]{64}", str(details.get("previous_action_record_sha256", ""))) is None
    or re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        str(details.get("transition_boot_id", "")),
    ) is None
    or type(details.get("transition_boottime_ns")) is not int
    or details.get("transition_boottime_ns", 0) <= 0
    or details.get("transition_basis") != "kernel_timeout_observed"
):
    raise SystemExit(2)
print(record["record_id"])
print(record["record_sha256"])
print(details["transition_basis"])
PY
}

core_status_fields() {
  local status_document="$1"
  CORE_STATUS_DOCUMENT="${status_document}" python3 - <<'PY'
import json
import os
import sys

def exact_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value

try:
    document = json.loads(os.environ["CORE_STATUS_DOCUMENT"], object_pairs_hook=exact_object)
except (KeyError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
expected = {
    "schema_version",
    "polls",
    "policy_commits",
    "prepared_plans",
    "quarantined_intents",
    "last_hunter_status",
    "hunter_persistence_status",
    "actuator_feedback_status",
    "actuator_journal_records",
    "action_records",
}
if (
    not isinstance(document, dict)
    or set(document) != expected
    or document.get("schema_version") != "agmind.core-runtime-status.v1"
    or any(type(document.get(key)) is not int or document[key] < 0 for key in {
        "polls",
        "policy_commits",
        "prepared_plans",
        "quarantined_intents",
        "actuator_journal_records",
        "action_records",
    })
):
    raise SystemExit(2)
if document.get("actuator_feedback_status") != "verified":
    raise SystemExit(1)
last_hunter = document.get("last_hunter_status")
if last_hunter is not None and not isinstance(last_hunter, str):
    raise SystemExit(2)
print(document["actuator_feedback_status"])
print(document["hunter_persistence_status"])
print("none" if last_hunter is None else last_hunter)
PY
}

hunter_page_fields() {
  local page_document="$1"
  local page_after="$2"
  HUNTER_PAGE_DOCUMENT="${page_document}" \
    AGMIND_SECRET_CANARY="${secret_canary}" \
    python3 - "${candidate_id}" "${page_after}" <<'PY'
import hashlib
import json
import os
import re
import sys

def exact_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value

def contains_canary(value, canary):
    if isinstance(value, str):
        return canary in value
    if isinstance(value, list):
        return any(contains_canary(item, canary) for item in value)
    if isinstance(value, dict):
        return any(canary in key or contains_canary(item, canary) for key, item in value.items())
    return False

def bounded_strings(values, maximum):
    return (
        isinstance(values, list)
        and len(values) <= 8
        and all(isinstance(value, str) and len(value.encode("utf-8")) <= maximum for value in values)
    )

try:
    document = json.loads(os.environ["HUNTER_PAGE_DOCUMENT"], object_pairs_hook=exact_object)
    canary = os.environ["AGMIND_SECRET_CANARY"]
except (KeyError, UnicodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
candidate_id = sys.argv[1]
after_text = sys.argv[2]
expected_after = None if after_text == "" else after_text
expected_top = {
    "schema_version",
    "after",
    "limit",
    "returned",
    "next_after",
    "truncated",
    "investigations",
}
records = document.get("investigations") if isinstance(document, dict) else None
if (
    not canary
    or not isinstance(document, dict)
    or set(document) != expected_top
    or document.get("schema_version") != "agmind.hunter-investigation-page.v1"
    or document.get("after") != expected_after
    or document.get("limit") != 100
    or type(document.get("returned")) is not int
    or not isinstance(document.get("truncated"), bool)
    or not isinstance(records, list)
    or document.get("returned") != len(records)
    or not 0 <= len(records) <= 100
):
    raise SystemExit(2)
if contains_canary(document, canary):
    raise SystemExit(4)

record_fields = {
    "candidate_id",
    "bundle_sha256",
    "status",
    "reason_code",
    "output",
    "record_sha256",
}
statuses = {"available", "unavailable", "invalid", "expired", "queue_full"}
ids = []
for record in records:
    if (
        not isinstance(record, dict)
        or set(record) != record_fields
        or re.fullmatch(r"cand_[0-9a-f]{64}", str(record.get("candidate_id", ""))) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(record.get("bundle_sha256", ""))) is None
        or record.get("status") not in statuses
        or not isinstance(record.get("reason_code"), str)
        or not 1 <= len(record["reason_code"]) <= 64
        or not record["reason_code"].isascii()
        or re.fullmatch(r"[0-9a-f]{64}", str(record.get("record_sha256", ""))) is None
        or (record.get("status") == "available") != isinstance(record.get("output"), dict)
        or (record.get("status") != "available" and record.get("output") is not None)
    ):
        raise SystemExit(2)
    ids.append(record["candidate_id"])
if ids != sorted(set(ids)) or (expected_after is not None and any(value <= expected_after for value in ids)):
    raise SystemExit(2)
expected_next = expected_after if not records else ids[-1]
if document.get("next_after") != expected_next:
    raise SystemExit(2)

matches = [record for record in records if record["candidate_id"] == candidate_id]
if len(matches) > 1:
    raise SystemExit(2)
if matches:
    record = matches[0]
    if (record["status"], record["reason_code"]) not in {
        ("available", "available"),
        ("invalid", "output_invalid"),
    }:
        print("TERMINAL")
        print(record["status"])
        print(record["reason_code"])
        raise SystemExit(0)
    output = record["output"]
    if record["status"] == "available":
        output_fields = {
            "schema_version",
            "hypotheses",
            "supporting_evidence_ids",
            "refuting_questions",
            "narrative",
            "limitations",
        }
        supporting = output.get("supporting_evidence_ids") if isinstance(output, dict) else None
        if (
            not isinstance(output, dict)
            or set(output) != output_fields
            or output.get("schema_version") != "agmind.hunter-output.v1"
            or not bounded_strings(output.get("hypotheses"), 1_024)
            or not bounded_strings(output.get("refuting_questions"), 1_024)
            or not bounded_strings(output.get("limitations"), 1_024)
            or not isinstance(supporting, list)
            or len(supporting) > 8
            or supporting != sorted(set(supporting))
            or any(re.fullmatch(r"evt_[0-9a-f]{64}", str(value)) is None for value in supporting)
            or not isinstance(output.get("narrative"), str)
            or len(output["narrative"].encode("utf-8")) > 8_192
        ):
            raise SystemExit(2)
    bound_document = {
        "schema_version": "agmind.hunter-investigation.v1",
        "candidate_id": record["candidate_id"],
        "bundle_sha256": record["bundle_sha256"],
        "status": record["status"],
        "reason_code": record["reason_code"],
        "output": output,
    }
    canonical = json.dumps(
        bound_document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected_hash = hashlib.sha256(b"AGMIND_HUNTER_INVESTIGATION_V1\0" + canonical).hexdigest()
    if expected_hash != record["record_sha256"]:
        raise SystemExit(2)
    print("FOUND")
    print(record["bundle_sha256"])
    print(record["record_sha256"])
    print(record["status"])
    print(record["reason_code"])
    raise SystemExit(0)

if ids and candidate_id < ids[-1]:
    print("WAIT")
    print("START" if expected_after is None else expected_after)
elif document["truncated"] or len(records) == 100:
    if not ids:
        raise SystemExit(2)
    print("NEXT")
    print(ids[-1])
else:
    print("WAIT")
    next_wait = ids[-1] if ids and candidate_id > ids[-1] else expected_after
    print("START" if next_wait is None else next_wait)
PY
}

find_exact_hunter_record() {
  local timeout_seconds="$1"
  local hunter_deadline="$((SECONDS + timeout_seconds))"
  local hunter_document=""
  local hunter_page=""
  local hunter_page_status=0
  local hunter_target="/v1/hunter?limit=100"
  local expected_wait="START"
  local -a hunter_page_values=()

  if [[ -n "${hunter_after}" ]]; then
    hunter_target="/v1/hunter?after=${hunter_after}&limit=100"
    expected_wait="${hunter_after}"
  fi
  hunter_fields=""
  while ((SECONDS < hunter_deadline)); do
    hunter_document=""
    if ! hunter_document="$(core_api_get "${hunter_target}")"; then
      sleep 2
      continue
    fi
    hunter_page=""
    if hunter_page="$(hunter_page_fields "${hunter_document}" "${hunter_after}")"; then
      :
    else
      hunter_page_status="$?"
      if ((hunter_page_status == 4)); then
        block "secret_canary_leaked_to_hunter"
      fi
      block "hunter_record_invalid"
    fi
    mapfile -t hunter_page_values <<<"${hunter_page}"
    case "${hunter_page_values[0]:-}" in
      FOUND)
        if [[ "${#hunter_page_values[@]}" -ne 5 ]]; then
          block "hunter_record_invalid"
        fi
        hunter_fields="${hunter_page_values[1]}"$'\n'"${hunter_page_values[2]}"$'\n'"${hunter_page_values[3]}"$'\n'"${hunter_page_values[4]}"
        return 0
        ;;
      WAIT)
        if [[ "${#hunter_page_values[@]}" -ne 2 ||
          "${hunter_page_values[1]}" != "${expected_wait}" ]]; then
          block "hunter_cursor_invariant_failed"
        fi
        ;;
      NEXT)
        block "hunter_cursor_invariant_failed"
        ;;
      TERMINAL)
        block "hunter_result_not_available"
        ;;
      *)
        block "hunter_page_invalid"
        ;;
    esac
    sleep 2
  done
  block "hunter_result_timeout"
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
if ! host_pcc_table_absent || ! target_pcc_table_absent; then
  block "preapproval_namespace_mutated"
fi
host_ruleset_before_approval=""
if ! host_ruleset_before_approval="$(host_ruleset_digest)" ||
  [[ "${host_ruleset_before_approval}" != "${host_ruleset_after_lab_setup}" ]]; then
  block "host_ruleset_changed_before_approval"
fi

printf 'AGmind smoke will request interactive approval for %s.\n' "${plan_id}"
approval_output=""
if ! approval_output="$(agmindctl proposal approve "${plan_id}" | tee /dev/fd/3)"; then
  block "interactive_approval_not_completed"
fi
approval_fields=""
if ! approval_fields="$(python3 - "${approval_output}" <<'PY'
import re
import sys

output = sys.argv[1]
pattern = re.compile(
    r"Decision: APPROVED\n"
    r"Action ID: (act_[0-9a-f]{32})\n"
    r"Record ID: (ar_[0-9a-f]{32})\n?\Z"
)
match = pattern.search(output)
if (
    match is None
    or output.count("Decision: ") != 1
    or output.count("Action ID: ") != 1
    or output.count("Record ID: ") != 1
):
    raise SystemExit(1)
print(match.group(1))
print(match.group(2))
PY
)"; then
  block "approval_receipt_invalid"
fi
mapfile -t approval_values <<<"${approval_fields}"
if [[ "${#approval_values[@]}" -ne 2 ]]; then
  block "approval_receipt_invalid"
fi
action_id="${approval_values[0]}"
approval_record_id="${approval_values[1]}"
if [[ ! "${action_id}" =~ ^act_[0-9a-f]{32}$ ||
  ! "${approval_record_id}" =~ ^ar_[0-9a-f]{32}$ ]]; then
  block "approval_receipt_invalid"
fi
approval_output=""
approval_fields=""
exec 3>&-

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
host_ruleset_during_containment=""
if ! host_ruleset_during_containment="$(host_ruleset_digest)" ||
  [[ "${host_ruleset_during_containment}" != "${host_ruleset_after_lab_setup}" ]]; then
  block "host_ruleset_changed_during_containment"
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
if ! nft_state="$(nft_set_state)" || [[ "${nft_state}" != "PRESENT" ]]; then
  block "containment_did_not_survive_control_plane_stop"
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
restored_ready=0
restored_ready_deadline="$((SECONDS + 30))"
while ((SECONDS < restored_ready_deadline)); do
  ready_report=""
  if ready_report="$(curl --fail --silent --show-error --noproxy '*' --max-time 2 \
    http://127.0.0.1:8787/ready 2>/dev/null)" &&
    core_ready_document "${ready_report}"; then
    restored_ready=1
    break
  fi
  sleep 1
done
if ((restored_ready != 1)); then
  block "core_not_ready_after_restore"
fi

# Wait for the recovered Core to mirror the exact signed terminal record.
action_fields=""
action_deadline="$((SECONDS + 90))"
while ((SECONDS < action_deadline)); do
  action_document=""
  if action_document="$(core_api_get "/v1/actions/${action_id}")"; then
    if action_fields="$(expired_action_fields "${action_document}")"; then
      break
    else
      action_parse_status="$?"
      if ((action_parse_status != 1)); then
        block "expired_action_record_invalid"
      fi
    fi
  fi
  sleep 2
done
mapfile -t action_values <<<"${action_fields}"
if [[ "${#action_values[@]}" -ne 3 ]]; then
  block "expired_action_mirror_timeout"
fi
action_record_id="${action_values[0]}"
action_record_sha256="${action_values[1]}"
transition_basis="${action_values[2]}"

status_fields=""
status_deadline="$((SECONDS + 30))"
while ((SECONDS < status_deadline)); do
  status_document=""
  if status_document="$(core_api_get "/v1/status")"; then
    if status_fields="$(core_status_fields "${status_document}")"; then
      break
    else
      status_parse_status="$?"
      if ((status_parse_status != 1)); then
        block "core_status_invalid"
      fi
    fi
  fi
  sleep 2
done
mapfile -t status_values <<<"${status_fields}"
if [[ "${#status_values[@]}" -ne 3 || "${status_values[0]}" != "verified" ]]; then
  block "actuator_feedback_not_verified"
fi

# Export and independently verify the exact action proof while the target still
# exists. The exporter owns quiescing; the outer trap remains a recovery guard.
if [[ -L "${proof_export_root}" ]]; then
  block "proof_export_root_unsafe"
fi
if ! install -d -o root -g root -m 0700 "${proof_export_root}"; then
  block "proof_export_root_unavailable"
fi
if [[ "$(stat -Lc '%u:%g:%a' -- "${proof_export_root}")" != "0:0:700" ]]; then
  block "proof_export_root_unsafe"
fi
proof_output="${proof_export_root}/${action_id}"
if [[ -e "${proof_output}" || -L "${proof_output}" ]]; then
  block "proof_output_already_exists"
fi
proof_export_output=""
services_need_restore=1
if ! proof_export_output="$(
  "${script_dir}/export-proof-linux.sh" \
    --action-id "${action_id}" \
    --output "${proof_output}"
)"; then
  block "proof_export_failed"
fi
services_need_restore=0
proof_fields=""
if ! proof_fields="$(PROOF_EXPORT_OUTPUT="${proof_export_output}" python3 - "${proof_output}" <<'PY'
import os
import re
import sys

lines = os.environ.get("PROOF_EXPORT_OUTPUT", "").splitlines()
if len(lines) < 5:
    raise SystemExit(1)
final = lines[-5:]
if final[0] != "bundle_path=" + sys.argv[1]:
    raise SystemExit(1)
patterns = (
    r"bundle_sha256=([0-9a-f]{64})",
    r"candidate_id=(cand_[0-9a-f]{64})",
    r"intent_id=(int_[0-9a-f]{32})",
)
values = []
for line, pattern in zip(final[1:4], patterns, strict=True):
    match = re.fullmatch(pattern, line)
    if match is None:
        raise SystemExit(1)
    values.append(match.group(1))
if final[4] != "action_state=EXPIRED":
    raise SystemExit(1)
print(sys.argv[1])
print(*values, sep="\n")
PY
)"; then
  block "proof_export_receipt_invalid"
fi
mapfile -t proof_values <<<"${proof_fields}"
if [[ "${#proof_values[@]}" -ne 4 ]]; then
  block "proof_export_receipt_invalid"
fi
proof_path="${proof_values[0]}"
proof_bundle_sha256="${proof_values[1]}"
candidate_id="${proof_values[2]}"
intent_id="${proof_values[3]}"
proof_export_output=""
proof_fields=""

# Search the complete exported artifact as bytes. The canary is passed only in
# the scanner environment and is never rendered in argv, logs, or PASS JSON.
if ! AGMIND_SECRET_CANARY="${secret_canary}" python3 - "${proof_path}" <<'PY'
import os
import stat
import sys

root = sys.argv[1]
needle = os.environ.get("AGMIND_SECRET_CANARY", "").encode("ascii", "strict")
if not needle or os.path.islink(root) or not os.path.isdir(root):
    raise SystemExit(1)
for directory, directories, files in os.walk(root, followlinks=False):
    relative = os.path.relpath(directory, root).encode(errors="surrogateescape")
    if needle in relative:
        raise SystemExit(1)
    for name in directories:
        path = os.path.join(directory, name)
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SystemExit(1)
        if needle in os.fsencode(name):
            raise SystemExit(1)
    for name in files:
        path = os.path.join(directory, name)
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise SystemExit(1)
        if needle in os.fsencode(name):
            raise SystemExit(1)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            tail = b""
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                combined = tail + chunk
                if needle in combined:
                    raise SystemExit(1)
                tail = combined[-(len(needle) - 1):] if len(needle) > 1 else b""
        finally:
            os.close(descriptor)
PY
then
  block "secret_canary_leaked_to_proof"
fi
if ! canary_sha256="$(AGMIND_SECRET_CANARY="${secret_canary}" python3 - <<'PY'
import hashlib
import os

value = os.environ.get("AGMIND_SECRET_CANARY", "").encode("ascii", "strict")
if not value:
    raise SystemExit(1)
print(hashlib.sha256(value).hexdigest())
PY
)" || [[ ! "${canary_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
  block "secret_canary_digest_failed"
fi

# Locate the exact proof-derived candidate without walking an unrelated store:
# the fixed-width hexadecimal predecessor is the adjacent lexicographic cursor.
hunter_after=""
if ! hunter_after="$(python3 - "${candidate_id}" <<'PY'
import re
import sys

match = re.fullmatch(r"cand_([0-9a-f]{64})", sys.argv[1])
if match is None:
    raise SystemExit(1)
value = int(match.group(1), 16)
if value > 0:
    print(f"cand_{value - 1:064x}")
PY
)"; then
  block "hunter_cursor_invalid"
fi

# First wait for a terminal record and recompute its canonical hash. The proof
# exporter restarted Core before this lookup, but recovery could have persisted
# the record after that restart, so this first read alone is not durability
# evidence.
hunter_fields=""
find_exact_hunter_record 120
hunter_fields_before_restart="${hunter_fields}"

# Force one additional Core stop/start only after the exact record exists, then
# require the reopened SQLite store to return the identical canonical record.
services_need_restore=1
if ! systemctl restart agmind-core-compose.service; then
  block "core_restart_for_hunter_durability_failed"
fi
if ! systemctl is-active --quiet agmind-core-compose.service; then
  block "core_restart_for_hunter_durability_failed"
fi
hunter_restart_ready=0
hunter_restart_deadline="$((SECONDS + 30))"
while ((SECONDS < hunter_restart_deadline)); do
  ready_report=""
  if ready_report="$(curl --fail --silent --show-error --noproxy '*' --max-time 2 \
    http://127.0.0.1:8787/ready 2>/dev/null)" &&
    core_ready_document "${ready_report}"; then
    hunter_restart_ready=1
    break
  fi
  sleep 1
done
if ((hunter_restart_ready != 1)); then
  block "core_not_ready_after_hunter_restart"
fi
services_need_restore=0

find_exact_hunter_record 60
if [[ "${hunter_fields}" != "${hunter_fields_before_restart}" ]]; then
  block "hunter_record_changed_after_restart"
fi
mapfile -t hunter_values <<<"${hunter_fields}"
if [[ "${#hunter_values[@]}" -ne 4 ]]; then
  block "hunter_record_invalid"
fi
hunter_bundle_sha256="${hunter_values[0]}"
hunter_record_sha256="${hunter_values[1]}"
hunter_status="${hunter_values[2]}"
hunter_reason_code="${hunter_values[3]}"

# `/v1/hunter` is served directly from the reopened SQLite investigation
# store. Equality across the explicit second restart, including the recomputed
# canonical record hash, is the durable-after-restart proof.

trap - EXIT INT TERM HUP
if ! cleanup_resources; then
  printf '%s\n' '{"reason_code":"exact_cleanup_failed","schema_version":"agmind.smoke-containment.v1","status":"BLOCKED"}' >&2
  exit 70
fi
secret_canary=""
python3 - \
  "${destination_ipv4}" "${plan_id}" "${action_id}" "${approval_record_id}" \
  "${action_record_id}" "${action_record_sha256}" "${transition_basis}" \
  "${candidate_id}" "${intent_id}" "${container_id}" "${ttl_seconds}" \
  "${proof_path}" "${proof_bundle_sha256}" "${hunter_bundle_sha256}" \
  "${hunter_record_sha256}" "${hunter_status}" "${hunter_reason_code}" \
  "${canary_sha256}" <<'PY'
import json
import sys

document = {
    "schema_version": "agmind.smoke-containment.v1",
    "status": "PASS",
    "destination_ipv4": sys.argv[1],
    "plan_id": sys.argv[2],
    "action_id": sys.argv[3],
    "approval_record_id": sys.argv[4],
    "action_record_id": sys.argv[5],
    "action_record_sha256": sys.argv[6],
    "transition_basis": sys.argv[7],
    "candidate_id": sys.argv[8],
    "intent_id": sys.argv[9],
    "target_container_id": sys.argv[10],
    "ttl_seconds": int(sys.argv[11]),
    "action_state": "EXPIRED",
    "actuator_feedback_status": "verified",
    "proof_path": sys.argv[12],
    "proof_bundle_sha256": sys.argv[13],
    "hunter_model": "dspark",
    "hunter_status": sys.argv[16],
    "hunter_reason_code": sys.argv[17],
    "hunter_bundle_sha256": sys.argv[14],
    "hunter_record_sha256": sys.argv[15],
    "hunter_persistence_status": "durable",
    "canary_sha256": sys.argv[18],
    "secret_canary_absent": True,
}
print(json.dumps(document, sort_keys=True, separators=(",", ":")))
PY
