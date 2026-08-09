#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly docker_endpoint="unix:///var/run/docker.sock"
readonly docker_config="/run/agmind-sais/docker-config"
readonly runtime_env="/etc/agmind-sais/runtime.env"
readonly evidence_root="/var/lib/agmind-sais/core/evidence"
readonly actuator_journal="/var/lib/agmind-sais/actuator/actions.agf"
readonly core_mirror="/var/lib/agmind-sais/core/actuator-actions.agf"
readonly observer_root="/etc/agmind-sais/observer-trust-root.json"
readonly observer_public_keys="/var/lib/agmind-sais/observer/observer-public-keys.json"
readonly actuator_public_key="/etc/agmind-sais/public/actuator-ed25519.pub"
readonly policy_file="/usr/share/agmind-sais/pcc.rego"
readonly detector_file="/etc/falco/rules.d/agmind-pcc.yaml"
readonly registry_file="/usr/share/agmind-sais/ipv4-special-use.csv"
readonly management_denylist="/etc/agmind-sais/management-destinations.json"

readonly -a quiesce_order=(
  agmind-core-compose.service
  agmind-actuatord.service
  agmind-observerd.service
)
readonly -a restore_order=(
  agmind-observerd.service
  agmind-actuatord.service
  agmind-core-compose.service
)

declare -A was_active=()
recovery_armed=0
staging_dir=""
scratch_dir=""

usage() {
  cat <<'EOF'
Usage:
  sudo /opt/agmind-sais/scripts/export-proof-linux.sh \
    --action-id act_<32hex> --output /absolute/new-dir
EOF
}

die() {
  printf 'export-proof-linux.sh: %s\n' "$*" >&2
  exit 1
}

status() {
  printf '[agmind-proof-export] %s\n' "$*" >&2
}

restore_units() {
  local failed=0
  local unit

  ((recovery_armed == 1)) || return 0
  status "restoring units that were active before the snapshot"
  for unit in "${restore_order[@]}"; do
    if [[ "${was_active[$unit]:-0}" == "1" ]]; then
      if ! systemctl start "$unit"; then
        printf 'export-proof-linux.sh: recovery start failed: %s\n' "$unit" >&2
        failed=1
        continue
      fi
      if ! systemctl is-active --quiet "$unit"; then
        printf 'export-proof-linux.sh: recovery readiness failed: %s\n' "$unit" >&2
        failed=1
      fi
    fi
  done
  return "$failed"
}

on_exit() {
  local exit_code="$?"
  local recovery_failed=0

  trap - EXIT INT TERM HUP
  set +e
  if ! restore_units; then
    recovery_failed=1
    printf '%s\n' \
      'export-proof-linux.sh: RECOVERY FAILURE: one or more previously active AGmind units were not restored' >&2
  fi
  if [[ -n "$staging_dir" && -d "$staging_dir/bundle" &&
        ! -e "$output" && ! -L "$output" ]]; then
    if mv -- "$staging_dir/bundle" "$output"; then
      printf 'export-proof-linux.sh: preserved incomplete bundle at %s\n' "$output" >&2
      rmdir -- "$staging_dir" 2>/dev/null || true
      staging_dir=""
    fi
  fi
  if [[ -n "$scratch_dir" && -d "$scratch_dir" ]]; then
    rmdir -- "$scratch_dir" 2>/dev/null ||
      printf 'export-proof-linux.sh: verifier scratch retained at %s\n' "$scratch_dir" >&2
  fi
  if [[ -n "$staging_dir" && -d "$staging_dir" ]]; then
    printf 'export-proof-linux.sh: export staging retained at %s\n' "$staging_dir" >&2
  fi
  if ((recovery_failed == 1)); then
    exit 70
  fi
  exit "$exit_code"
}

trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

action_id=""
output=""
seen_action=0
seen_output=0

while (($# > 0)); do
  case "$1" in
    -h|--help)
      (($# == 1)) || die "--help cannot be combined with other arguments"
      usage
      exit 0
      ;;
    --action-id)
      (($# >= 2)) || die "--action-id requires a value"
      ((seen_action == 0)) || die "--action-id may be specified only once"
      action_id="$2"
      seen_action=1
      shift 2
      ;;
    --output)
      (($# >= 2)) || die "--output requires a value"
      ((seen_output == 0)) || die "--output may be specified only once"
      output="$2"
      seen_output=1
      shift 2
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

((seen_action == 1)) || die "--action-id is required"
((seen_output == 1)) || die "--output is required"

[[ "$(uname -s)" == "Linux" ]] || die "Linux is required"
((EUID == 0)) || die "EUID 0 is required"
[[ "$action_id" =~ ^act_[0-9a-f]{32}$ ]] ||
  die "--action-id must be exactly act_<32 lowercase hex>"

for command_name in docker mktemp mv python3 realpath rmdir stat systemctl uname; do
  command -v "$command_name" >/dev/null 2>&1 ||
    die "required command unavailable: $command_name"
done
[[ "$(command -v docker)" == "/usr/bin/docker" && -x /usr/bin/docker ]] ||
  die "the installed runtime requires Docker CLI at /usr/bin/docker"
[[ -S /var/run/docker.sock ]] || die "Docker socket is unavailable"
systemctl is-active --quiet docker.service || die "docker.service is not active"

[[ "$output" == /* && "$output" != "/" ]] ||
  die "--output must be an absolute new directory"
[[ "$output" != *$'\n'* && "$output" != *$'\r'* ]] ||
  die "--output contains a control character"
[[ "$output" == "$(realpath --canonicalize-missing -- "$output")" ]] ||
  die "--output must be a canonical absolute path without symlink traversal"
[[ ! -e "$output" && ! -L "$output" ]] || die "--output must not exist"

output_parent="${output%/*}"
[[ -n "$output_parent" ]] || output_parent="/"
output_name="${output##*/}"
[[ "$output_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
  die "the output directory name must be 1-128 safe ASCII characters"
[[ "$output_parent" != *","* ]] || die "the output parent cannot contain a comma"
[[ -d "$output_parent" && ! -L "$output_parent" ]] ||
  die "the output parent must be an existing non-symlink directory"
[[ "$output_parent" == "$(realpath --canonicalize-existing -- "$output_parent")" ]] ||
  die "the output parent must not traverse symlinks"
parent_metadata="$(stat -Lc '%u:%a' -- "$output_parent")"
parent_uid="${parent_metadata%%:*}"
parent_mode="${parent_metadata#*:}"
[[ "$parent_uid" == "0" && "$parent_mode" =~ ^[0-7]{3,4}$ ]] ||
  die "the output parent must be root-owned"
(((8#$parent_mode & 8#022) == 0)) ||
  die "the output parent must not be group/world writable"

required_directories=("$evidence_root" "$docker_config")
required_files=(
  "$runtime_env"
  "$actuator_journal"
  "$observer_root"
  "$observer_public_keys"
  "$actuator_public_key"
  "$policy_file"
  "$detector_file"
  "$registry_file"
  "$management_denylist"
)
for required_directory in "${required_directories[@]}"; do
  [[ -d "$required_directory" && ! -L "$required_directory" ]] ||
    die "required installed directory is missing or unsafe: $required_directory"
done
for required_file in "${required_files[@]}"; do
  [[ -f "$required_file" && ! -L "$required_file" ]] ||
    die "required installed file is missing or unsafe: $required_file"
  [[ "$(stat -Lc '%h' -- "$required_file")" == "1" ]] ||
    die "required installed file has multiple links: $required_file"
done
if [[ -e "$core_mirror" || -L "$core_mirror" ]]; then
  [[ -f "$core_mirror" && ! -L "$core_mirror" ]] ||
    die "optional Core mirror exists but is unsafe: $core_mirror"
  [[ "$(stat -Lc '%h' -- "$core_mirror")" == "1" ]] ||
    die "optional Core mirror has multiple links"
  have_core_mirror=1
else
  have_core_mirror=0
fi

for source_path in "${required_directories[@]}" "${required_files[@]}"; do
  if [[ "$output_parent" == "$source_path" ||
        "$output_parent" == "$source_path"/* ||
        "$source_path" == "$output_parent"/* ]]; then
    die "the output parent must not overlap a trusted source: $source_path"
  fi
done
if ((have_core_mirror == 1)); then
  if [[ "$output_parent" == "$core_mirror" ||
        "$output_parent" == "$core_mirror"/* ||
        "$core_mirror" == "$output_parent"/* ]]; then
    die "the output parent must not overlap the Core mirror"
  fi
fi

for unit in "${quiesce_order[@]}"; do
  unit_load_state="$(systemctl show --property=LoadState --value "$unit")"
  [[ "$unit_load_state" == "loaded" ]] || die "required unit is not loaded: $unit"
done

core_image=""
core_image_count=0
while IFS= read -r runtime_line || [[ -n "$runtime_line" ]]; do
  case "$runtime_line" in
    AGMIND_CORE_IMAGE=*)
      core_image="${runtime_line#AGMIND_CORE_IMAGE=}"
      ((core_image_count += 1))
      ;;
  esac
done <"$runtime_env"
((core_image_count == 1)) || die "runtime.env must contain exactly one AGMIND_CORE_IMAGE"
[[ "$core_image" =~ ^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}$ ]] ||
  die "AGMIND_CORE_IMAGE is malformed"

docker_fixed() {
  DOCKER_CONFIG="$docker_config" /usr/bin/docker --host "$docker_endpoint" "$@"
}

docker_fixed info >/dev/null || die "Docker Engine is unavailable"
core_image_id="$(docker_fixed image inspect --format '{{.Id}}' "$core_image" 2>/dev/null || true)"
[[ "$core_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  die "the installed Core image is not present locally: $core_image"

staging_dir="$(mktemp -d -p "$output_parent" .agmind-proof-export.XXXXXXXX)" ||
  die "cannot create isolated export staging"
scratch_dir="$(mktemp -d -p "$output_parent" .agmind-proof-verify.XXXXXXXX)" ||
  die "cannot create isolated verifier scratch"
for private_directory in "$staging_dir" "$scratch_dir"; do
  private_metadata="$(stat -Lc '%u:%a' -- "$private_directory")"
  [[ "$private_metadata" == "0:700" && ! -L "$private_directory" ]] ||
    die "temporary proof workspace is not root-owned mode 0700"
done

for unit in "${quiesce_order[@]}"; do
  unit_state="$(systemctl show --property=ActiveState --value "$unit")"
  case "$unit_state" in
    active)
      was_active["$unit"]=1
      ;;
    inactive|failed)
      was_active["$unit"]=0
      ;;
    *)
      die "unit is in a transitional or unsupported state: $unit ($unit_state)"
      ;;
  esac
  status "pre-snapshot unit=$unit active=${was_active[$unit]}"
done
if [[ "${was_active[agmind-core-compose.service]}" == "1" &&
      ( "${was_active[agmind-actuatord.service]}" != "1" ||
        "${was_active[agmind-observerd.service]}" != "1" ) ]]; then
  die "active Core has inactive required host dependencies"
fi
if [[ "${was_active[agmind-actuatord.service]}" == "1" &&
      "${was_active[agmind-observerd.service]}" != "1" ]]; then
  die "active actuator has an inactive observer dependency"
fi

recovery_armed=1
status "quiescing Core, actuator, then observer without touching Docker or nftables"
for unit in "${quiesce_order[@]}"; do
  systemctl stop "$unit" || die "failed to stop unit: $unit"
  if systemctl is-active --quiet "$unit"; then
    die "unit remained active after stop: $unit"
  fi
done

common_run=(
  run --rm
  --pull never
  --network none
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges:true
  --user 0:0
  --pids-limit 128
  --memory 1g
  --cpus 1
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m
  --workdir /app
  --entrypoint /opt/venv/bin/python
)
export_mounts=(
  --cap-add DAC_READ_SEARCH
  --mount "type=bind,src=$evidence_root,dst=$evidence_root,readonly"
  --mount "type=bind,src=$actuator_journal,dst=$actuator_journal,readonly"
  --mount "type=bind,src=$observer_root,dst=$observer_root,readonly"
  --mount "type=bind,src=$observer_public_keys,dst=$observer_public_keys,readonly"
  --mount "type=bind,src=$actuator_public_key,dst=$actuator_public_key,readonly"
  --mount "type=bind,src=$policy_file,dst=$policy_file,readonly"
  --mount "type=bind,src=$detector_file,dst=$detector_file,readonly"
  --mount "type=bind,src=$registry_file,dst=$registry_file,readonly"
  --mount "type=bind,src=$management_denylist,dst=$management_denylist,readonly"
  --mount "type=bind,src=$staging_dir,dst=/proof-output"
)
export_arguments=(
  -m agmind_immune.proof export-quiesced
  --action-id "$action_id"
  --output "/proof-output/bundle"
  --evidence "$evidence_root"
  --actuator-journal "$actuator_journal"
  --observer-root "$observer_root"
  --observer-public-keys "$observer_public_keys"
  --actuator-public-key "$actuator_public_key"
  --policy "$policy_file"
  --detector "$detector_file"
  --registry "$registry_file"
  --management-denylist "$management_denylist"
)
if ((have_core_mirror == 1)); then
  export_mounts+=(--mount "type=bind,src=$core_mirror,dst=$core_mirror,readonly")
  export_arguments+=(--core-mirror "$core_mirror")
fi

status "exporting a quiesced proof bundle for $action_id"
docker_fixed "${common_run[@]}" "${export_mounts[@]}" \
  "$core_image" "${export_arguments[@]}"

[[ -d "$staging_dir/bundle" && ! -L "$staging_dir/bundle" ]] ||
  die "exporter did not create the isolated bundle directory"

status "verifying the exported bundle against external host trust pins"
verify_report="$(
  docker_fixed "${common_run[@]}" \
    --env TMPDIR=/proof-work \
    --mount "type=bind,src=$staging_dir/bundle,dst=/proof-bundle,readonly" \
    --mount "type=bind,src=$scratch_dir,dst=/proof-work" \
    --mount "type=bind,src=$observer_root,dst=$observer_root,readonly" \
    --mount "type=bind,src=$actuator_public_key,dst=$actuator_public_key,readonly" \
    "$core_image" \
    -m agmind_immune.replay verify-export /proof-bundle \
    --observer-root "$observer_root" \
    --actuator-public-key "$actuator_public_key"
)" || die "offline proof verification failed"

bundle_sha256="$(python3 - "$verify_report" <<'PY'
from __future__ import annotations

import json
import re
import sys


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


try:
    report = json.loads(sys.argv[1], object_pairs_hook=reject_duplicates)
except (IndexError, json.JSONDecodeError, ValueError) as error:
    raise SystemExit(f"invalid verifier JSON: {error}")
if not isinstance(report, dict):
    raise SystemExit("verifier report is not an object")
if report.get("integrity_verified") is not True:
    raise SystemExit("verifier did not prove integrity")
if report.get("causal_links_verified") is not True:
    raise SystemExit("verifier did not prove causal links")
digest = report.get("bundle_sha256")
if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit("verifier returned an invalid bundle_sha256")
print(digest)
PY
)" || die "verifier report did not satisfy the proof contract"

mv -- "$staging_dir/bundle" "$output" || die "cannot publish verified bundle"
rmdir -- "$staging_dir" || die "isolated export staging is not empty"
staging_dir=""
rmdir -- "$scratch_dir" || die "isolated verifier scratch is not empty"
scratch_dir=""

if ! restore_units; then
  die "failed to restore one or more previously active AGmind units"
fi
recovery_armed=0

printf 'bundle_path=%s\n' "$output"
printf 'bundle_sha256=%s\n' "$bundle_sha256"
