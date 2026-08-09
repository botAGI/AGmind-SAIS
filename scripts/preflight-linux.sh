#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
python_bin="$(command -v python3 || true)"
if [[ -z "${python_bin}" ]]; then
  printf '%s\n' '{"active_containment_supported":false,"hard_failures":["python3_unavailable"],"schema_version":"agmind.preflight.v1"}'
  exit 1
fi

exec "${python_bin}" - "${script_dir}/../deploy/versions.env" "$@" <<'PY'
from __future__ import annotations

import argparse
import glob
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


def command(
    argv: list[str],
    timeout: float = 8.0,
    *,
    remove_env: tuple[str, ...] = (),
) -> tuple[int, str]:
    child_env = {**os.environ, "LC_ALL": "C"}
    for key in remove_env:
        child_env.pop(key, None)
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=child_env,
        )
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    return result.returncode, result.stdout.strip()


def version_tuple(value: str) -> tuple[int, int, int] | None:
    head = value.split("-", 1)[0]
    parts = head.split(".")
    if len(parts) < 2:
        return None
    try:
        numbers = tuple(int(item) for item in parts[:3])
    except ValueError:
        return None
    return numbers + (0,) * (3 - len(numbers))


def load_versions(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError:
        return values
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.replace("_", "").isalnum() and key.upper() == key:
            values[key] = value
    return values


def load_runtime_env(path: Path) -> tuple[dict[str, str], bool]:
    values: dict[str, str] = {}
    try:
        info = path.lstat()
    except OSError:
        return values, False
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_size > 1024 * 1024
    ):
        return values, False
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return values, False
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            return {}, False
        key, value = line.split("=", 1)
        if (
            not key
            or key in values
            or key.upper() != key
            or not key[0].isalpha()
            or not key.replace("_", "").isalnum()
            or value != value.strip()
            or any(ord(character) < 0x20 for character in value)
        ):
            return {}, False
        values[key] = value
    return values, True


def sha256_regular_file(path: Path, max_bytes: int = 16 * 1024 * 1024) -> str | None:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            return None
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as source:
            while chunk := source.read(128 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    return None
                digest.update(chunk)
        after = path.lstat()
    except OSError:
        return None
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        return None
    return digest.hexdigest()


def load_json_object(path: Path) -> tuple[dict[str, object], bool]:
    try:
        info = path.lstat()
    except OSError:
        return {}, False
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_size > 1024 * 1024
    ):
        return {}, False
    try:
        raw = path.read_bytes()
    except OSError:
        return {}, False
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}, False
    return (value, True) if isinstance(value, dict) else ({}, False)


parser = argparse.ArgumentParser(description="Read-only AGmind-SAIS Linux preflight")
parser.add_argument("--dgx-url", default=None, help="fixed DeepSeek /v1 endpoint")
parser.add_argument(
    "--runtime-env",
    type=Path,
    default=None,
    help="root-owned Compose runtime.env paired with --dgx-url",
)
parser.add_argument(
    "--management-denylist",
    type=Path,
    default=None,
    help="root-owned management destination JSON paired with --dgx-url",
)
arguments = parser.parse_args(sys.argv[2:])
versions_path = Path(sys.argv[1]).resolve()
versions = load_versions(versions_path)
repo_root = versions_path.parent.parent

hard: set[str] = set()
degraded: set[str] = set()
facts: dict[str, object] = {}


def require(condition: bool, reason: str) -> None:
    if not condition:
        hard.add(reason)


asset_specs = {
    "actuator_config": ("ACTUATOR_CONFIG_SHA256", "deploy/config/actuator.json"),
    "core_config": ("CORE_CONFIG_SHA256", "deploy/config/core.json"),
    "dgx_relay_config": ("DGX_RELAY_CONFIG_SHA256", "deploy/config/dgx-relay.cfg"),
    "falco_config": ("FALCO_CONFIG_SHA256", "deploy/falco/falco.yaml"),
    "falco_rules": ("FALCO_RULES_SHA256", "deploy/falco/rules.d/agmind-pcc.yaml"),
    "hunter_config": ("HUNTER_CONFIG_SHA256", "deploy/config/hunter.json"),
    "ipv4_special_use": ("IPV4_SPECIAL_USE_SHA256", "contracts/v1/ipv4-special-use.csv"),
    "observer_config": ("OBSERVER_CONFIG_SHA256", "deploy/config/observer.json"),
    "operator_denylist": (
        "OPERATOR_DENYLIST_SHA256",
        "deploy/config/operator-denylist.json",
    ),
    "pcc_policy": ("PCC_POLICY_SHA256", "policies/pcc.rego"),
}
asset_hashes: dict[str, str] = {}
invalid_assets: list[str] = []
for asset_name, (version_key, relative_path) in asset_specs.items():
    expected_hash = versions.get(version_key, "")
    actual_hash = sha256_regular_file(repo_root / relative_path)
    if actual_hash is not None:
        asset_hashes[asset_name] = actual_hash
    if (
        len(expected_hash) != 64
        or any(character not in "0123456789abcdef" for character in expected_hash)
        or actual_hash != expected_hash
    ):
        invalid_assets.append(asset_name)
facts["pinned_asset_sha256"] = asset_hashes
facts["invalid_pinned_assets"] = sorted(invalid_assets)
require(not invalid_assets, "pinned_asset_hash_mismatch")

installed_asset_specs = {
    "actuator_config": ("ACTUATOR_CONFIG_SHA256", "/etc/agmind-sais/actuator.json"),
    "core_config": ("CORE_CONFIG_SHA256", "/etc/agmind-sais/core.json"),
    "falco_rules": (
        "FALCO_RULES_SHA256",
        "/etc/falco/rules.d/agmind-pcc.yaml",
    ),
    "hunter_config": ("HUNTER_CONFIG_SHA256", "/etc/agmind-sais/hunter.json"),
    "ipv4_special_use": (
        "IPV4_SPECIAL_USE_SHA256",
        "/usr/share/agmind-sais/ipv4-special-use.csv",
    ),
    "observer_config": ("OBSERVER_CONFIG_SHA256", "/etc/agmind-sais/observer.json"),
    "operator_denylist": (
        "OPERATOR_DENYLIST_SHA256",
        "/etc/agmind-sais/operator-denylist.json",
    ),
}
invalid_installed_assets: list[str] = []
for asset_name, (version_key, absolute_path) in installed_asset_specs.items():
    if sha256_regular_file(Path(absolute_path)) != versions.get(version_key, ""):
        invalid_installed_assets.append(asset_name)
facts["invalid_installed_assets"] = sorted(invalid_installed_assets)
require(not invalid_installed_assets, "installed_asset_hash_mismatch")

dgx_inputs = (
    arguments.dgx_url is not None,
    arguments.runtime_env is not None,
    arguments.management_denylist is not None,
)
require(not any(dgx_inputs) or all(dgx_inputs), "dgx_inputs_incomplete")

runtime_values: dict[str, str] = {}
runtime_env_valid = arguments.runtime_env is None
if arguments.runtime_env is not None:
    runtime_values, runtime_env_valid = load_runtime_env(arguments.runtime_env)
require(runtime_env_valid, "runtime_env_invalid")

is_linux = sys.platform.startswith("linux")
facts["platform"] = sys.platform
require(is_linux, "not_linux")
require(os.geteuid() == 0, "root_required")

kernel = platform.release()
facts["kernel_release"] = kernel
parsed_kernel = version_tuple(kernel)
require(parsed_kernel is not None and parsed_kernel >= (5, 8, 0), "kernel_too_old")

pid1 = ""
try:
    pid1 = Path("/proc/1/comm").read_text(encoding="ascii").strip()
except OSError:
    pass
facts["pid1"] = pid1
require(pid1 == "systemd", "pid1_not_systemd")

cgroup_controllers = Path("/sys/fs/cgroup/cgroup.controllers")
require(cgroup_controllers.is_file(), "cgroup_v2_unavailable")
require(os.access(cgroup_controllers, os.R_OK), "cgroup_v2_unreadable")
require(os.access("/sys/kernel/btf/vmlinux", os.R_OK), "kernel_btf_unavailable")

mount_text = ""
try:
    mount_text = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
except OSError:
    pass
tracefs_mounted = any(
    " - tracefs " in line and " /sys/kernel/tracing " in line
    for line in mount_text.splitlines()
)
require(tracefs_mounted and os.access("/sys/kernel/tracing", os.R_OK), "tracefs_unavailable")

for proc_path, reason in (
    ("/proc/self/stat", "proc_stat_unavailable"),
    ("/proc/self/cgroup", "proc_cgroup_unavailable"),
    ("/proc/self/ns/net", "proc_netns_unavailable"),
):
    require(os.access(proc_path, os.R_OK), reason)

bpftool_status, _ = command(["bpftool", "feature", "probe", "kernel"], timeout=15.0)
require(bpftool_status == 0, "modern_ebpf_preflight_failed")
nft_status, _ = command(["nft", "--json", "list", "ruleset"], timeout=10.0)
require(nft_status == 0, "nftables_preflight_failed")

memory_kib = 0
try:
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemTotal:"):
            memory_kib = int(line.split()[1])
            break
except (OSError, ValueError):
    pass
facts["memory_bytes"] = memory_kib * 1024
require(memory_kib >= 8 * 1024 * 1024, "host_memory_below_8gib")

disk_probe = Path("/var/lib/agmind-sais")
while not disk_probe.exists() and disk_probe != disk_probe.parent:
    disk_probe = disk_probe.parent
try:
    free_bytes = shutil.disk_usage(disk_probe).free
except OSError:
    free_bytes = 0
facts["evidence_filesystem_free_bytes"] = free_bytes
require(free_bytes >= 10 * 1024**3, "evidence_filesystem_below_10gib")

docker_binary = shutil.which("docker")
require(docker_binary is not None, "docker_cli_unavailable")
docker_endpoint = "unix:///var/run/docker.sock"
docker_host = os.environ.get("DOCKER_HOST", "")
docker_context_env = os.environ.get("DOCKER_CONTEXT", "")
facts["docker_endpoint"] = docker_endpoint
require(docker_host in {"", docker_endpoint}, "docker_host_not_fixed_rootful_socket")
require(docker_context_env in {"", "default"}, "docker_context_not_default")

current_context = ""
if docker_binary is not None:
    context_status, current_context = command(
        [docker_binary, "context", "show"],
        remove_env=("DOCKER_HOST", "DOCKER_CONTEXT"),
    )
else:
    context_status = 127
facts["docker_current_context"] = current_context
require(context_status == 0 and current_context == "default", "docker_context_not_default")


def docker_command(argv: list[str], timeout: float = 8.0) -> tuple[int, str]:
    if docker_binary is None:
        return 127, ""
    return command(
        [docker_binary, "--host", docker_endpoint, *argv],
        timeout,
        remove_env=("DOCKER_HOST", "DOCKER_CONTEXT"),
    )

socket_paths = ["/var/run/docker.sock", "/run/docker.sock"]
socket_paths.extend(glob.glob("/run/user/*/docker.sock"))
socket_identities: set[tuple[int, int]] = set()
for candidate in socket_paths:
    try:
        info = os.stat(candidate)
    except OSError:
        continue
    if stat.S_ISSOCK(info.st_mode):
        socket_identities.add((info.st_dev, info.st_ino))
require(len(socket_identities) == 1, "docker_socket_count_not_one")
try:
    docker_socket = os.stat("/var/run/docker.sock")
    require(stat.S_ISSOCK(docker_socket.st_mode), "docker_socket_invalid")
    require(docker_socket.st_uid == 0, "docker_socket_not_root_owned")
except OSError:
    hard.add("docker_socket_unavailable")

docker_info: dict[str, object] = {}
if docker_binary is not None:
    info_status, info_raw = docker_command(["info", "--format", "{{json .}}"], 15.0)
    if info_status == 0:
        try:
            decoded = json.loads(info_raw)
            if isinstance(decoded, dict):
                docker_info = decoded
        except json.JSONDecodeError:
            pass
require(bool(docker_info), "docker_info_unavailable")

server_version = str(docker_info.get("ServerVersion", ""))
operating_system = str(docker_info.get("OperatingSystem", ""))
security_options = docker_info.get("SecurityOptions", [])
if not isinstance(security_options, list):
    security_options = []
facts["docker_server_version"] = server_version
facts["docker_operating_system"] = operating_system
facts["docker_security_options"] = sorted(str(option) for option in security_options)
require("docker desktop" not in operating_system.lower(), "docker_desktop_unsupported")
require(
    not any("rootless" in str(option).lower() for option in security_options),
    "rootless_docker_unsupported",
)
require(
    not any("userns" in str(option).lower() for option in security_options),
    "docker_userns_remap_unsupported",
)
expected_docker = versions.get("LAB_DOCKER_ENGINE_VERSION", "")
require(bool(expected_docker) and server_version == expected_docker, "docker_engine_version_mismatch")

bridge_status, bridge_driver = docker_command(
    ["network", "inspect", "bridge", "--format", "{{.Driver}}"],
    8.0,
)
facts["default_network_driver"] = bridge_driver
require(bridge_status == 0 and bridge_driver == "bridge", "docker_bridge_unavailable")

if arguments.runtime_env is None:
    core_image = "agmind-sais-core:0.1.0"
    adapter_image = "agmind-sais-falco-adapter:0.1.0"
else:
    core_image = runtime_values.get("AGMIND_CORE_IMAGE", "")
    adapter_image = runtime_values.get("AGMIND_ADAPTER_IMAGE", "")
    require(
        runtime_values.get("AGMIND_FALCO_IMAGE", "") == versions.get("FALCO_IMAGE", ""),
        "runtime_falco_image_not_pinned",
    )
    require(
        runtime_values.get("AGMIND_OPA_IMAGE", "") == versions.get("OPA_IMAGE", ""),
        "runtime_opa_image_not_pinned",
    )
    require(
        runtime_values.get("AGMIND_HAPROXY_IMAGE", "")
        == versions.get("HAPROXY_IMAGE", ""),
        "runtime_haproxy_image_not_pinned",
    )

image_specs = (
    (core_image, "core_image_unavailable"),
    (adapter_image, "falco_adapter_image_unavailable"),
    (versions.get("FALCO_IMAGE", ""), "pinned_falco_image_unavailable"),
    (versions.get("OPA_IMAGE", ""), "pinned_opa_image_unavailable"),
    (versions.get("HAPROXY_IMAGE", ""), "pinned_haproxy_image_unavailable"),
)
local_images: dict[str, str] = {}
for image, reason in image_specs:
    if not image:
        hard.add(reason)
        continue
    image_status, image_id = docker_command(
        ["image", "inspect", "--format", "{{.Id}}", image],
        8.0,
    )
    valid_image_id = (
        image_status == 0
        and image_id.startswith("sha256:")
        and len(image_id) == 71
        and all(character in "0123456789abcdef" for character in image_id[7:])
    )
    require(valid_image_id, reason)
    if valid_image_id:
        local_images[image] = image_id
facts["local_images"] = local_images

runtime_parents = (
    "/run/agmind-sais/observer-ingest",
    "/run/agmind-sais/observer-core",
    "/run/agmind-sais/observer-actuator",
    "/run/agmind-sais/actuator-intent",
    "/run/agmind-sais/actuator-admin",
)
installed_parents = 0
for value in runtime_parents:
    try:
        info = os.stat(value, follow_symlinks=False)
    except OSError:
        continue
    installed_parents += 1
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) == 0o750,
        "unsafe_runtime_socket_parent",
    )
if installed_parents != len(runtime_parents):
    degraded.add("runtime_socket_parents_not_installed")

if arguments.runtime_env is not None:
    core_gid_text = runtime_values.get("AGMIND_CORE_GID", "")
    try:
        core_gid = int(core_gid_text)
    except ValueError:
        core_gid = -1
    secret_boundary_valid = core_gid > 0 and str(core_gid) == core_gid_text
    try:
        secret_parent = Path("/etc/agmind-sais/secrets").lstat()
        secret_boundary_valid = secret_boundary_valid and (
            stat.S_ISDIR(secret_parent.st_mode)
            and secret_parent.st_uid == 0
            and secret_parent.st_gid == core_gid
            and stat.S_IMODE(secret_parent.st_mode) == 0o710
        )
    except OSError:
        secret_boundary_valid = False
    for token_name in ("core-api.token", "dgx-api.token"):
        try:
            token_info = (Path("/etc/agmind-sais/secrets") / token_name).lstat()
            secret_boundary_valid = secret_boundary_valid and (
                stat.S_ISREG(token_info.st_mode)
                and token_info.st_uid == 0
                and token_info.st_gid == core_gid
                and token_info.st_nlink == 1
                and stat.S_IMODE(token_info.st_mode) == 0o640
                and 1 <= token_info.st_size <= 4097
            )
        except OSError:
            secret_boundary_valid = False
    for private_key_name in ("observer-ed25519.key", "actuator-ed25519.key"):
        try:
            private_key_info = (
                Path("/etc/agmind-sais/secrets") / private_key_name
            ).lstat()
            secret_boundary_valid = secret_boundary_valid and (
                stat.S_ISREG(private_key_info.st_mode)
                and private_key_info.st_uid == 0
                and private_key_info.st_gid == 0
                and private_key_info.st_nlink == 1
                and stat.S_IMODE(private_key_info.st_mode) == 0o400
                and 1 <= private_key_info.st_size <= 4096
            )
        except OSError:
            secret_boundary_valid = False
    facts["core_secret_directory_mode"] = "0710" if secret_boundary_valid else ""
    require(secret_boundary_valid, "core_secret_boundary_unsafe")

if all(dgx_inputs):
    assert arguments.dgx_url is not None
    assert arguments.runtime_env is not None
    assert arguments.management_denylist is not None

    try:
        parsed = urlsplit(arguments.dgx_url)
        parsed_port = parsed.port
    except ValueError:
        parsed = urlsplit("")
        parsed_port = None
    parsed_host = parsed.hostname or ""
    canonical_url = (
        f"http://{parsed_host}:{parsed_port}/v1"
        if parsed_host and parsed_port is not None
        else ""
    )
    dgx_url_valid = (
        len(arguments.dgx_url) <= 2048
        and arguments.dgx_url.isascii()
        and arguments.dgx_url == canonical_url
        and parsed.scheme == "http"
        and parsed_port == 8000
        and parsed.username is None
        and parsed.password is None
        and parsed.path == "/v1"
        and parsed.query == ""
        and parsed.fragment == ""
        and all(
            character in "abcdefghijklmnopqrstuvwxyz0123456789.-"
            for character in parsed_host
        )
    )
    require(dgx_url_valid, "dgx_url_invalid")

    runtime_ipv4_text = runtime_values.get("AGMIND_DGX_IPV4", "")
    try:
        runtime_ipv4 = ipaddress.IPv4Address(runtime_ipv4_text)
    except ipaddress.AddressValueError:
        runtime_ipv4 = None
    require(
        runtime_ipv4 is not None and str(runtime_ipv4) == runtime_ipv4_text,
        "dgx_runtime_ipv4_invalid",
    )

    resolved_addresses: set[str] = set()
    if dgx_url_valid:
        try:
            for item in socket.getaddrinfo(
                parsed_host,
                parsed_port,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            ):
                resolved_addresses.add(str(ipaddress.ip_address(item[4][0])))
        except (OSError, ValueError):
            pass
    require(bool(resolved_addresses), "dgx_resolution_failed")
    require(
        runtime_ipv4 is not None
        and resolved_addresses == {str(runtime_ipv4)},
        "dgx_resolution_not_exact",
    )
    require(
        all(
            not ipaddress.ip_address(value).is_loopback
            and not ipaddress.ip_address(value).is_link_local
            and not ipaddress.ip_address(value).is_multicast
            and not ipaddress.ip_address(value).is_unspecified
            for value in resolved_addresses
        ),
        "dgx_resolution_unsafe",
    )

    management, management_valid = load_json_object(arguments.management_denylist)
    addresses = management.get("denied_addresses")
    networks = management.get("denied_networks")
    management_valid = (
        management_valid
        and set(management) == {"denied_addresses", "denied_networks"}
        and isinstance(addresses, list)
        and isinstance(networks, list)
        and networks == []
        and all(isinstance(value, str) for value in addresses)
    )
    denied_addresses: set[str] = set()
    if management_valid and isinstance(addresses, list):
        try:
            denied_addresses = {
                str(ipaddress.IPv4Address(value))
                for value in addresses
                if isinstance(value, str)
            }
        except ipaddress.AddressValueError:
            management_valid = False
    management_valid = (
        management_valid
        and isinstance(addresses, list)
        and len(addresses) == len(denied_addresses)
        and all(str(ipaddress.IPv4Address(value)) == value for value in addresses)
    )
    require(management_valid, "management_denylist_invalid")
    require(
        runtime_ipv4 is not None
        and denied_addresses == {str(runtime_ipv4)}
        and resolved_addresses == denied_addresses,
        "dgx_management_denylist_not_exact",
    )

    facts["dgx_ipv4"] = sorted(resolved_addresses)
    facts["management_denylist_sha256"] = (
        sha256_regular_file(arguments.management_denylist) or ""
    )
    facts["runtime_env_sha256"] = sha256_regular_file(arguments.runtime_env) or ""
else:
    degraded.add("dgx_endpoint_not_checked")

document = {
    "schema_version": "agmind.preflight.v1",
    "active_containment_supported": not hard,
    "hard_failures": sorted(hard),
    "degraded": sorted(degraded),
    "facts": facts,
}
print(json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
raise SystemExit(0 if not hard else 1)
PY
