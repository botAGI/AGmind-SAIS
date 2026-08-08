from __future__ import annotations

import re
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_PYTHON_IMAGE = (
    "python:3.12.13-slim-trixie@"
    "sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
)


def _read(name: str) -> str:
    return (_REPOSITORY_ROOT / name).read_text(encoding="utf-8")


def _make_target(makefile: str, name: str) -> str:
    match = re.search(rf"(?ms)^{re.escape(name)}:\s*\n(?P<body>(?:\t.*(?:\n|\Z))+)", makefile)
    assert match is not None, f"missing make target {name}"
    return match.group("body")


def test_runtime_image_uses_pinned_base_and_root_owned_venv() -> None:
    dockerfile = _read("Dockerfile")
    versions = _read("deploy/versions.env").splitlines()

    assert f"ARG PYTHON_IMAGE={_PYTHON_IMAGE}" in dockerfile
    assert f"PYTHON_IMAGE={_PYTHON_IMAGE}" in versions
    assert dockerfile.count("FROM ${PYTHON_IMAGE}") == 2
    assert "python -m venv /opt/agmind-venv" in dockerfile
    assert "/opt/agmind-venv/bin/pip install --no-cache-dir -r requirements.txt" in dockerfile
    assert "COPY --from=builder /opt/agmind-venv /opt/agmind-venv" in dockerfile
    assert 'ENV PATH="/opt/agmind-venv/bin:${PATH}"' in dockerfile
    assert "--user" not in dockerfile
    assert "/root/.local" not in dockerfile


def test_runtime_image_installs_fixed_rule_before_non_root_default() -> None:
    dockerfile = _read("Dockerfile")
    user_offset = dockerfile.index("USER sais")
    directory_command = (
        "install -d -o root -g root -m 0755 /etc/falco "
        "/etc/falco/rules.d"
    )
    rule_copy = (
        "COPY --chown=0:0 --chmod=0444 deploy/falco/rules.d/agmind-pcc.yaml "
        "\\\n  /etc/falco/rules.d/agmind-pcc.yaml"
    )

    assert directory_command in dockerfile
    assert rule_copy in dockerfile
    assert dockerfile.index(directory_command) < user_offset
    assert dockerfile.index(rule_copy) < user_offset
    assert dockerfile.rfind("USER ") == user_offset
    assert dockerfile.rfind('CMD ["python3", "main.py"]') > user_offset


def test_requirements_pin_core_and_preserve_legacy_app_dependencies() -> None:
    requirements = {
        line.strip()
        for line in _read("requirements.txt").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    core_pins = {
        "aiosqlite==0.22.1",
        "cryptography==49.0.0",
        "fastapi==0.140.0",
        "google-crc32c==1.8.0",
        "httpx==0.28.1",
        "jsonschema==4.26.0",
        "pydantic==2.13.4",
        "uvicorn[standard]==0.51.0",
    }
    legacy_dependencies = {
        "aiohttp>=3.10.0",
        "pyyaml>=6.0.2",
        "python-multipart>=0.0.17",
        "websockets>=12.0",
    }

    assert core_pins <= requirements
    assert legacy_dependencies <= requirements
    for package in ("aiosqlite", "cryptography", "fastapi", "google-crc32c", "httpx", "jsonschema", "pydantic"):
        assert sum(line.startswith(f"{package}=") for line in requirements) == 1
    assert sum(line.startswith("uvicorn") for line in requirements) == 1


def test_make_target_builds_and_smokes_real_image_without_root_or_network() -> None:
    makefile = _read("Makefile")
    target = _make_target(makefile, "test-core-detector-pin-image")

    assert "test-core-detector-pin-image" in re.search(
        r"(?m)^\.PHONY:.*$",
        makefile,
    ).group(0)
    assert "docker build" in target
    assert '$(PYTHON_IMAGE)' in target
    assert "docker run --rm" in target
    assert target.count("--platform linux/arm64") == 2
    assert "--network none" in target
    assert "--read-only" in target
    assert "--user" not in target
    assert re.search(r"(?:^|\s)-u(?:\s|=)", target) is None
    assert "PYTHONPATH=/app/core" in target
    assert "_load_pinned_detector_bundle" in target
    assert "pcc_detector_bundle_sha256" in target
    assert "/expected/agmind-pcc.yaml" in target
    assert "/app/core/tests/correlation/sqlite_integrity_runtime_smoke.py" in target
