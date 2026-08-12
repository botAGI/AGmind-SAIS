# Captured Falco HTTP output — provenance

`captured-http-output.ndjson` and `captured-http-output.legacy-rule.ndjson` are **not
hand-written**. Every line is one HTTP request body that the pinned Falco actually POSTed to
`http://falco-adapter:8765/v1/falco/raw`, one body per line, byte-for-byte as Falco serialized
it apart from the sanitization listed below.

Everything else in this directory is a hand-built fixture. A hand-built fixture cannot prove the
adapter accepts production sensor output — that is exactly how `metrics-heartbeat-real.json`
came to carry a field (`falco.evts_rate_sec`) the real sensor never emits and to omit the
twenty-five fields it does.

## How they were captured

A throwaway Falco was run from the pinned image on a scratch Docker network, with the same
privileges, mounts and command as `deploy/compose/compose.yaml`, and with **`deploy/falco/falco.yaml`
and `deploy/falco/rules.d/agmind-pcc.yaml` bind-mounted verbatim** — no edits. The capture server
was simply named `falco-adapter` on that network, so `http_output.url` resolved to it and the
configuration Falco hashed is byte-identical to the one this repository ships:

    docker network create agmind-falco-capture
    docker run -d --name falco-adapter --network agmind-falco-capture \
      -v .../server.py:/server.py:ro -v .../out:/out $PYTHON_IMAGE python /server.py
    docker run -d --name falco-capture-sensor --network agmind-falco-capture --user 0:0 \
      --read-only --cap-drop ALL --cap-add SYS_ADMIN --cap-add SYS_RESOURCE --cap-add SYS_PTRACE \
      --security-opt no-new-privileges:true --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
      --ulimit memlock=-1:-1 \
      -v /sys/kernel/tracing:/sys/kernel/tracing:ro -v /proc:/host/proc:ro \
      -v /etc/os-release:/host/etc/os-release:ro -v /etc/passwd:/host/etc/passwd:ro \
      -v /etc/group:/host/etc/group:ro \
      -v $PWD/deploy/falco/falco.yaml:/etc/falco/falco.yaml:ro \
      -v $PWD/deploy/falco/rules.d/agmind-pcc.yaml:/etc/falco/rules.d/agmind-pcc.yaml:ro \
      $FALCO_IMAGE /usr/bin/falco -c /etc/falco/falco.yaml

Traffic was generated from a throwaway `busybox` container: TCP/UDP connects over IPv4 and IPv6,
to loopback, to a refused port, to an unreachable address, and to an AF_UNIX path — plus whatever
this host's own containers were doing at the time.

Because the mounted configuration is the shipped one, the metrics snapshots carry
`falco.sha256_config_file.falco_yaml` = sha256 of `deploy/falco/falco.yaml` and
`falco.sha256_rules_file.agmind_pcc_yaml` = sha256 of `deploy/falco/rules.d/agmind-pcc.yaml`.
`core/tests/falco_adapter/test_captured_sensor_output.py` asserts exactly that, so **editing either
sensor artifact without re-capturing turns the suite red.** Re-capture; do not hand-edit these
files.

## What was sanitized

Byte-level replacement only, so Falco's own key order, float spelling and `null` spelling survive:

| captured value      | fixture value       | why |
| ------------------- | ------------------- | --- |
| `c485ee626757`, `50c1fe0b5b5c` (`hostname`, `evt.hostname`) | `agmind-falco` | sensor container identity |
| `172.27.0.3` (`falco.host_netinfo...eth0...addresses`) | `192.0.2.10` | host bridge address |
| `7.0.0-28-generic` (`falco.kernel_release`) | `0.0.0-0-generic` | host kernel build |

Container IDs, container start timestamps, event timestamps, counters, `proc.*`, `fd.*` and every
digest are untouched — the adapter's parser reads those, so redacting them would defeat the point.

## The two files

- **`captured-http-output.ndjson`** — captured with the current
  `deploy/falco/rules.d/agmind-pcc.yaml`. Every body in it must parse. Contains three metrics
  snapshots and the connect shapes the pinned rule produces (`SUCCESS` tcp/udp, `EINPROGRESS`,
  and the `ENOENT` / `ECONNREFUSED` / `ERESTARTSYS` failures that carry no fd information).
- **`captured-http-output.legacy-rule.ndjson`** — captured with the *previous* rule, whose
  `or evt.rawres < 0` disjunct dropped the address-family restriction. It contains real bodies
  with `"fd.rip":"::1"`, which `FalcoConnectV1` cannot represent and the redactor rejects. That is
  the defect that kept `falco_parse_rejection` / `invalid_falco_body` permanently open. It is kept
  so the contract's refusal to accept a non-IPv4 destination stays asserted against a real body,
  not an invented one.
