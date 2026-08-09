# Export and verify an action proof

This runbook exports one immutable proof bundle from an installed M1 single-host
deployment. The command briefly pauses AGmind telemetry and control-plane
processes to take a coherent snapshot. It does **not** stop Docker, edit
nftables, or remove an already-applied containment rule. A native nftables
timeout remains enforced by the kernel and continues to expire on kernel time
while Core, actuator, and observer are stopped.

## Preconditions

Run on the installed rootful Linux Docker host. The fixed AGmind state,
configuration, public keys, systemd units, Docker socket, and locally built Core
image must still be present. The output parent must already exist, be
root-owned, canonical (no symlink traversal), and not group/world writable. The
new bundle directory itself must not exist.

For example:

```sh
sudo install -d -o root -g root -m 0700 /var/lib/agmind-sais/exports
sudo /opt/agmind-sais/scripts/export-proof-linux.sh \
  --action-id act_0123456789abcdef0123456789abcdef \
  --output /var/lib/agmind-sais/exports/act_0123456789abcdef0123456789abcdef
```

The script records whether each of `agmind-core-compose.service`,
`agmind-actuatord.service`, and `agmind-observerd.service` was active. It stops
them in that order, exports and verifies the snapshot, then starts only the
units that were previously active, in dependency order: observer, actuator,
Core. Signal and error exits use the same recovery path. A recovery failure is
reported prominently and makes the command fail even if bundle creation
succeeded.

The export container has no network, a read-only root filesystem, no-new-
privileges, bounded resources, narrow read-only mounts for the trusted inputs,
and one fresh isolated staging directory mounted read-write. The requested
output parent and any sibling data are never mounted into the container. All
capabilities are dropped; only `CAP_DAC_READ_SEARCH` is added back because the
quiesced inputs are deliberately split across root-owned and `agmind-core`-
owned `0700` state. It does not receive `CAP_DAC_OVERRIDE`, a Docker-socket
mount, a host namespace, or any private key/token. The offline verification
container is zero-capability, sees the staged bundle and the two host trust
pins read-only, and receives a separate fresh owner-only scratch directory.

## Successful result

The script trusts neither the bundle manifest alone nor exporter output. It
runs `python -m agmind_immune.replay verify-export` in the installed Core image
with the host's observer trust root and actuator public key supplied as external
pins. Success requires the verifier to report both `integrity_verified=true`
and `causal_links_verified=true`, bind the exact requested `action_id`, and
report terminal `action_state="EXPIRED"`. This installed M1 workflow therefore
exports proof only after the native TTL has elapsed and the restarted actuator
has durably observed expiry. The lower-level offline verifier may still inspect
non-success lifecycle states for forensics, but they are not accepted as an M1
containment proof. The final five machine-readable lines are:

```text
bundle_path=/absolute/path/chosen/by/operator
bundle_sha256=<64 lowercase hex>
candidate_id=cand_<64 lowercase hex>
intent_id=int_<32 lowercase hex>
action_state=EXPIRED
```

Store the bundle and its printed digest together. Verification on another host
still requires independently trusted copies of the observer trust root and
actuator public key; keys copied only from inside the bundle are not an external
trust anchor.

The bundle proves integrity of the included records and their verified causal
links from evidence and policy admission through the prepared plan and signed
actuator lifecycle. It does not prove that an untrusted Hunter/LLM narrative is
correct, complete, or causally authoritative. Hunter text is enrichment, not a
containment proof.

If export or verification fails after bundle creation starts, the script moves
the incomplete isolated bundle to the requested output path when that can be
done without overwriting anything. If a hard interruption prevents promotion,
it reports the retained root-only staging or verifier-scratch path. Inspect or
preserve it as needed, then choose a new output path. Always resolve any
reported unit-recovery failure before relying on resumed telemetry.
