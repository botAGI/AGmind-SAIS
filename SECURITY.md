# Security policy

## Status

AGmind-SAIS is pre-release. The one release gate — a native acceptance run of
`scripts/verify-linux-integration.sh` on a dedicated Linux host — has not
produced a `"status":"PASS"` report yet, so the project is **not
production-ready**. Deploy it only on dedicated lab hosts.

There are no supported release lines yet; reports are assessed against the
current `main`/`develop` state.

## Reporting a vulnerability

Please report vulnerabilities privately — do not open a public issue.

- Email: <lab@agmind.ai>
- Include: affected component, a reproduction or proof of concept, and the
  impact you see. Encrypted mail is not required.

You will get an acknowledgement within 7 days. There is no bug bounty. Please
allow a reasonable window for a fix before public disclosure; we will credit
you in the fix unless you prefer otherwise.

## What counts as a vulnerability here

The product is the invariant chain:

```text
signed evidence -> deterministic correlation -> OPA admission -> durable intent
-> local interactive approval -> exact container netns -> nftables deny with
native TTL -> signed action journal -> Core mirror / offline proof
```

Anything that weakens an arrow of that chain is in scope, in particular:

- model (Hunter) output reaching policy, intent, or approval decisions;
- any path that applies an nftables change without the actuator's local Unix
  socket peer-credential check, or outside the target container's netns;
- fail-open behaviour: ambiguity in policy, identity, signature, or netns
  resolution that leads to an action instead of a refusal;
- forging, replaying, or silently dropping signed evidence or journal entries;
- privilege escalation between components (Core, adapter, Falco, observerd,
  actuatord) beyond their documented capabilities.

Findings against the *legacy* generation (`app/`, root `main.py`, the root
`Dockerfile`) are still welcome, but note that no shipped deployment starts
it and its known exposure is documented in the code.
