# Where AGmind-SAIS sits

An honest reading of the runtime-security landscape as of August 2026, and what this project
does that the established tools do not. Written to be argued with: every claim about another
project is about its documented default behaviour, and every claim about this one is about code
in this repository.

## The landscape is crowded at detection and thin at response

Runtime detection on Linux is mature and well served. Falco streams kernel events to a
user-space rule engine and has the largest rule and integration ecosystem; Tetragon does
in-kernel filtering and enforcement through Cilium's eBPF machinery; Tracee leans into forensic
capture — binaries, memory regions, per-event traffic. Among CNCF end users running more than
one, the common pattern is Falco for detection plus Tetragon for enforcement on critical
syscalls.

**This project does not compete there.** It consumes Falco. The pinned Falco 0.44.1 and its
single detector rule are the sensing leg; replacing them with Tetragon or Tracee would be a
adapter-sized change, not an architectural one.

The thin part is what happens *after* a detection, when the response would disrupt something:

- **Wazuh Active Response** executes the containment action with no human in the loop, typically
  in under three seconds, and writes the result back afterwards. The audit trail is a log
  produced by the same system that acted.
- **Falco Talon** is a no-code response engine for Falco events: match the rule, run the
  actionner. Its own guidance is that stateful workloads should not be auto-terminated without a
  human approval gate — and the gate is not something it provides.
- **Human-in-the-loop, where it exists, lives in a case-management product.** The usual pattern
  is Wazuh or Falco routing into TheHive, where an analyst clicks approve in a web application on
  another machine, and the automation then acts on that click.

So the field offers two shapes: act automatically and log it, or ask a human through a web app.

## What this project does differently

Four things, all of them architectural rather than configurable.

### 1. Approval is bound to the exact plan, on the host, in person

The operator does not approve *an alert*. The actuator resolves the target itself — container ID,
start time, image ID, immutable spec hash, init PID, netns inode, inventory generation, the
destination, the TTL, the evidence IDs, the safety-snapshot hashes — freezes all of it into a
plan, and shows the plan's hash. Approval means typing a suffix of that hash into a terminal on
the host, over a Unix socket that admits only `root` or the `agmind-admin` group by kernel peer
credentials. Every precondition is re-resolved and compared immediately before the rule is
applied.

Consequences that a web-app approval cannot offer: a compromised control plane cannot approve;
a stolen session token is not enough, because there is no session; and the thing approved cannot
drift between the click and the action, because the plan is the hash.

### 2. Evidence is signed where it is observed, not summarised after the fact

The observer signs each event with Ed25519 at the moment of observation, binds it into a hash
chain with a monotonic sequence, and mirrors it to Core, which verifies rather than trusts.
Gaps in observation are themselves signed facts: a period where the Docker inventory was
uncertain produces a signed coverage window, so a blind spot cannot be silently absent from the
record.

This is the difference between a log and a chain of custody in the sense NIST SP 800-61 and
800-86 mean it: any alteration to a sealed record is detectable, and verification reports the
first break. The export path produces a bundle that can be verified offline, away from the
machine that produced it.

### 3. The model is denied authority by construction, not by prompting

OWASP's LLM Top 10 calls it Excessive Agency (LLM06): damaging actions performed in response to
manipulated model output. The prevailing advice is that prompt-level guardrails fail and real
enforcement has to live at the architectural layer — a gateway that intercepts tool calls, an
allowlist of tools per agent.

This project goes past that: there are no tools to intercept. The Hunter — a locally hosted
uncensored model on operator hardware — receives an incident-scoped, field-allowlisted, read-only
snapshot and returns hypotheses, supporting evidence IDs, refuting questions and stated
limitations. Action candidates originate only from versioned deterministic correlation over
authenticated inventory facts; the correlation function does not accept a model parameter at all,
and the candidate bytes are required to be identical whether the model output is benign, hostile,
or absent. The milestone's own acceptance criterion is that replacing the model with a
deliberately malicious implementation cannot produce an unauthorised state change.

Untrusted model text is delimited on the way in and never reaches policy, intent, plan or
approval serialisation on the way out.

### 4. Containment expires without anyone's cooperation

The blocking element carries a kernel timeout. It disappears whether or not Core is alive, whether
or not the operator is at the terminal, whether or not the network is up. The industry framing is
that the cost of an automated mistake is set by how fast it can be reversed; here reversal is not
an action anyone has to take.

The honest footnote: only the set *element* expires. The supporting table, chain and drop rule
remain in the container's network namespace, inert while empty, until the namespace goes away.

## Where it fits, and where it does not

**Fits.** A single dedicated Linux Docker host where a wrong containment is expensive and an
unexplainable one is worse: a lab or bench with sensitive workloads; a regulated or
forensically-exposed environment that must be able to prove afterwards what was observed, what
was decided, on what evidence and who authorised it; any deployment putting an LLM near incident
response where the honest answer to "what if the model is compromised?" has to be structural.

**Does not fit.** Kubernetes and multi-node coordination — deliberately out of scope for M1, and
a DaemonSet actuator is a separate threat model, not a port. Remote or on-call approval: the
approval boundary is the product, and moving it off the host would remove the reason to choose
this over Falco Talon. High alert volume with no one to answer: nothing here is autonomous, so an
unattended deployment simply does not contain anything. And it is not a detection engine — bring
Falco, or write an adapter for the sensor you already run.

## Maturity, stated plainly

M1 is a single-host milestone under development. The vertical slice — signed evidence,
deterministic correlation, OPA admission, durable intent, local interactive approval, exact
container netns, nftables deny with kernel TTL, signed action journal, Core mirror and offline
proof — is implemented, and the whole stack has been observed running on real hardware.

It is not production-ready and no version is tagged. The project's own release gate,
`scripts/verify-linux-integration.sh` producing a `"status":"PASS"` report on a dedicated host,
has not yet passed. There is no user interface, no metrics endpoint, no notification path, and no
history view: an operator's whole interface today is `agmindctl`, `systemctl` and container logs.
Those gaps are the roadmap, and the read-only half of them can be built without touching the
approval boundary — which is the one thing that must not be traded for convenience.
