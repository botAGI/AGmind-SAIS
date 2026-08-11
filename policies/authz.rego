# OPA's own API authorization policy, evaluated by --authorization=basic for EVERY request the
# server receives.
#
# Without it the management API is wide open to anything that can reach the control network: a
# single `PUT /v1/policies/pcc` replaces the admission policy in memory while the mounted
# pcc.rego on disk still reads exactly as reviewed. The file is bind-mounted read-only, which
# protects the bytes on disk and nothing about the decision actually being made.
#
# Default deny. The only thing this deployment needs is the one decision query Core sends
# (core/agmind_immune/policy/client.py: POST /v1/data/agmind/pcc/decision) plus the liveness
# probe. Everything else — policy mutation, data mutation, compile, config and query
# introspection — is refused.

package system.authz

import rego.v1

default allow := false

# The single decision endpoint Core queries. Kept exact rather than a prefix match: a prefix would
# also admit sibling packages that a future policy file might introduce.
allow if {
	input.method == "POST"
	input.path == ["v1", "data", "agmind", "pcc", "decision"]
}

# No liveness exemption on purpose: the compose healthcheck is `/opa eval true`, a CLI invocation
# that never touches the HTTP API, so nothing legitimate needs an unauthenticated GET. An earlier
# draft carried a `GET /` rule; it was removed after testing showed it never matched — a rule that
# cannot fire is worse than no rule, because it reads like coverage.

# Explicitly named so the refusal is greppable when someone wonders why a management call 404s:
# v1/policies (read AND write), v1/data writes, v1/compile, v1/config and v1/query are all denied
# by the default above. Do not add a rule for them without a recorded decision — replacing the
# admission policy at runtime defeats the entire proof-carrying chain, since the durable record
# attests that OPA decided, not what OPA contained when it decided.
