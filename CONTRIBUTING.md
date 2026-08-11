# Contributing

## Ground rules

This is a security product; its value is the invariant chain described in
[README.md](README.md) and [SECURITY.md](SECURITY.md). A change that weakens
any arrow of that chain is a regression even if every test is green.

- **Fail closed.** Ambiguity in policy, identity, signature, or netns
  resolution means refuse, never proceed.
- **The LLM has no authority.** Hunter output must never reach policy, intent,
  or approval logic.
- **Never weaken a security check to make a gate pass.** If the check is
  wrong, fix the check deliberately and record why; if the caller is wrong,
  fix the caller.
- Justification comments (why a file mode is 0400, why a capability is
  granted) are load-bearing. Update them when stale; do not delete them.

## Development gate

```sh
make contracts
```

This is the project's gate: uv lock check, ruff, mypy, the Python contract
tests, then the Go tests and two fuzz targets. Notes:

- The gate is fully containerised. Go does **not** need to be installed on the
  host; all Go work runs through the Makefile's `GO_RUN`.
- The pinned images must be present locally — `--mount type=image` does not
  pull. If the gate dies with `No such image: ghcr.io/astral-sh/uv`, pull the
  pinned image and re-run.
- The steps run **in order and short-circuit**. A red early step means the
  later steps never executed; when reporting a failure, say what did not run,
  not only what failed.

The release gate is separate: `scripts/verify-linux-integration.sh` on a
dedicated Linux host (see [docs/runbooks/beelink-lab.md](docs/runbooks/beelink-lab.md)).
Green unit gates are not native proof.

## Tests

- Behaviour changes are test-driven: write the failing test first, then the
  minimal patch that turns it green.
- **A test must exercise the path production actually uses.** Where production
  has an installer, a systemd unit, or a Dockerfile, the test must consume
  that artifact — not a hand-built fixture. This repo has already shipped a
  green suite against a file mode the installer never produced; do not repeat
  it.
- Guards derive their subject set from the source of truth (compose file,
  installer allowlist), never from hardcoded examples, and assert that
  discovery is non-empty.
- Mutation-test new guards: break the real logic once and confirm the guard
  goes red before trusting it.

## Commits and pull requests

- Conventional commits, matching existing history: `feat(core):`,
  `fix(host):`, `docs:`, `ci:`.
- Minimal diffs: only what the task requires. Unrelated findings belong in
  their own change.
- For any diff touching the invariant chain, answer in the PR description:
  1. Which arrow of the chain does this touch?
  2. Can the change be reached from untrusted input (evidence, model text,
     network)?
  3. Does it fail open on error, timeout, or absence?
  4. Does an automated gate cover it — on the real artifact?
  5. Does it change what an operator sees before approving?

Security findings go to [SECURITY.md](SECURITY.md), not the issue tracker.
