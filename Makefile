include deploy/versions.env

.PHONY: contracts observer sensor fmt iana-check test-core-detector-pin-image

UV_RUN = docker run --rm --mount "type=image,src=$(UV_IMAGE),dst=/uv-image" -v "$(PWD):/src" -w /src "$(PYTHON_IMAGE)" /uv-image/uv
GO_RUN = docker run --rm -v "$(PWD):/src" -w /src -e GOFLAGS=-mod=readonly "$(GO_IMAGE)"

contracts:
	$(UV_RUN) lock --check --python "$(PYTHON_VERSION)"
	$(UV_RUN) sync --python "$(PYTHON_VERSION)" --frozen --all-groups
	$(UV_RUN) run --frozen ruff check core tests
	$(UV_RUN) run --frozen mypy core/agmind_immune
	$(UV_RUN) run --frozen pytest -q core/tests/test_contract_fixtures.py core/tests/test_contract_regressions.py core/tests/test_contract_rereview.py core/tests/test_contract_finalreview.py tests/adversarial/test_contract_fuzz.py
	$(GO_RUN) go test ./internal/contracts ./internal/specialuse
	$(GO_RUN) go test -fuzz=FuzzDecodeStrict -fuzztime=10s ./internal/contracts
	$(GO_RUN) go test -fuzz=FuzzCanonicalJSON -fuzztime=10s ./internal/contracts
	$(MAKE) iana-check

observer:
	$(UV_RUN) lock --check --python "$(PYTHON_VERSION)"
	$(UV_RUN) run --frozen ruff format --check core/agmind_immune/evidence core/tests/evidence
	$(UV_RUN) run --frozen ruff check core/agmind_immune/evidence core/tests/evidence
	$(UV_RUN) run --frozen mypy core/agmind_immune/evidence
	$(UV_RUN) run --frozen pytest -q core/tests/evidence/test_frames.py
	$(GO_RUN) go mod tidy -diff
	$(GO_RUN) go test ./internal/durablefile ./internal/uds ./host/observerd
	$(GO_RUN) go test -race ./internal/durablefile ./internal/uds ./host/observerd
	$(GO_RUN) go test -fuzz=FuzzDecodeAGF1 -fuzztime=10s ./internal/durablefile
	$(GO_RUN) sh -c 'CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go test -c -o /tmp/durablefile-darwin.test ./internal/durablefile'
	$(GO_RUN) sh -c 'CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go test -c -o /tmp/uds-darwin.test ./internal/uds'
	$(GO_RUN) sh -c 'CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go test -c -o /tmp/observerd-darwin.test ./host/observerd'
	$(GO_RUN) sh -c 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/agmind-observerd-linux-amd64 ./host/observerd/cmd/agmind-observerd'
	$(GO_RUN) sh -c 'CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/agmind-observerd-linux-arm64 ./host/observerd/cmd/agmind-observerd'

sensor:
	$(UV_RUN) lock --check --python "$(PYTHON_VERSION)"
	$(UV_RUN) run --frozen ruff format --check core/agmind_immune/falco_adapter core/tests/falco_adapter
	$(UV_RUN) run --frozen ruff check core/agmind_immune/falco_adapter core/tests/falco_adapter
	$(UV_RUN) run --frozen mypy core/agmind_immune/falco_adapter
	$(UV_RUN) run --frozen pytest -q core/tests/falco_adapter core/tests/test_contract_regressions.py::test_falco_schema_and_runtime_cover_candidate_investigation_and_hard_error
	$(GO_RUN) go test ./internal/contracts ./host/observerd -run '^(TestTask4|TestIngestFalco|TestFalcoIngestHTTP|TestSharedContradictoryFalcoResultIsRejected|TestFalcoResultTupleMatrixIsExact|TestC2AControlRoutesExistOnlyOnPhysicalCoreSocket)'
	@validation_log="$$(mktemp)"; \
	trap 'rm -f "$$validation_log"' 0; \
	validation_status=0; \
	docker run --rm --pull=never --network none -v "$(PWD)/deploy/falco:/etc/falco:ro" --entrypoint /usr/bin/falco "$(FALCO_IMAGE)" -c /etc/falco/falco.yaml -o json_output=false --validate /etc/falco/rules.d/agmind-pcc.yaml >"$$validation_log" 2>&1 || validation_status=$$?; \
	cat "$$validation_log"; \
	if test "$$validation_status" -ne 0; then exit "$$validation_status"; fi; \
	if grep -Eiq 'schema validation:[[:space:]]*failed|Validation of .* failed|Missing required property|Schema validation failed|\[FAILED\]' "$$validation_log"; then exit 1; fi; \
	if ! sed 's/^[^[:space:]]*:[[:space:]]*//' "$$validation_log" | grep -Fxq '/etc/falco/falco.yaml | schema validation: ok'; then exit 1; fi; \
	grep -Fxq '/etc/falco/rules.d/agmind-pcc.yaml: Ok' "$$validation_log"

iana-check:
	test "$$(shasum -a 256 contracts/v1/ipv4-special-use.csv | awk '{print $$1}')" = "e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73"

fmt:
	$(UV_RUN) run --frozen ruff format core tests
	docker run --rm -v "$(PWD):/src" -w /src "$(GO_IMAGE)" gofmt -w internal/contracts internal/specialuse internal/durablefile internal/uds host/observerd

CORE_DETECTOR_PIN_IMAGE ?= agmind-sais:core-detector-pin-test

test-core-detector-pin-image:
	docker build --pull=false --build-arg PYTHON_IMAGE="$(PYTHON_IMAGE)" --tag "$(CORE_DETECTOR_PIN_IMAGE)" .
	docker run --rm --network none --read-only --mount "type=bind,src=$(PWD)/deploy/falco/rules.d/agmind-pcc.yaml,dst=/expected/agmind-pcc.yaml,readonly" -e PYTHONPATH=/app/core "$(CORE_DETECTOR_PIN_IMAGE)" python -c 'import os, pwd; from pathlib import Path; from agmind_immune.canonicaljson import pcc_detector_bundle_sha256; from agmind_immune.correlation.authority import _load_pinned_detector_bundle; assert pwd.getpwuid(os.geteuid()).pw_name == "sais"; actual = _load_pinned_detector_bundle(); expected = pcc_detector_bundle_sha256(Path("/expected/agmind-pcc.yaml").read_bytes()); assert actual == expected, (actual, expected)'
