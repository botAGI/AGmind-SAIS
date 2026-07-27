include deploy/versions.env

.PHONY: contracts fmt iana-check

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

iana-check:
	test "$$(shasum -a 256 contracts/v1/ipv4-special-use.csv | awk '{print $$1}')" = "e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73"

fmt:
	$(UV_RUN) run --frozen ruff format core tests
	docker run --rm -v "$(PWD):/src" -w /src "$(GO_IMAGE)" gofmt -w internal/contracts internal/specialuse
