.PHONY: contracts fmt

contracts:
	uv sync --python 3.12.13 --frozen --all-groups
	uv run --frozen ruff check core tests
	uv run --frozen mypy core/agmind_immune
	uv run --frozen pytest -q core/tests/test_contract_fixtures.py tests/adversarial/test_contract_fuzz.py
	docker run --rm -v "$(PWD):/src" -w /src golang:1.26.5-bookworm go test ./internal/contracts ./internal/specialuse

fmt:
	uv run --frozen ruff format core tests
	docker run --rm -v "$(PWD):/src" -w /src golang:1.26.5-bookworm gofmt -w internal/contracts internal/specialuse
