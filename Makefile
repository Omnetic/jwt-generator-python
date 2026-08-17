DC = docker compose run --rm python

.PHONY: build install test typecheck lint lint-fix example example-request shell

# Build the dev/test image
build:
	docker compose build

# Resolve and install dependencies (writes/uses uv.lock)
install:
	$(DC) uv sync

# Run the pytest suite
test:
	$(DC) uv run pytest

# Run mypy static analysis (strict, over src + tests + examples per pyproject files)
typecheck:
	$(DC) uv run mypy

# Check code style (ruff lint + format, both check-only)
lint:
	$(DC) uv run ruff check
	$(DC) uv run ruff format --check

# Auto-fix code style (ruff)
lint-fix:
	$(DC) uv run ruff check --fix
	$(DC) uv run ruff format

# Print a signed SA token: make example KEY=./sa-key.pem KID=<kid> [LIFETIME=3600]
# The recipes are silenced (@) so that redirecting stdout captures only the output.
example:
	@$(DC) uv run python examples/generate_token.py "$(KEY)" "$(KID)" $(LIFETIME)

# Call a DMS endpoint with a signed SA token: make example-request KEY=./sa-key.pem KID=<kid> URL=<url>
example-request:
	@$(DC) uv run python examples/call_dms_api.py "$(KEY)" "$(KID)" "$(URL)"

# Open a shell in the container
shell:
	$(DC) sh
