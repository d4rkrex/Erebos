.PHONY: install install-tools install-global dev lint test scan

# Full installation (Python + tools)
install:
	@bash scripts/install.sh

# Install only Go security tools
install-tools:
	@bash scripts/install.sh --tools-only

# Install erebos as global command (requires pipx or creates symlink)
install-global:
	@if command -v pipx >/dev/null 2>&1; then \
		pipx install -e . --force; \
	else \
		poetry install && \
		mkdir -p ~/.local/bin && \
		ln -sf "$$(poetry env info -e)/bin/erebos" ~/.local/bin/erebos && \
		echo "Linked to ~/.local/bin/erebos — ensure ~/.local/bin is in PATH"; \
	fi

# Development install
dev:
	poetry install

# Lint and type check
lint:
	poetry run ruff check erebos tests
	poetry run black --check erebos tests

# Run tests
test:
	poetry run pytest tests/unit

# Quick fleet scan (pass TARGET=example.com)
scan:
	@test -n "$(TARGET)" || (echo "Usage: make scan TARGET=example.com" && exit 1)
	poetry run erebos scan $(TARGET) --fleet
