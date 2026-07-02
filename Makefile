.PHONY: all lint fmt test clean help

all: lint test

lint:
	ruff check .
	ruff format --check .

fmt:
	ruff check --fix .
	ruff format .

test:
	pytest tests/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

help:
	@echo "Available targets:"
	@echo "  lint   - Run ruff check + format check"
	@echo "  fmt    - Auto-fix lint issues + format code"
	@echo "  test   - Run pytest"
	@echo "  clean  - Remove build artifacts and caches"
	@echo "  help   - Show this help message"
