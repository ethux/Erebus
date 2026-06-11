.DEFAULT_GOAL := help
.PHONY: help hooks dev lint fix deadcode test check

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-10s %s\n", $$1, $$2}'

hooks: ## Enable the committed git hooks (.githooks/) for this clone
	git config core.hooksPath .githooks
	@echo "Git hooks enabled (core.hooksPath = .githooks)"

dev: ## Install dev tooling (ruff, pylint, vulture) and enable hooks
	python3 -m pip install -e '.[dev]'
	$(MAKE) hooks

lint: ## Ruff + pylint (max module lines) + dead-code scan
	ruff check .
	pylint --recursive=y erebus tests
	vulture

fix: ## Auto-fix lint violations where safe
	ruff check --fix .

deadcode: ## Dead-code scan only (vulture)
	vulture

test: ## Run the full test suite
	bash tests/run_tests.sh

check: lint test ## Everything CI runs
