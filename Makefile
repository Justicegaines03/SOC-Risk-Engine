# SOC Risk Engine — Makefile
# One-command targets for setup, management, and testing.

.DEFAULT_GOAL := help
COMPOSE := docker compose

# ---------------------------------------------------------------------------
# Setup & Lifecycle
# ---------------------------------------------------------------------------

.PHONY: setup
setup: ## First-time setup: generate .env, start stack, bootstrap services
	@bash scripts/bootstrap.sh

.PHONY: up
up: ## Start all services (requires .env to exist)
	$(COMPOSE) up -d

.PHONY: down
down: ## Stop all services (data preserved)
	$(COMPOSE) down

.PHONY: restart
restart: ## Restart all services
	$(COMPOSE) restart

.PHONY: reset
reset: ## Destroy all data and re-run setup from scratch
	$(COMPOSE) down -v
	@bash scripts/bootstrap.sh

.PHONY: status
status: ## Show service status and health
	@echo "=== Service Status ==="
	@$(COMPOSE) ps
	@echo ""
	@echo "=== Health Checks ==="
	@printf "TheHive  (9000): " && (curl -sf http://localhost:9000/api/status > /dev/null 2>&1 && echo "OK" || echo "UNREACHABLE")
	@printf "Cortex   (9001): " && (curl -sf http://localhost:9001/api/status > /dev/null 2>&1 && echo "OK" || echo "UNREACHABLE")
	@printf "Elastic  (9200): " && (curl -sf http://localhost:9200/_cluster/health > /dev/null 2>&1 && echo "OK" || echo "UNREACHABLE")

.PHONY: logs
logs: ## Tail logs for all services
	$(COMPOSE) logs -f

.PHONY: logs-engine
logs-engine: ## Tail logs for the risk engine only
	$(COMPOSE) logs -f risk_engine

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------

.PHONY: test
test: ## Run unit test suite
	python -m pytest tests/ -v

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	python -m pytest tests/ -v --cov=risk_engine --cov-report=term-missing

.PHONY: smoke
smoke: ## Run integration smoke test against the live stack
	python scripts/smoke_test.py

.PHONY: lint
lint: ## Run linter (ruff)
	python -m ruff check risk_engine/ tests/

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

.PHONY: help
help: ## Show this help message
	@echo "SOC Risk Engine — Available Targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
