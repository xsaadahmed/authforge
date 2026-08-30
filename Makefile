# The whole development loop in a handful of memorable commands (§25).
#
# Every target here is also what CI runs, so "it passed locally" and "it passed in CI" mean the same
# thing rather than two similar things.

.DEFAULT_GOAL := help
SHELL := /bin/bash

VENV        ?= .venv
PYTHON      ?= $(VENV)/bin/python
PYTEST      ?= $(VENV)/bin/pytest
RUFF        ?= $(VENV)/bin/ruff
MYPY        ?= $(VENV)/bin/mypy
ALEMBIC     ?= $(VENV)/bin/alembic
COMPOSE     ?= docker compose
IMAGE       ?= authforge
TAG         ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

export AUTHFORGE_ENVIRONMENT ?= local

.PHONY: help
help: ## Show the available targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------ environment
.PHONY: install
install: ## Create the virtualenv and install the project with dev extras
	@command -v uv >/dev/null || { echo "uv is required: https://docs.astral.sh/uv/"; exit 1; }
	uv venv $(VENV)
	uv pip install --python $(PYTHON) -e ".[dev]"

# ------------------------------------------------------------------ local stack
.PHONY: up
up: ## Start Postgres, Redis and the IdP (with hot reload)
	$(COMPOSE) up -d --build postgres redis app
	@echo "IdP:       http://localhost:8000"
	@echo "Discovery: http://localhost:8000/.well-known/openid-configuration"
	@echo "Docs:      http://localhost:8000/docs"

.PHONY: down
down: ## Stop the stack, keeping volumes
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and delete its volumes (destroys local data and dev keys)
	$(COMPOSE) down -v
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml .coverage

.PHONY: logs
logs: ## Tail the IdP's logs
	$(COMPOSE) logs -f app

.PHONY: shell
shell: ## Open a shell inside the running IdP container
	$(COMPOSE) exec app /bin/sh

.PHONY: tools
tools: ## Start pgweb for database inspection on :8081
	$(COMPOSE) --profile tools up -d pgweb

.PHONY: demo
demo: ## Start the demo relying party (:8100) and resource server (:8200)
	@test -n "$$AUTHFORGE_DEMO_CLIENT_SECRET" \
		|| { echo "set AUTHFORGE_DEMO_CLIENT_SECRET to the value printed by 'make seed'"; exit 1; }
	$(COMPOSE) --profile demo up -d --build demo-rp demo-api
	@echo "Demo RP: http://localhost:8100"

# ------------------------------------------------------------------ database
.PHONY: migrate
migrate: ## Apply migrations (explicit, never automatic on boot)
	$(COMPOSE) exec app alembic upgrade head

.PHONY: migrate-down
migrate-down: ## Roll back the most recent migration
	$(COMPOSE) exec app alembic downgrade -1

.PHONY: migration
migration: ## Autogenerate a migration: make migration m="add widgets"
	@test -n "$(m)" || { echo 'usage: make migration m="describe the change"'; exit 1; }
	$(COMPOSE) exec app alembic revision --autogenerate -m "$(m)"

.PHONY: migration-check
migration-check: ## Fail if the models have drifted from the migrations
	$(COMPOSE) exec app alembic check

.PHONY: seed
seed: ## Create scopes, a signing key, an admin user and the demo client
	$(COMPOSE) exec app authforge-admin bootstrap \
		--admin-email admin@localhost \
		--demo-redirect-uri http://localhost:8100/callback

.PHONY: rotate-keys
rotate-keys: ## Rotate the signing key without a redeploy
	$(COMPOSE) exec app authforge-admin keys rotate --reason manual
	$(COMPOSE) exec app authforge-admin keys list

.PHONY: audit
audit: ## Tail the security audit trail
	$(COMPOSE) exec app authforge-admin audit tail --limit 25

# ------------------------------------------------------------------ staging one-offs
# These use `aws ecs run-task` against the existing Fargate task definition, private
# subnets, and ecs-sg (same path as the service). Values come from terraform output.
TF_STAGING ?= infra/envs/staging

.PHONY: migrate-staging
migrate-staging: ## Run alembic upgrade head as a one-off staging Fargate task
	./scripts/run-ecs-oneoff.sh $(TF_STAGING) -- alembic upgrade head

.PHONY: bootstrap-keys-staging
bootstrap-keys-staging: ## Create the first signing key in staging (idempotent; run after migrate)
	./scripts/run-ecs-oneoff.sh $(TF_STAGING) -- authforge-admin keys init

# Synthetic k6 account. Password is passed on the task command line — never use a real user.
LOADTEST_EMAIL ?= loadtest@authforge.test
LOADTEST_PASSWORD ?= LoadtestPassw0rd!
LOADTEST_CLIENT_ID ?= k6-loadtest
LOADTEST_REDIRECT_URI ?= https://rp.example.test/callback

.PHONY: seed-loadtest-staging
seed-loadtest-staging: ## Create/reset the k6 client+user on staging and print credentials
	./scripts/run-ecs-oneoff.sh $(TF_STAGING) -- authforge-admin seed-loadtest \
		--email $(LOADTEST_EMAIL) \
		--password $(LOADTEST_PASSWORD) \
		--client-id $(LOADTEST_CLIENT_ID) \
		--redirect-uri $(LOADTEST_REDIRECT_URI)

# ------------------------------------------------------------------ quality
.PHONY: lint
lint: ## Check formatting, lint rules and types
	$(RUFF) format --check .
	$(RUFF) check .
	$(MYPY) app

.PHONY: format
format: ## Apply formatting and safe lint fixes
	$(RUFF) format .
	$(RUFF) check --fix .

.PHONY: test
test: ## Run the whole suite (needs Postgres and Redis reachable)
	$(PYTEST)

.PHONY: test-unit
test-unit: ## Run only the tests that need no external services
	$(PYTEST) tests/unit

.PHONY: test-integration
test-integration: ## Run the integration and security suites
	$(PYTEST) tests/integration tests/security

.PHONY: coverage
coverage: ## Run the suite with a coverage gate on the auth-critical modules
	$(PYTEST) --cov=app --cov-report=term-missing --cov-report=xml --cov-fail-under=80

# ------------------------------------------------------------------ container
.PHONY: build
build: ## Build the runtime image tagged with the git SHA
	docker build -f docker/Dockerfile -t $(IMAGE):$(TAG) -t $(IMAGE):latest .

.PHONY: smoke
smoke: ## Hit the endpoints a post-deploy smoke test checks
	@curl -fsS http://localhost:8000/health | $(PYTHON) -m json.tool
	@curl -fsS http://localhost:8000/ready | $(PYTHON) -m json.tool
	@curl -fsS http://localhost:8000/.well-known/openid-configuration | $(PYTHON) -m json.tool
	@curl -fsS http://localhost:8000/.well-known/jwks.json | $(PYTHON) -m json.tool

# ------------------------------------------------------------------ infrastructure
.PHONY: tf-fmt
tf-fmt: ## Format the Terraform sources
	terraform -chdir=infra fmt -recursive

.PHONY: tf-validate
tf-validate: ## Validate every Terraform module and environment
	./scripts/validate-terraform.sh

K6 ?= k6

.PHONY: loadtest-token
loadtest-token: ## k6 authorization_code + PKCE (TOKEN_VUS=15 TOKEN_DURATION=45s)
	@test -n "$$BASE_URL" || { echo "set BASE_URL to the staging ALB URL"; exit 1; }
	@test -n "$$CLIENT_ID" || { echo "set CLIENT_ID"; exit 1; }
	@test -n "$$CLIENT_SECRET" || { echo "set CLIENT_SECRET"; exit 1; }
	@test -n "$$USER_EMAIL" || { echo "set USER_EMAIL"; exit 1; }
	@test -n "$$USER_PASSWORD" || { echo "set USER_PASSWORD"; exit 1; }
	$(K6) run loadtest/k6/token_exchange.js

.PHONY: loadtest-refresh
loadtest-refresh: ## k6 refresh reuse races (REFRESH_VUS=10 REFRESH_DURATION=45s REFRESH_CONTENTION=5)
	@test -n "$$BASE_URL" || { echo "set BASE_URL to the staging ALB URL"; exit 1; }
	@test -n "$$CLIENT_ID" || { echo "set CLIENT_ID"; exit 1; }
	@test -n "$$CLIENT_SECRET" || { echo "set CLIENT_SECRET"; exit 1; }
	@test -n "$$USER_EMAIL" || { echo "set USER_EMAIL"; exit 1; }
	@test -n "$$USER_PASSWORD" || { echo "set USER_PASSWORD"; exit 1; }
	$(K6) run loadtest/k6/refresh_rotation.js
