# Darknyx — convenience targets for common workflows.
#
# This file is INTENTIONALLY thin. Long-form documentation of each
# workflow lives in:
#   * CLAUDE.md §2   — the unbreakable build/deploy/validate cycle
#   * scripts/dev-commands.md — full command catalogue
#   * docs/tee-architecture.md §12 — TEE dev workflow
#
# The Makefile exists for muscle memory:  `make dev-tee` instead of
# remembering the sim-start incantation.

# ─── Phony bookkeeping ───────────────────────────────────────────────
.PHONY: help check clippy fmt fmt-check test \
        dev-tee dev-tee-env dev-tee-build \
        darknyx-tee-run darknyx-tee-check \
        smoke-deploy smoke-status smoke-logs smoke-down

help:
	@echo 'Common targets:'
	@echo '  make check          — cargo check --workspace'
	@echo '  make clippy         — cargo clippy --workspace --all-targets -- -D warnings'
	@echo '  make fmt            — cargo fmt --all'
	@echo '  make fmt-check      — cargo fmt --all -- --check (CI gate)'
	@echo '  make test           — cargo test --workspace'
	@echo ''
	@echo 'In-TEE dev (offline, no Phala credits):'
	@echo '  make dev-tee        — start dstack-simulator in foreground'
	@echo '  make dev-tee-env    — print export statements to source into your shell'
	@echo '  make dev-tee-build  — force-rebuild the simulator binary'
	@echo '  make darknyx-tee-run    — cargo run -p darknyx-tee (assumes simulator running)'
	@echo '  make darknyx-tee-check  — cargo check -p darknyx-tee'
	@echo ''
	@echo 'Phala Cloud smoke deploy (requires `phala login`):'
	@echo '  make smoke-deploy   — phala deploy of deploy/docker-compose.yaml'
	@echo '  make smoke-status   — phala cvms get darknyx-tee-spike'
	@echo '  make smoke-logs     — phala logs --cvm-id darknyx-tee-spike'
	@echo '  make smoke-down     — phala cvms delete darknyx-tee-spike (stops billing)'

# ─── Workspace hygiene ──────────────────────────────────────────────
check:
	cargo check --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

test:
	cargo test --workspace

# ─── darknyx-tee dev (against dstack-simulator) ─────────────────────────
dev-tee:
	./scripts/dstack-simulator-start.sh

dev-tee-env:
	@./scripts/dstack-simulator-start.sh --env

dev-tee-build:
	./scripts/dstack-simulator-start.sh --build

darknyx-tee-check:
	cargo check -p darknyx-tee

# Note: `make darknyx-tee-run` assumes you've already started the
# simulator in another terminal (or via `eval "$(make dev-tee-env)"`).
# The binary will work without the simulator too — boot::probe_dstack
# only logs that no socket was found.
darknyx-tee-run:
	cargo run -p darknyx-tee

# ─── Phala Cloud smoke-deploy ───────────────────────────────────────
# These mirror the workflow documented in deploy/README.md. They
# assume `phala login` has been run interactively at least once.
SMOKE_NAME ?= darknyx-tee-spike

smoke-deploy:
	phala deploy -c deploy/docker-compose.yaml -n $(SMOKE_NAME)

smoke-status:
	phala cvms get $(SMOKE_NAME)

smoke-logs:
	phala logs --cvm-id $(SMOKE_NAME)

smoke-down:
	phala cvms delete $(SMOKE_NAME)
