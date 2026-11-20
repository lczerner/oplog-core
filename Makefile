# SPDX-License-Identifier: MIT
# Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
# Makefile for oplog-core. Run "make" or "make help" to list the targets.
# The targets wrap the npm scripts. A comment after "##" is the help text.

SHELL := /bin/bash
.DEFAULT_GOAL := help
SBOM_FORMAT ?= cyclonedx

.PHONY: help install typecheck test check sbom outdated audit clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target> [VAR=value]\n\nTargets:\n"} \
		/^[a-zA-Z0-9_-]+:.*## / {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf "\nVariables:\n  SBOM_FORMAT=%s\n" "$(SBOM_FORMAT)"

install: ## Install the npm dependencies (npm ci)
	npm ci

typecheck: ## Run the TypeScript type check
	npm run typecheck

test: ## Run the unit and property tests
	npm test

check: typecheck test sbom ## Run the checks before each commit

sbom: ## Write the SBOMs to sbom/ (runtime + build, SBOM_FORMAT=cyclonedx|spdx) and check them
	node scripts/sbom.mjs $(SBOM_FORMAT)

outdated: ## List npm dependencies with newer versions
	-npm outdated

audit: ## Check npm dependencies for known vulnerabilities (the level of the CI)
	npm audit --audit-level=moderate

clean: ## Remove generated files (sbom/, coverage/)
	rm -rf sbom coverage
