SHELL := /bin/bash

.PHONY: help setup bootstrap hooks-install
.PHONY: format format-check lint test test-agent-helper test-invocation test-installation test-no-persistence test-keychain-integration test-keychain-auth-ui test-pty test-ssh-manual build release-build install uninstall
.PHONY: ci ci-swift ci-workflows ci-secrets
.PHONY: pin-actions pin-actions-check
.PHONY: workflow-lint workflow-security
.PHONY: secret-scan pre-commit

TOOLCHAIN_DIR := $(shell xcode-select -p)
SWIFTPM_GIT_SAFE_BARE := GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.bareRepository GIT_CONFIG_VALUE_0=all
PINACT_GITHUB_TOKEN ?= $(shell gh auth token 2>/dev/null || true)
GH_TOKEN ?= $(shell gh auth token 2>/dev/null || true)

help:
	@printf '%s\n' \
	  'Setup:       make setup | bootstrap | hooks-install' \
	  'Development: make format | format-check | lint | build | release-build | test | test-agent-helper | test-invocation | test-installation | test-no-persistence' \
	  'Install:     make install | uninstall' \
	  'Manual:      make test-keychain-integration | test-keychain-auth-ui | test-pty | test-ssh-manual' \
	  'CI groups:   make ci-swift | ci-workflows | ci-secrets | ci' \
	  'Governance:  make workflow-lint | workflow-security | secret-scan | pin-actions-check'

setup: bootstrap hooks-install

bootstrap:
	mise install

hooks-install:
	git config --local core.hooksPath .githooks

format:
	mise exec -- swiftformat .

format-check:
	mise exec -- swiftformat --lint .

lint:
	XCODE_DEFAULT_TOOLCHAIN_OVERRIDE="$(TOOLCHAIN_DIR)" mise exec -- swiftlint lint --strict

test:
	swift run macop-selftest

test-agent-helper: build
	@bash scripts/test-agent-helper.sh

test-invocation: build
	@bash scripts/test-invocation.sh

test-installation: build
	@bash scripts/test-installation.sh

test-no-persistence: build
	@python3 scripts/test-no-persistence.py

test-keychain-integration:
	MACOP_RUN_KEYCHAIN_INTEGRATION=1 swift run macop-selftest

test-keychain-auth-ui: build
	@bash scripts/test-keychain-auth-ui.sh

test-pty: build
	@python3 scripts/test-pty.py
	@.build/debug/macop run --debug -- /usr/bin/true 2>&1 | grep -Fx 'macop: debug exit_code=0 command=run'
	@.build/debug/macop run -- /bin/sh -c 'kill -TERM $$$$'; status=$$?; test $$status -eq 143

# Deliberately non-mutating: no CTK identity is created or deleted.
test-ssh-manual: build
	@python3 scripts/test-ssh-manual.py

build:
	$(SWIFTPM_GIT_SAFE_BARE) swift build

release-build:
	$(SWIFTPM_GIT_SAFE_BARE) swift build -c release

install:
	@bash scripts/build-install.sh

uninstall:
	@bash scripts/uninstall.sh

workflow-lint:
	mise exec -- actionlint

workflow-security:
	@GH_TOKEN="$(GH_TOKEN)" mise exec -- zizmor --persona regular .

secret-scan:
	mise exec -- betterleaks dir .

ci-swift: format-check lint build test test-agent-helper test-invocation test-installation test-no-persistence

ci-workflows: pin-actions-check workflow-lint workflow-security

ci-secrets: secret-scan

ci: ci-workflows ci-swift test-pty ci-secrets

pre-commit:
	.githooks/pre-commit

pin-actions:
	@PINACT_GITHUB_TOKEN="$(PINACT_GITHUB_TOKEN)" mise exec -- pinact run -update -verify-comment -min-age 7

pin-actions-check:
	@PINACT_GITHUB_TOKEN="$(PINACT_GITHUB_TOKEN)" mise exec -- pinact run -check -verify-comment
