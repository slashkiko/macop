SHELL := /bin/bash

.PHONY: setup bootstrap hooks-install
.PHONY: format format-check lint test build
.PHONY: ci ci-swift ci-workflows ci-secrets
.PHONY: pin-actions pin-actions-check
.PHONY: workflow-lint workflow-security
.PHONY: secret-scan pre-commit

TOOLCHAIN_DIR := $(shell xcode-select -p)
SWIFTPM_GIT_SAFE_BARE := GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.bareRepository GIT_CONFIG_VALUE_0=all
PINACT_GITHUB_TOKEN ?= $(shell gh auth token 2>/dev/null || true)
GH_TOKEN ?= $(shell gh auth token 2>/dev/null || true)

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

build:
	$(SWIFTPM_GIT_SAFE_BARE) swift build

workflow-lint:
	mise exec -- actionlint

workflow-security:
	GH_TOKEN="$(GH_TOKEN)" mise exec -- zizmor --persona regular .

secret-scan:
	mise exec -- betterleaks dir .

ci-swift: format-check lint build test

ci-workflows: pin-actions-check workflow-lint workflow-security

ci-secrets: secret-scan

ci: ci-workflows ci-swift ci-secrets

pre-commit:
	.githooks/pre-commit

pin-actions:
	PINACT_GITHUB_TOKEN="$(PINACT_GITHUB_TOKEN)" mise exec -- pinact run -update -verify-comment -min-age 7

pin-actions-check:
	PINACT_GITHUB_TOKEN="$(PINACT_GITHUB_TOKEN)" mise exec -- pinact run -check -verify-comment
