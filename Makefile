SHELL := /bin/bash

.PHONY: bootstrap format format-check lint test build ci
.PHONY: pin-actions pin-actions-check
.PHONY: workflow-lint workflow-security

TOOLCHAIN_DIR := $(shell xcode-select -p)
SWIFTPM_GIT_SAFE_BARE := GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.bareRepository GIT_CONFIG_VALUE_0=all

bootstrap:
	mise install

format:
	mise exec -- swiftformat .

format-check:
	mise exec -- swiftformat --lint .

lint:
	XCODE_DEFAULT_TOOLCHAIN_OVERRIDE="$(TOOLCHAIN_DIR)" mise exec -- swiftlint lint --strict

test:
	$(SWIFTPM_GIT_SAFE_BARE) swift test

build:
	$(SWIFTPM_GIT_SAFE_BARE) swift build

workflow-lint:
	mise exec -- actionlint

workflow-security:
	mise exec -- zizmor --persona regular .

ci: pin-actions-check workflow-lint workflow-security format-check lint build test

pin-actions:
	mise exec -- pinact run -update -verify-comment

pin-actions-check:
	mise exec -- pinact run -check -verify-comment
