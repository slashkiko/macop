SHELL := /bin/bash

.PHONY: bootstrap format format-check lint test build ci

TOOLCHAIN_DIR := $(shell xcode-select -p)
SWIFTPM_GIT_SAFE_BARE := GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.bareRepository GIT_CONFIG_VALUE_0=all

bootstrap:
	brew list --versions swiftformat >/dev/null 2>&1 || brew install swiftformat
	brew list --versions swiftlint >/dev/null 2>&1 || brew install swiftlint

format:
	swiftformat .

format-check:
	swiftformat --lint .

lint:
	XCODE_DEFAULT_TOOLCHAIN_OVERRIDE="$(TOOLCHAIN_DIR)" swiftlint lint --strict

test:
	$(SWIFTPM_GIT_SAFE_BARE) swift test

build:
	$(SWIFTPM_GIT_SAFE_BARE) swift build

ci: format-check lint build test
