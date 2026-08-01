# macop

Apple-native `op` compatibility CLI for macOS (MVP scaffold).

## Local setup

```bash
make setup
```

`setup` does all first-time local setup:

1. Installs required tools with `mise`
2. Enables repository hooks via `git config --local core.hooksPath .githooks`

Installed tools:

- `swiftformat`
- `swiftlint`
- `pinact`
- `actionlint`
- `zizmor`
- `betterleaks`

## Local quality commands

```bash
make setup
make bootstrap
make hooks-install
make format
make format-check
make lint
make test
make build
make ci-swift
make ci-workflows
make ci-secrets
make ci
make workflow-lint
make workflow-security
make secret-scan
make pre-commit
make pin-actions
make pin-actions-check
```

`make ci` runs all local checks (`ci-workflows` + `ci-swift` + `ci-secrets`).
`make pre-commit` runs only the relevant check groups for staged files:

- Workflow-related changes: `ci-workflows`
- Swift/package/tooling changes: `ci-swift`
- Any staged file change: `ci-secrets`

`make lint` sets `XCODE_DEFAULT_TOOLCHAIN_OVERRIDE=$(xcode-select -p)` automatically so SwiftLint can resolve SourceKit in Command Line Tools-only environments.

## CI

CI is split into path-scoped workflows:

- `.github/workflows/swift-quality.yml`
  - Triggered only when Swift/package/tooling files change
  - Runs `format-check`, `lint`, `build`, `test`
- `.github/workflows/workflow-governance.yml`
  - Triggered only when workflow/governance files change
  - Runs `pin-actions-check`, `workflow-lint`, `workflow-security`
- `.github/workflows/secret-scan.yml`
  - Triggered only when configured source/config files change
  - Runs `betterleaks`

All workflows use `jdx/mise-action` and SHA-pinned actions. Swift workflows use `actions/cache` for `.build` and `.swiftpm`.

Action pin updates are automated by `.github/workflows/update-action-pins.yml` (weekly + manual dispatch), which runs `pinact` and opens a PR with updated SHAs.

## Supply-chain update delay

- `.pinact.yml` + `make pin-actions` enforce a minimum release age of 7 days when updating action pins.
- `renovate.json` sets `minimumReleaseAge: 7 days` for GitHub Actions, Swift dependencies, and mise-managed tools.
- Renovate runs weekly via `.github/workflows/renovate.yml`.
