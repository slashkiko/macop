# Development and CI

Set up the repository, run its quality gates and focused checks, and understand the path-scoped CI and dependency-update policy.

[Back to the project overview](../README.md)

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
make test-agent-helper
make test-invocation
make test-personal-install
make test-no-persistence
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
make help
```

`make ci` runs all local checks (`ci-workflows` + `ci-swift` + `test-pty` +
`ci-secrets`). `ci-swift` includes the signed-agent helper, personal-signing
wrapper validation (including fresh-clone update success and failure fixtures),
alias/symlink, and fake-Keychain no-persistence fixtures;
the deterministic PTY relay runs both in the macOS workflow and in the broader
local `ci` target.
`make pre-commit` runs only the relevant check groups for staged files:

- `.github/workflows/**`, `.pinact.yml`, or `Makefile`: `ci-workflows`
- `Sources/**`, `Resources/**`, `Tests/**`, `scripts/**`, `Package.swift`,
  `.swiftformat`, `.swiftlint.yml`, `.mise.toml`, or `Makefile`: `ci-swift`
- Any staged file change: `ci-secrets`

`make lint` sets `XCODE_DEFAULT_TOOLCHAIN_OVERRIDE=$(xcode-select -p)` automatically so SwiftLint can resolve SourceKit in Command Line Tools-only environments.

## Focused and manual checks

- `MACOP_TEAM_SIGNED_MAIN=/path/to/macop MACOP_TEAM_SIGNED_HELPER=/path/to/macop-agent swift run macop-selftest`
  enables the gated integration check for a production Apple-anchored,
  same-Team, hardened-runtime signed pair with library validation enabled,
  including a suspended live helper launch; ordinary
  ad-hoc CI exercises the negative policy and suspended pre-execution rejection
  instead.
- `make test-keychain-integration` creates and removes a dedicated local test
  Keychain item; it may prompt for Keychain access.
- `MACOP_KEYCHAIN_AUTH_REFERENCE='keychain://generic/service/account' make test-keychain-auth-ui`
  performs a read against an existing ACL-protected item, discards the secret,
  and requires the operator to confirm that exactly one authentication dialog
  appeared. It does not create, update, or delete Keychain items. Legacy login
  Keychain ACLs can present two system-managed dialogs inside the single exact
  value lookup; the fixture intentionally fails in that case. macop does not
  weaken exact-one selection, retrieve multiple candidate secrets, or rewrite
  an item's ACL to hide those dialogs. Set
  `MACOP_KEYCHAIN_AUTH_EXECUTABLE="$HOME/.local/bin/macop"` to validate a
  stably signed installed binary instead of the default debug build.
- `make test-pty` verifies interactive relay and signal behavior.
- `make test-invocation` exercises the documented `alias op=macop` and sibling
  `op -> macop` symlink installation modes in a temporary PATH.
- `make test-no-persistence` uses the self-test's fake Keychain client to check
  a runtime-generated secret through a real config mapping. It checks child
  argv and safe debug output, then scans dedicated HOME/config/tmp/log roots;
  `inject` output is verified and discarded in memory. The fake-provider seam
  receives the secret over an inherited test-only pipe, outside argv and env.
- `make test-ssh-manual` is non-mutating and reports Apple SSH/CTK prerequisites;
  it does not create or delete an identity.

## CI

CI is split into path-scoped workflows:

- `.github/workflows/swift-quality.yml`
  - Triggered only when Swift/package/tooling or `scripts/**` files change
  - Runs `make ci-swift` and the deterministic `make test-pty` fixture
- `.github/workflows/workflow-governance.yml`
  - Triggered only when workflow/governance files change
  - Runs `pin-actions-check`, `workflow-lint`, `workflow-security`
- `.github/workflows/secret-scan.yml`
  - Triggered for every pull request and every push to `main`
  - Runs `betterleaks`

Workflows that run mise-managed tools use `jdx/mise-action`. All third-party
actions are SHA-pinned. Swift workflows use `actions/cache` for `.build` and
`.swiftpm`; the scheduled Renovate workflow runs its pinned action directly.

Action pin updates are automated by `.github/workflows/update-action-pins.yml` (weekly + manual dispatch), which runs `pinact` and opens a PR with updated SHAs.

## Supply-chain update delay

- `.pinact.yml` + `make pin-actions` enforce a minimum release age of 7 days when updating action pins.
- `renovate.json` sets `minimumReleaseAge: 7 days` for GitHub Actions, Swift dependencies, and mise-managed tools.
- Renovate runs weekly via `.github/workflows/renovate.yml`.
