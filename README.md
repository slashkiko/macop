# macop

Apple-native `op` compatibility CLI for macOS (MVP scaffold).

## Local setup

```bash
make bootstrap
```

`bootstrap` installs these tools when missing:

- `swiftformat`
- `swiftlint`
- `pinact`
- `actionlint`
- `zizmor`

## Local quality commands

```bash
make format
make format-check
make lint
make test
make build
make ci
make workflow-lint
make workflow-security
make pin-actions
make pin-actions-check
```

`make ci` runs the same checks as CI (`pin-actions-check`, `workflow-lint`, `workflow-security`, `format-check`, `lint`, `build`, `test`).
`make lint` sets `XCODE_DEFAULT_TOOLCHAIN_OVERRIDE=$(xcode-select -p)` automatically so SwiftLint can resolve SourceKit in Command Line Tools-only environments.

## CI

GitHub Actions workflow: `.github/workflows/ci.yml`

- Runs on `macos-latest`
- Splits checks into independent parallel jobs (`action-pins`, `workflow-lint`, `workflow-security`, `format-check`, `lint`, `build`, `test`)
- Uses `jdx/mise-action` and `.mise.toml` pinned tool versions
- Uses `actions/cache` for SwiftPM build artifacts (`.build`, `.swiftpm`) in build/test jobs
- Verifies all `uses:` lines are SHA-pinned and version-commented (`make pin-actions-check`)
- Runs `actionlint` and `zizmor`

Action pin updates are automated by `.github/workflows/update-action-pins.yml` (weekly + manual dispatch), which runs `pinact` and opens a PR with updated SHAs.

## Supply-chain update delay

- `.pinact.yml` + `make pin-actions` enforce a minimum release age of 7 days when updating action pins.
- `renovate.json` sets `minimumReleaseAge: 7 days` for GitHub Actions, Swift dependencies, and mise-managed tools.
- Renovate runs weekly via `.github/workflows/renovate.yml`.
