# macop

Apple-native `op` compatibility CLI for macOS (MVP scaffold).

## Local setup

```bash
make bootstrap
```

`bootstrap` installs these tools when missing:

- `swiftformat`
- `swiftlint`

## Local quality commands

```bash
make format
make format-check
make lint
make test
make build
make ci
make pin-actions
make pin-actions-check
```

`make ci` runs the same checks as CI (`format-check`, `lint`, `build`, `test`).
`make lint` sets `XCODE_DEFAULT_TOOLCHAIN_OVERRIDE=$(xcode-select -p)` automatically so SwiftLint can resolve SourceKit in Command Line Tools-only environments.

## CI

GitHub Actions workflow: `.github/workflows/ci.yml`

- Runs on `macos-latest`
- Uses `swift-actions/setup-swift` with Swift `6.2`
- Installs `swiftformat` / `swiftlint`
- Installs `pinact`
- Verifies all `uses:` lines are SHA-pinned and version-commented (`make pin-actions-check`)
- Runs `make ci`

Action pin updates are automated by `.github/workflows/update-action-pins.yml` (weekly + manual dispatch), which runs `pinact` and opens a PR with updated SHAs.
