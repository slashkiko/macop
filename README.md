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
```

`make ci` runs the same checks as CI (`format-check`, `lint`, `build`, `test`).
`make lint` sets `XCODE_DEFAULT_TOOLCHAIN_OVERRIDE=$(xcode-select -p)` automatically so SwiftLint can resolve SourceKit in Command Line Tools-only environments.

## CI

GitHub Actions workflow: `.github/workflows/ci.yml`

- Runs on `macos-latest`
- Uses `swiftlang/setup-swift@v2` with Swift `6.2`
- Installs `swiftformat` / `swiftlint`
- Runs `make ci`
