# macop

Apple-native `op` compatibility CLI for macOS. Swift package; the CLI, a one-shot
agent, and the `MacopAuth.app` companion are built and installed together as one
signed generation. `README.md` is the authoritative description of behaviour,
installation and the security model — read it before changing anything that
touches signing, the broker, the Keychain access group, or the installer.

## Build and check

```bash
make            # see the Makefile for the full local gate
```

`scripts/build-install.sh --check` runs the gate that CI runs. Production
installs require a certificate-backed `--signing-identity`; ad-hoc artifacts are
build and test fixtures only.

## Conventions

- Swift formatting and linting are configured in `.swiftformat` and
  `.swiftlint.yml`; run them rather than reformatting by hand.
- Shell scripts under `scripts/` are `set -euo pipefail` and fail through a
  `fail()` helper. Match that.
- Do not put third-party logos or artwork into the product or its icon.
