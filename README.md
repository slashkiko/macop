<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="design/icon/png/macop-lockup-1600-reversed.png">
    <source media="(prefers-color-scheme: light)" srcset="design/icon/png/macop-lockup-1600.png">
    <img src="design/icon/png/macop-lockup-1600.png" width="520" alt="macop">
  </picture>

  <p><strong>Apple-native <code>op</code> compatibility for macOS.</strong></p>
  <p>Keychain-backed secrets and Secure Enclave SSH identities, without private-key files.</p>
</div>

macop resolves configured Keychain references at the process boundary, runs
commands with narrowly delivered credentials, and signs SSH or Git operations
with hardware-backed identities.

> [!IMPORTANT]
> macop is an early source-build preview for macOS 15+. It is not a 1Password
> backend or vault, and it implements a deliberately limited `op` compatibility
> surface. Check `macop compatibility` before switching existing scripts.

## Why macop

- Resolve `op://`-style references from the macOS Keychain.
- Store managed credentials behind native approval and macOS authentication.
- Use non-exportable Secure Enclave identities for SSH and Git signing.
- Launch one-shot, identity-bound SSH agent sessions instead of exposing a
  login-wide agent socket.
- Install the CLI, agent, and `MacopAuth.app` as one signed generation that
  fails closed when its components do not match.

Apple Passwords access remains user-initiated through the system AutoFill
chooser. macop cannot enumerate or silently query the Passwords database.

## Install from source

Clone the repository, then build, sign, verify, and install all components:

```bash
git clone https://github.com/slashkiko/macop.git
cd macop

MACOP_PROVISIONING_PROFILE="$HOME/Library/Application Support/macop/MacopAuth.provisionprofile" \
  scripts/build-install.sh \
  --signing-identity 'Apple Development: Example (IDENTIFIER)'
```

A production installation requires a certificate-backed signing identity and a
matching provisioning profile. Ad-hoc artifacts are test fixtures and cannot
satisfy the live broker or verified SSH-session boundary.

See [Installation and removal](docs/installation.md) for profile creation,
updates, PATH configuration, the optional `op` symlink, and uninstalling.

## Start here

Initialize and inspect the non-secret configuration:

```bash
macop config init
macop config validate
macop compatibility
macop doctor
```

After adding a Keychain mapping, resolve a field or run a command with a mapped
credential:

```bash
macop read op://Local/GitHub/token
export GH_TOKEN='op://Local/GitHub/token'
macop run -- gh api user
```

Create a Secure Enclave SSH identity and print its public key:

```bash
macop ssh create github --touch-id
macop ssh public-key github
```

Register the printed public key with GitHub, then test the identity:

```bash
macop ssh test github
```

The detailed examples and configuration schema are in the guides below.

## Documentation

- **[Installation and removal](docs/installation.md):** signing, provisioning,
  updates, `op` compatibility, and uninstalling.
- **[Keychain and configuration](docs/keychain.md):** providers, managed items,
  Passwords AutoFill, OTP, profiles, and secret I/O.
- **[Secure Enclave SSH](docs/secure-enclave-ssh.md):** identity lifecycle,
  migration, verified sessions, and Git signing.
- **[Security model](docs/security-model.md):** trust boundaries, fail-closed
  behavior, and explicit non-goals.
- **[Development and CI](docs/development.md):** local setup, quality gates,
  manual checks, CI, and dependency updates.

Design history and the Phase 0 feasibility result remain available in
[the design document](docs/macop-design.md) and
[the SSH feasibility report](docs/macop-phase0-feasibility-2026-08-14.md).

## Security boundaries

- Real secret values do not belong in configuration, shell arguments, or the
  repository. Secret-accepting mutation commands read from stdin.
- Commands that explicitly read, generate, or inject a secret may expose it to
  stdout or a direct child process. Resolved values exist in process memory;
  macop does not promise zeroization, locked memory, or protection from process
  inspection, core dumps, or swap.
- Secure Enclave private keys are non-exportable. Verified sessions reject
  unregistered clients, relays, agent forwarding, stale sessions, and mismatched
  live process identities.
- macop never falls back to a separately installed 1Password `op` binary.
- Signing, broker, Keychain, and installer checks fail closed when identity,
  protocol, ownership, permissions, or generation state is ambiguous.

Read the [security model](docs/security-model.md) before deploying macop or
changing signing, broker, Keychain, SSH-agent, or installer behavior.

## Development

```bash
make setup
make ci
```

See [Development and CI](docs/development.md) for focused checks and workflow
details. All third-party GitHub Actions are SHA-pinned, and automated dependency
updates observe a minimum release age of seven days.

## License and security reports

macop is **source-available, not open source**. Personal and commercial use and
exact, unmodified redistribution are allowed; modified or derivative versions
are not. See [LICENSE](LICENSE) for the complete terms.

External contributions and modified versions are not accepted. Report security
issues privately as described in the [security policy](.github/SECURITY.md).

macop is an independent project and is not affiliated with or endorsed by
Apple Inc. Apple and macOS are trademarks of Apple Inc.
