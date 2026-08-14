# macop

Apple-native `op` compatibility CLI for macOS. It resolves configured Keychain
references at the process boundary and uses Secure Enclave-backed SSH identities
without exporting private-key files.

This project is a source-build MVP for a personal macOS 14+ environment. It is
not a 1Password backend, vault, or Apple Passwords reader.

## Install from source

Build the release binary and install it in a user-owned bin directory:

```bash
swift build -c release
mkdir -p "$HOME/.local/bin"
install -m 755 .build/release/macop "$HOME/.local/bin/macop"
install -m 755 .build/release/macop-agent "$HOME/.local/bin/macop-agent"
codesign --force --sign - --identifier macop "$HOME/.local/bin/macop"
codesign --force --sign - --identifier macop-agent "$HOME/.local/bin/macop-agent"
```

Ensure `$HOME/.local/bin` is on `PATH`. `macop-agent` must stay a safe,
user-owned sibling of `macop`; macop resolves its own executable image rather
than the command name used through `PATH`, and accepts only a regular,
user-owned, non-group/world-writable `macop-agent` with a strict valid code
signature whose identifier is `macop-agent`. Re-run `codesign` for both after
replacing them.
Keychain authorization prompts can change after a binary update; use
`macop doctor` to inspect the local prerequisites without printing secrets.

For daily interactive use, an alias is the least surprising option:

```zsh
alias op=macop
eval "$(macop completion zsh)"
```

Aliases are not expanded by ordinary non-interactive scripts. For scripts that
already invoke `op`, install a sibling symlink instead; this intentionally makes
`op` resolve to macop for that `PATH` entry:

```bash
ln -s macop "$HOME/.local/bin/op"
```

macop never falls back to a separately installed 1Password `op` binary. Check
the supported boundary with `macop compatibility` before switching scripts.

## Keychain and configuration

Create the Keychain item before creating its macop mapping. Use Keychain Access
to add a normal login-keychain password item, and enter the secret only in that
UI; do not put a real secret in a shell command, repository file, or the JSON
below. Record its service/account (generic password) or server/account
(internet password), then initialize the non-secret configuration:

```bash
macop config init
macop config validate
```

The default file is `~/Library/Application Support/macop/config.json`. macop
requires the directory to be owned by the current user with mode `0700`, and
the file to be current-user owned with mode `0600`; it rejects weaker or
different permissions rather than attempting to repair them silently.

Only lookup metadata belongs in the file. For example, this is safe because it
contains no secret value:

```json
{
  "version": 1,
  "items": {
    "Local/GitHub": {
      "provider": "keychain-generic",
      "service": "example-github-token",
      "account": "example-user",
      "fields": ["token"]
    }
  }
}
```

The supported secret boundary is deliberately narrow:

- `read` writes the requested UTF-8 text secret to stdout.
- `run` resolves references only into its direct child process; it masks matching
  stdout/stderr by default, unless `--no-masking` is explicitly selected.
- `inject` reads a template from stdin or an input file and writes the expanded
  result only to stdout; persistent secret output files are rejected.
- `item list` and `item get` return macop metadata. Their JSON is a macop schema
  with `schema_version`, not a complete 1Password item schema; `--reveal` is an
  explicit request to expose an item field.

`--out-file`, secret-bearing argv, Apple Passwords access, binary/NUL secrets,
and unsupported 1Password cloud/vault commands are outside this contract.

## Secure Enclave SSH

Create and inspect an identity through macop, then register only the resulting
public key with the Git host:

```bash
macop ssh create github --touch-id
macop ssh public-key github
macop ssh test github
```

`create` uses a Secure Enclave `p-256-ne` identity with Touch ID. The private
key is non-exportable: it is not written under `~/.ssh`, cannot be exported as
an OpenSSH key, and cannot be moved or synchronized to another Mac.

For the Apple provider in a normal SSH configuration, use the macOS provider
and turn forwarding off for that host. Select a host-specific stanza rather
than applying the provider globally:

```sshconfig
Host github.com
  User git
  PKCS11Provider /usr/lib/ssh-keychain.dylib
  IdentitiesOnly yes
  ForwardAgent no
```

Alternatively, `macop ssh run` and `macop ssh test` invoke Apple SSH with the
provider, selected identity, `IdentitiesOnly=yes`, and `ForwardAgent=no`.
Direct use of `/usr/lib/ssh-keychain.dylib` remains possible for the current
user and is outside macop's agent-level controls.

The verified-session agent is a separate, deliberately constrained path. It
may present application- and key-specific approval only for a cooperating
client that macop newly launched or registered. Existing applications,
unregistered clients, non-cooperating clients, external relays, stale sessions,
and agent-forwarded requests are rejected rather than being labeled verified.
Its host-binding policy accepts only `ssh-ed25519` and
`ecdsa-sha2-nistp256` host keys; RSA and host certificates fail closed.

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
`ci-secrets`). `ci-swift` includes the signed-agent helper, alias/symlink, and
fake-Keychain no-persistence fixtures; the deterministic PTY relay runs both in
the macOS workflow and in the broader local `ci` target.
`make pre-commit` runs only the relevant check groups for staged files:

- Workflow-related changes: `ci-workflows`
- Swift/package/tooling changes: `ci-swift`
- Any staged file change: `ci-secrets`

`make lint` sets `XCODE_DEFAULT_TOOLCHAIN_OVERRIDE=$(xcode-select -p)` automatically so SwiftLint can resolve SourceKit in Command Line Tools-only environments.

## Verified SSH sessions

`macop ssh agent` does not expose a login-wide `SSH_AUTH_SOCK`. It starts a
one-shot `macop-agent` service which reserves and listens on a private socket
before launching the requested root process, then verifies that root PID,
start time, code requirement, and process ancestry before enabling signing.

```bash
macop ssh agent shell github -- /usr/bin/ssh git@github.com
macop ssh agent application github /Applications/Example.app
```

Only the socket is passed to the new process. A nonce stays as an opaque
launcher-to-registry reservation capability; it is not read from, or used to
authenticate, the launched root. Requests remain pending until activation;
signing requires OpenSSH session binding and is revoked when the root exits or
the session expires. Existing
applications, manually exported socket paths, relays outside the launched
process tree, and direct `ssh-keychain.dylib` use are intentionally outside
this verified-session contract.

With `--debug`, human-readable agent invocations emit one safe
`macop: debug exit_code=N command=ssh` line. JSON error responses retain the
same metadata inside their single error object. Successful agent sessions relay
the launched program's stream unchanged, so they intentionally do not append a
JSON debug record that could corrupt that program's output protocol.

Focused/manual checks:

- `make test-keychain-integration` creates and removes a dedicated local test
  Keychain item; it may prompt for Keychain access.
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
  - Triggered only when configured source/config files change
  - Runs `betterleaks`

All workflows use `jdx/mise-action` and SHA-pinned actions. Swift workflows use `actions/cache` for `.build` and `.swiftpm`.

Action pin updates are automated by `.github/workflows/update-action-pins.yml` (weekly + manual dispatch), which runs `pinact` and opens a PR with updated SHAs.

## Supply-chain update delay

- `.pinact.yml` + `make pin-actions` enforce a minimum release age of 7 days when updating action pins.
- `renovate.json` sets `minimumReleaseAge: 7 days` for GitHub Actions, Swift dependencies, and mise-managed tools.
- Renovate runs weekly via `.github/workflows/renovate.yml`.
