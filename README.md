# macop

Apple-native `op` compatibility CLI for macOS. It resolves configured Keychain
references at the process boundary and uses Secure Enclave-backed SSH identities
without exporting private-key files.

This project is an early source-build preview for macOS 14+. It is not a
1Password backend or vault. Apple Passwords access is user-initiated through
the system AutoFill chooser; macop cannot enumerate or silently query its
database.

## Install from source

Build, sign, verify, and install the CLI, agent, and `MacopAuth.app` companion
in a user-owned bin directory:

```bash
scripts/build-install.sh
```

Run the full local gate before building, or safely create the optional script-compatible
`op -> macop` symlink:

```bash
scripts/build-install.sh --check
scripts/build-install.sh --with-op-symlink
scripts/build-install.sh --configure-path
```

The default remains an ad-hoc source install. For an existing macOS
code-signing identity, use the same identity for every update:

```bash
scripts/build-install.sh --signing-identity 'Developer ID Application: Example (TEAMID)'
```

`MACOP_SIGNING_IDENTITY` is the equivalent environment setting. Stable signing
keeps identifiers and designated requirements stable across updates. A
certificate-backed build without a provisioning profile enables the native
approval UI and verified SSH signing. Setting an absolute
`MACOP_PROVISIONING_PROFILE` path additionally embeds the profile and enables
the managed Data Protection Keychain capability. For that build, the auth
bundle's application identifier and Keychain access-group entitlements are
generated from the selected certificate's Team ID; no Team ID, certificate
name, or profile is stored in the repository. The installer rejects `-` as an
explicitly requested stable identity instead of silently falling back to
ad-hoc signing.

For managed Keychain dogfooding with an Apple Development identity, Xcode can
create or renew a matching development profile without storing its Team ID in
the repository:

```bash
scripts/create-development-profile.sh \
  --signing-identity 'Apple Development: Example (IDENTIFIER)'

MACOP_PROVISIONING_PROFILE="$HOME/Library/Application Support/macop/MacopAuth.provisionprofile" \
  scripts/build-install.sh \
  --signing-identity 'Apple Development: Example (IDENTIFIER)'
```

The profile helper uses Xcode automatic signing and may register the fixed
`io.github.slashkiko.macop.auth` bundle ID and the current Mac with the selected
team. The default output is outside the repository with mode `0600`. Personal
Team profiles normally need periodic renewal; the helper prints the exact
expiration returned by Xcode.

The install directory defaults to `~/.local/bin` and can be changed with
`--bin-dir` or `MACOP_BIN_DIR`. The installer refuses to replace an existing
`op` command or an unrelated `op` symlink. `--configure-path` adds a marked,
installer-managed block to `~/.zprofile` or `~/.bash_profile`; use
`--shell-profile` or `MACOP_SHELL_PROFILE` to select another file. Profile
editing is opt-in and refuses symlinks.

Ensure `$HOME/.local/bin` is on `PATH`. The source-build commands above are
appropriate for the ordinary Keychain and `ssh` wrapper commands, but ad-hoc
signing is deliberately **not** eligible for `macop ssh agent`: same-user
replacement cannot be made safe with an ad-hoc signature. Verified sessions
require a production pair signed by one Apple Developer team (Apple-anchored,
same Team ID, `macop` and `macop-agent` identifiers), with hardened runtime
enabled and library validation not disabled. The installer applies and reads
back those signing properties. Keep the helper as a
regular user-owned, non-group/world-writable sibling; macop resolves its own
image rather than `PATH`, validates both static signatures, and the helper
is spawned suspended. Before any helper code can execute, the parent validates
the live process image against the fixed helper identifier and the already
validated Team ID, then resumes it; the helper also re-validates itself as
defense in depth. Re-run the production signing step for both files after
replacing them.
Keychain authorization prompts can change after an ad-hoc binary update. A
legacy login-Keychain ACL may also show its item authorization dialog followed
by an XARA partition dialog for an ad-hoc client, even though macop performs
only one exact secret-data query. Use a stable signing identity and an explicit
item ACL decision for repeatable local authorization; use `macop doctor` to
inspect prerequisites without printing secrets.

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

The installer can create this symlink with `--with-op-symlink`; the manual form
is retained here to make the PATH behavior explicit.

macop never falls back to a separately installed 1Password `op` binary. Check
the supported boundary with `macop compatibility` before switching scripts.

## Uninstall

Remove the installed executables and an installer-owned `op -> macop` symlink:

```bash
scripts/uninstall.sh
```

The uninstaller verifies the code-signing identifiers before removing the two
executables. It deliberately preserves the install directory, macop
configuration, Keychain items, CTK identities, and unrelated `op` commands.
It removes only its marked PATH block by default; pass `--keep-path` to retain
that block. Use the same `--bin-dir`, `MACOP_BIN_DIR`, `--shell-profile`, or
`MACOP_SHELL_PROFILE` value that was used to install.

To remove every item stored in macop's private managed-Keychain access group,
delete them while the signed CLI and companion are still installed:

```bash
scripts/uninstall.sh --delete-managed-keychain
```

This opt-in path displays the native macop approval window and requires Touch ID
or the Mac login password before deleting the items. It does not delete legacy
generic/internet Keychain entries, configuration, or Secure Enclave identities.

## Keychain and configuration

macop supports legacy generic/internet Keychain mappings and a separate
`keychain-managed` provider. Legacy items are created in Keychain Access. A
managed item is stored by `MacopAuth.app` in the Data Protection Keychain with
`userPresence` access control and is read only after the native approval UI and
Mac authentication succeed. Never put a real secret in a shell command,
repository file, or the JSON below. Initialize the non-secret configuration:

```bash
macop config init
macop config validate
```

The default file is `~/Library/Application Support/macop/config.json`. macop
requires the directory to be owned by the current user with mode `0700`, and
the file to be current-user owned with mode `0600`, with no extended ACL grants. It opens both without
following a final-path symlink and reads the already-validated file descriptor,
rejecting weaker or different permissions rather than attempting to repair them
silently. A generic or internet-password mapping is intentionally valid only
when its selector matches exactly one accessible Keychain item; use distinct
service/account or server/account metadata for items that must coexist.

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

Set `"synchronization": "icloud"` on an individual `keychain-managed` item
to store it as a synchronizable Data Protection Keychain item. The default
(`null` or `"local"`) remains device-local. An iCloud item uses
`kSecAttrAccessibleWhenUnlocked`, because `ThisDeviceOnly` accessibility cannot
sync, while retaining `userPresence` authorization. The other Mac must have
iCloud Keychain enabled and a macop build signed for the same Keychain access
group. Updates and deletions affect the synchronized copies. Cross-Mac
propagation still requires acceptance on a second Mac; local add/read/update/delete
and the synchronizable query contract are covered by the implementation tests.

For a Touch ID-protected managed item, use the same non-secret selector shape
with `"provider": "keychain-managed"`, then pass the secret only over stdin:

```json
{
  "version": 1,
  "items": {
    "Local/GitHub": {
      "provider": "keychain-managed",
      "service": "example-github-token",
      "account": "example-user",
      "fields": ["token"]
    }
  }
}
```

```bash
printf %s "$SECRET_FROM_A_SAFE_SOURCE" | macop item import GitHub
macop read op://Local/GitHub/token
```

`item import` is create-only: it refuses an existing selector and never deletes
or overwrites the source item. The companion and CLI must be certificate-signed
by the same Apple Developer team, and `MacopAuth.app` must be built with a
matching provisioning profile via `MACOP_PROVISIONING_PROFILE`; builds without
that profile do not advertise the managed Keychain capability. Ad-hoc builds
deliberately fail closed.

Configured legacy `keychain-generic` and `keychain-internet` items support
stdin-only create and edit, plus exact-one deletion:

```bash
printf %s "$SECRET_FROM_A_SAFE_SOURCE" | macop item create GitHub
printf %s "$REPLACEMENT_FROM_A_SAFE_SOURCE" | macop item edit GitHub
macop item delete GitHub
```

`create` refuses an existing selector. `edit` and `delete` enumerate opaque
persistent references first and refuse zero or multiple matches, so an
ambiguous service/account or server/account selector never modifies several
Keychain items.

For an interactive credential, `read`, `run`, and `inject` first try the
configured managed Keychain item. If it is missing, macOS opens its Passwords
AutoFill chooser; after selection, macop shows the verified requesting app again
and requires Touch ID or the Mac login password before returning the credential
to the requesting command. The approval window lets you save or update the
selected password in the managed Keychain. Cancellation, authentication errors,
and other Keychain failures never trigger the fallback.
The system chooser is intentionally user-initiated: macop cannot enumerate or
silently query the Passwords database through a public macOS API, and the
current AutoFill workaround obtains the password field but not the username.

`item acquire` performs the same lookup and writes the credential to stdout.
Pass `--from-passwords` to bypass a known-bad cached item explicitly; macop does
not automatically rerun a child command after a remote service rejects a stored
credential.

```bash
macop item acquire GitHub
macop item acquire GitHub --from-passwords
macop item delete GitHub
macop item delete --all-managed
```

`item delete GitHub` uses the configured exact selector. Managed items require
the native macop approval and macOS authentication; legacy items use their
system Keychain access policy.
`--all-managed` is intentionally limited to generic-password items in macop's
private access group and includes local and synchronizable copies. Deleting an
already-missing individual item reports not found.

The supported secret boundary is deliberately narrow:

- `read` and `item acquire` write the requested UTF-8 text secret to stdout.
- `run` resolves references only into its direct child process; it masks matching
  stdout/stderr by default, unless `--no-masking` is explicitly selected.
- `inject` reads a template from stdin or an input file and writes the expanded
  result only to stdout; persistent secret output files are rejected.
- `item list` and `item get` return macop metadata. `item import` accepts exact
  UTF-8 secret bytes from stdin for a configured managed item; `item acquire`
  returns a managed or interactively selected credential; `item create/edit`
  mutate configured legacy items from stdin, and `item delete` removes one
  exactly selected Keychain item. Metadata JSON is a macop schema
  with `schema_version`, not a complete 1Password item schema; `--reveal` is an
  explicit request to expose an item field.
- Resolved secrets exist in process memory while a command is prepared and
  relayed. macop does not guarantee zeroization, locked memory, or protection
  from process memory inspection, core dumps, or swap.

`--out-file`, secret-bearing argv, binary/NUL secrets, and unsupported 1Password
cloud/vault commands are outside this contract.

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
an OpenSSH key, and cannot be moved or synchronized to another Mac. After
creation, macop requires Security.framework to resolve exactly one public key
for the new identity. Resolution failure returns exit 4 and leaves the identity
visible for inspection and explicit `macop ssh delete <label>` cleanup rather
than claiming a usable SSH setup.

`macop ssh run` and `macop ssh test` launch the requested command under a
one-shot verified-session agent. The nested Apple SSH process uses an empty
config (`-F /dev/null`), `PKCS11Provider=none`, `ForwardAgent=no`,
`IdentityFile=none`, `IdentityAgent=SSH_AUTH_SOCK`, and public-key-only
authentication. The session socket exposes exactly the selected identity and
is revoked with the launched root or its fixed deadline. These commands fail
rather than authenticating with a key from the user's SSH config, a default
identity file, another ssh-agent, or a non-public-key fallback.
On macOS, `ssh run` resolves the `/usr/bin/git` developer-tool shim to the
active Xcode/Command Line Tools Git image with xcrun lookup overrides removed
and its mutable cache bypassed. Before launch and again on the suspended live
process, Security.framework requires Apple's `com.apple.git` code requirement
and library-validation flag, then pins the exact image as the verified root.
Git remains suspended through registry activation and approval, and receives
`SIGCONT` only after the session is authorized; rejection kills and reaps it
without allowing its first instruction to run.
It accepts only the `git` and `/usr/bin/git` entry points; renamed or alternate
executables are rejected rather than receiving the verified-session socket.

Generate repository-local Git commit/tag SSH-signing configuration for the same
Secure Enclave identity:

```bash
macop ssh git-signing-config github
# Review the three printed `git config --local` commands, then run them.
git commit -S
git tag -s v1.0.0
```

Git invokes the installed macop binary through its `ssh-keygen -Y sign`
interface. macop accepts only Git's
`-Y sign -n git -f <public-key> <message-file>` shape, requires the direct
parent to be Apple's live Git image, accepts only owner-controlled regular
input files and an owner-controlled signature directory, and refuses
to overwrite an existing `.sig`, matches the configured public key to exactly
one CTK identity, and signs the canonical `SSHSIG` preimage after native macop
approval. The generated envelope is checked by the test suite with Apple
OpenSSH. No private key or stable agent socket is exported.

`macop doctor` enumerates each CTK identity by its public hash, resolves its
public key through Security.framework, and checks the effective isolated SSH
configuration. It does not depend on `/usr/lib/ssh-keychain.dylib`.

The verified-session agent is deliberately constrained. It
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

For one verified session per interactive Terminal tab, add the generated shell
plugin to the relevant startup file:

```bash
export MACOP_SSH_IDENTITY=github
eval "$(macop ssh shell-init zsh)" # use bash or fish as appropriate
```

The plugin replaces the initial interactive shell with
`macop ssh agent shell ... -- $SHELL -l` exactly once, guarded by
`MACOP_SHELL_INTEGRATION_ACTIVE`. The child login shell inherits the private
socket and normal terminal process group. Closing the tab or exiting that shell
ends the registered root and revokes the session/socket; the fixed session
deadline remains an independent upper bound.

Only the socket is passed to the new process. A nonce stays as an opaque
launcher-to-registry reservation capability; it is not read from, or used to
authenticate, the launched root. Requests remain pending until activation;
signing requires OpenSSH session binding and is revoked when the root exits or
the fixed ten-minute session deadline shown in the approval prompt expires. Existing
applications, manually exported socket paths, relays outside the launched
process tree, and alternate direct CTK access paths are intentionally outside
this verified-session contract.

The approval prompt shows the launched root's canonical executable path, the
signature authority/team (when anchored), and an abbreviated cdhash from one
live code-signing snapshot. An ad-hoc or unanchored image is labelled `exact
image pinned; publisher unverified`; it is never represented as a verified
publisher. From that same snapshot, macop builds and validates a final live
requirement containing the exact identifier and cdhash (plus Apple anchor and
Team ID for trusted publishers); the registry stores that same requirement.
The agent rejects a root whose live executable path differs from the exact
command or application executable selected before launch.

With `--debug`, human-readable agent invocations emit one safe
`macop: debug exit_code=N command=ssh` line. JSON error responses retain the
same metadata inside their single error object. Successful agent sessions relay
the launched program's stream unchanged, so they intentionally do not append a
JSON debug record that could corrupt that program's output protocol.

Focused/manual checks:

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
  - Triggered only when configured source/config files change
  - Runs `betterleaks`

All workflows use `jdx/mise-action` and SHA-pinned actions. Swift workflows use `actions/cache` for `.build` and `.swiftpm`.

Action pin updates are automated by `.github/workflows/update-action-pins.yml` (weekly + manual dispatch), which runs `pinact` and opens a PR with updated SHAs.

## Supply-chain update delay

- `.pinact.yml` + `make pin-actions` enforce a minimum release age of 7 days when updating action pins.
- `renovate.json` sets `minimumReleaseAge: 7 days` for GitHub Actions, Swift dependencies, and mise-managed tools.
- Renovate runs weekly via `.github/workflows/renovate.yml`.
