# macop

Apple-native `op` compatibility CLI for macOS. It resolves configured Keychain
references at the process boundary and uses Secure Enclave-backed SSH identities
without exporting private-key files.

This project is an early source-build preview for macOS 15+. It is not a
1Password backend or vault. Apple Passwords access is user-initiated through
the system AutoFill chooser; macop cannot enumerate or silently query its
database.

## Install from source

Build, sign, verify, and install the CLI, agent, and `MacopAuth.app` companion
in a user-owned bin directory:

```bash
MACOP_PROVISIONING_PROFILE="$HOME/Library/Application Support/macop/MacopAuth.provisionprofile" \
scripts/build-install.sh --signing-identity 'Apple Development: Example (IDENTIFIER)'
```

Production installation requires an explicit certificate-backed
`--signing-identity` and a regular matching `MACOP_PROVISIONING_PROFILE`.
Ad-hoc artifacts remain supported only by the owner-only temporary installer
fixture; they cannot satisfy the same-Team live broker verification.

Run the full local gate before building, or safely create the optional script-compatible
`op -> macop` symlink:

```bash
MACOP_PROVISIONING_PROFILE="$HOME/Library/Application Support/macop/MacopAuth.provisionprofile" scripts/build-install.sh --check --signing-identity 'Apple Development: Example (IDENTIFIER)'
MACOP_PROVISIONING_PROFILE="$HOME/Library/Application Support/macop/MacopAuth.provisionprofile" scripts/build-install.sh --with-op-symlink --signing-identity 'Apple Development: Example (IDENTIFIER)'
MACOP_PROVISIONING_PROFILE="$HOME/Library/Application Support/macop/MacopAuth.provisionprofile" scripts/build-install.sh --configure-path --signing-identity 'Apple Development: Example (IDENTIFIER)'
```

Use the same certificate-backed identity and matching profile for every update:

```bash
MACOP_PROVISIONING_PROFILE="$HOME/Library/Application Support/macop/MacopAuth.provisionprofile" \
scripts/build-install.sh --signing-identity 'Developer ID Application: Example (TEAMID)'
```

`MACOP_SIGNING_IDENTITY` is the equivalent environment setting. Stable signing
keeps identifiers and designated requirements stable across updates. A
matching absolute `MACOP_PROVISIONING_PROFILE` path embeds the profile and
enables the managed Data Protection Keychain capability. For that build, the auth
bundle's application identifier and Keychain access-group entitlements are
generated from the selected certificate's Team ID; no Team ID, certificate
name, or profile is stored in the repository. The installer rejects `-`
instead of silently falling back to ad-hoc signing; ad-hoc builds are build/test
fixtures only.

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

Each installation is published as one broker generation: the CLI, one-shot
agent, companion app, and `macop-install-manifest.json` are staged and
preflighted before replacement. The manifest records the build generation,
protocol v9, executable hashes, and code identities. An atomic per-directory
installer lock rejects concurrent updates; an interrupted update rolls every
component back to the prior generation. `macop doctor` fails closed when an
installed generation is missing, mixed, or does not match its manifest.
Before committing, the installer launches the installed companion in a
background probe, verifies its same-Team peer identity and required
approval/SSH-signing/direct-key capabilities through a protocol-v9 hello/welcome, then
closes without reading protected state, requesting approval, or mutating trust
data. A source build that cannot satisfy this broker boundary is rolled back.
`macop doctor` reports the companion bundle's presence, its signature and
same-Team identity, the non-secret socket probe, and the negotiated current
wire version separately. Broker-facing CLI failures use one safe category:
`companion_unavailable`, `identity_invalid`, `protocol_mismatch`,
`transport_failure`, or `user_denied`. The output includes a recovery action
but never prints a socket path, request data, or secret.
An active one-shot agent session blocks publication rather than being stopped
under its caller. It is not automatically restarted: after its command exits,
the next `macop ssh agent` invocation creates a new session from the installed
generation. The MacopAuth bundle contract combines the executable's
CodeDirectory digest with `codesign --verify --deep --strict`; sealed bundle
resources such as Info.plist and the embedded profile are verified before a
manifest digest or identity is accepted.

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
It also preserves the machine-local trusted Git client registry. Remove only
that registry (not config.json, Keychain items, or CTK identities) with:

```bash
scripts/uninstall.sh --remove-data
```

It removes only its marked PATH block by default; pass `--keep-path` to retain
that block. Use the same `--bin-dir`, `MACOP_BIN_DIR`, `--shell-profile`, or
`MACOP_SHELL_PROFILE` value that was used to install.

It also removes a recognized generation manifest, but refuses to run through a
live installer lock and preserves stale transaction journals for recovery.

To remove every item stored in macop's private managed-Keychain access group,
delete them while the signed CLI and companion are still installed:

```bash
scripts/uninstall.sh --delete-managed-keychain
```

This opt-in path displays the native macop approval window and requires Touch ID,
Apple Watch, or the Mac login password before deleting the items. It also removes
separately stored macop-managed OTP seeds. It does not delete legacy
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
silently. Reads, edits, and deletes for generic or internet-password mappings
require selectors that match exactly one accessible Keychain item. Creates and
non-replacing generation instead require zero matches before adding, followed
by exact postflight verification. Use distinct service/account or
server/account metadata for items that must coexist.

Only lookup metadata belongs in the file. For example, this is safe because it
contains no secret value:

```json
{
  "version": 2,
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

`config init` now creates schema version 2. Version 1 remains readable with its
original custom-field behavior: names such as `username` and `password` still
resolve the stored secret. Version 2 opts into well-known username/password
fields, OTP metadata, credential profiles, and SSH host aliases. Add or migrate
those entries only after changing the document version to 2; macop rejects v2
keys in a v1 document instead of silently changing their meaning.
Legacy generic/internet selectors keep the v1 acceptance contract. A v1
`keychain-managed` selector must still fit the broker's bounded, display-safe
wire metadata because every managed operation crosses that authenticated
boundary.

Set `"synchronization": "icloud"` on an individual `keychain-managed` item
to store it as a synchronizable Data Protection Keychain item. The default
(`null` or `"local"`) remains device-local. An iCloud item uses
`kSecAttrAccessibleWhenUnlocked`, because `ThisDeviceOnly` accessibility cannot
sync, while retaining `userPresence` authorization. The other Mac must have
iCloud Keychain enabled and a macop build signed for the same Keychain access
group. Updates and deletions affect the synchronized copies. Cross-Mac
propagation still requires acceptance on a second Mac; local add/read/update/delete
and the synchronizable query contract are covered by the implementation tests.

For a user-presence-protected managed item, use the same non-secret selector shape
with `"provider": "keychain-managed"`, then pass the secret only over stdin:

```json
{
  "version": 2,
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

`item list` prints canonical keys such as `Dogfood/Managed`. Every item command
accepts that full key unchanged. A leaf such as `Managed` remains supported for
backward compatibility only when it is unique among providers supported by the
operation; otherwise macop reports the candidate full keys and requires one of
them explicitly.

`create` requires a zero-match preflight, captures the persistent reference
returned by the add, and postflight-verifies that it is the selector's only
match. If a concurrent add makes the selector ambiguous, macop rolls back only
its returned reference, never every broad selector match. A missing returned
reference or unconfirmed targeted rollback is reported as indeterminate with
manual selector-reconciliation guidance. `edit` and `delete` enumerate opaque
persistent references first and refuse zero or multiple matches, so an
ambiguous service/account or server/account selector never modifies several
Keychain items.

The well-known `username` field resolves the configured `account` metadata
without reading secret data. `password` resolves Keychain secret data, while
the existing `token` spelling remains backward-compatible:

```bash
macop read op://Local/GitHub/username
macop read op://Local/GitHub/password
macop read op://Local/GitHub/token
```

Generate a password explicitly to stdout, or generate and save it without
returning the value to the shell. Generation uses `SecRandomCopyBytes` and
rejection sampling:

```bash
macop generate password --length 40 --exclude 'O0l1'
macop item generate GitHub --length 40
macop item generate --replace GitHub --length 40
```

For an interactive credential, `read`, `run`, and `inject` first try the
configured managed Keychain item. If it is missing, macOS opens its Passwords
AutoFill chooser; after selection, macop shows the verified requesting app again
and requires Touch ID, Apple Watch, or the Mac login password before returning the credential
to the requesting command. The approval window lets you save or update the
selected password in the managed Keychain. Cancellation, authentication errors,
and other Keychain failures never trigger the fallback.
The system chooser is intentionally user-initiated: macop cannot enumerate or
silently query the Passwords database through a public macOS API, and the
AutoFill can populate both fields. If it does not return a username, the user
must enter the configured account explicitly; a different username is rejected
instead of being silently saved under the configured account.
The CLI requires broker protocol v9, its closed operation-specific approval-purpose enum,
username attestation, and explicit committed/failed/indeterminate mutation outcomes;
an older companion cannot satisfy the handshake and is never allowed to
substitute the configured account for an unverified username.
After request transmission, response ID/type, username, save outcome, and
OSStatus combinations are validated as one closed contract. A malformed or
lost response is reported as indeterminate because selection or saving may
have occurred; the credential is never used. The native result UI separately
reports the known Keychain save state and whether delivery to the CLI was
confirmed.

An optional `otp` object stores only non-secret TOTP metadata. Its seed is a
separate managed Keychain item and is imported from unpadded Base32 or a strict
`otpauth://totp/` URI over stdin:

```json
"otp": {
  "service": "example-github-otp",
  "account": "example-user",
  "algorithm": "SHA1",
  "digits": 6,
  "period": 30,
  "label": "Example:example-user",
  "issuer": "Example"
}
```

```bash
secure-source-command | macop item otp import GitHub
secure-source-command | macop item otp edit GitHub
macop item otp delete GitHub
macop item otp GitHub
macop read 'op://Local/GitHub/password?attribute=otp'
```

Only SHA-1, SHA-256, and SHA-512 RFC 6238 TOTP are accepted. macop emits only
the current code after authorization. Base32 must be canonical, unpadded RFC
4648. For an `otpauth` import, algorithm, digits, period, label, and issuer must
exactly match the non-secret config metadata before any Keychain operation.

Top-level `profiles` bind an exact canonical executable to an explicit mapping
of environment variable names to static secret references. macop never invokes
a shell:

```json
"profiles": {
  "example": {
    "executable": "/usr/bin/example-cli",
    "environment": { "EXAMPLE_TOKEN": "op://Local/GitHub/token" }
  }
}
```

```bash
macop profile run example -- /usr/bin/example-cli status
eval "$(macop profile shell-init example zsh)"
```

`profile shell-init` emits zsh, bash, or fish syntax and preserves an explicit
`--config` directory in the generated wrapper. All three shells escape literal
apostrophe Unicode scalars; Fish uses its own encoder for both apostrophes and
backslashes. Selftest executes adversarial zsh/bash wrappers, always checks the
Fish parsing contract, and executes Fish when a safe absolute executable is
found through `PATH` (including Nix or MacPorts-style locations).

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
system Keychain access policy. When an item has a separate OTP seed, macop
deletes the primary item first so a missing, ambiguous, cancelled, or failed
primary operation cannot destroy the seed. If the later OTP deletion is
definitively denied, the error reports primary-deleted/seed-retained. If its
broker response is lost, macop reports the seed state as indeterminate and
gives an idempotent `item otp delete` reconciliation action without including
the item name or seed.
`--all-managed` is intentionally limited to generic-password items in macop's
private access group and includes local and synchronizable copies. Deleting an
already-missing individual item reports not found.

The supported secret boundary is deliberately narrow:

- `read` and `item acquire` write the requested UTF-8 text secret to stdout.
- `run` resolves references only into its direct child process; it masks matching
  stdout/stderr by default, unless `--no-masking` is explicitly selected.
- `inject` reads a template from stdin or an input file and writes the expanded
  result only to stdout; persistent secret output files are rejected.
- `generate password` is the explicit stdout-producing generator. `item
  generate` creates a new exact item; `item generate --replace` rotates an
  existing exact item. Both send the value directly to the selected Keychain
  mutation boundary. Legacy create uses zero-match preflight plus a
  persistent-reference postflight, including broad internet-password selectors
  whose existing items differ only by path or protocol. Concurrent ambiguity
  rolls back only the item created by that operation.
- `item otp` and `?attribute=otp` expose only the current code; OTP seed import
  and edit are stdin-only, deletion is explicit, and the seed is stored as a
  separate managed Keychain item. OTP reads never use Passwords AutoFill.
- `profile run` accepts only its configured canonical absolute executable and
  resolves only the profile's declared secret-reference environment keys.
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

On macOS 15 or later, an existing CTK identity can be moved to MacopAuth's
private direct Secure Enclave backend. The direct key allows Touch ID, Apple
Watch, or the local Mac password at each signature. Migration is deliberately
staged; macop never assumes that a public key was registered externally and
never deletes the legacy key automatically:

```bash
macop ssh migration prepare github
macop ssh migration public-key github
# Register the printed direct public key at the remote service.
macop ssh migration confirm-registered github
# Prove that the registered candidate can authenticate while legacy remains default.
macop ssh test github --migration-candidate
macop ssh migration activate github
# Confirm the normal path now selects the same direct key.
macop ssh test github
macop ssh git-signing-config github
# After SSH and Git signing checks succeed:
macop ssh migration retire github
macop ssh delete github
macop ssh migration confirm-retired github
```

`macop ssh migration status [label]` reports a human-readable `state revision`
rather than an internal “generation n”. Before `activate`, the verified session
continues to select the exact legacy fingerprint recorded at `prepare`. From
`active` onward it selects only the protected direct key ID and public key.
`ssh test <label> [destination] --migration-candidate` is accepted only in
`externally_registered`; it temporarily exposes that entry's exact protected
direct key to the one-shot test session without changing the selected backend.
This proof must succeed before `activate`.
`rollback` is available from `externally_registered`, `active`, and `retiring`.
`delete-prepared` removes only a never-activated direct key; it uses a recoverable
`deleting` marker and cannot delete an active or retired direct key.
`migration orphans` lists direct keys that are not referenced by protected
state after an interrupted prepare. `delete-orphan` deletes exactly one such
ID and public key after a separate approval; it never performs a broad label delete.

`macop ssh run` and `macop ssh test` launch the requested command under a
one-shot verified-session agent. The nested Apple SSH process uses an empty
config (`-F /dev/null`), `PKCS11Provider=none`, `ForwardAgent=no`,
`IdentityFile=none`, `IdentityAgent=SSH_AUTH_SOCK`, and public-key-only
authentication. The session socket exposes exactly the selected identity and
is revoked with the launched root or its fixed deadline. These commands fail
rather than authenticating with a key from the user's SSH config, a default
identity file, another ssh-agent, or a non-public-key fallback.
For shell and command sessions, the already verified `macop-agent` process is
the stable registry root. The requested program is spawned in the suspended
state and its live code identity is pinned before the approval UI is shown. It
receives `SIGCONT` only after registry activation, approval, signer installation,
and agent authorization all finish; rejection kills and reaps it without allowing
its first instruction to run. This also supports shells that legitimately replace
their own image after launch without weakening the registry root's live-code
requirement.
On macOS, `ssh run` resolves the `/usr/bin/git` developer-tool shim to the
active Xcode/Command Line Tools Git image with xcrun lookup overrides removed
and its mutable cache bypassed. Before launch and again on the suspended live
process, Security.framework requires Apple's `com.apple.git` code requirement
and library-validation flag, then pins the exact image as the verified root.
Git remains suspended through registry activation and approval, and receives
`SIGCONT` only after the session is authorized; rejection kills and reaps it
without allowing its first instruction to run.
It accepts only the `git` and `/usr/bin/git` entry points. The non-Apple Git
registry described below is intentionally not used by `ssh run`; registered
paths authorize only Git's direct signing/verification adapter and never grant
a verified-session agent socket.

The optional top-level `ssh_hosts` object maps a safe alias to public connection
metadata and one Secure Enclave identity label:

```json
"ssh_hosts": {
  "example": {
    "hostname": "example.com", "user": "git", "port": 22, "identity": "github"
  }
}
```

`macop ssh connect example` launches Apple OpenSSH under the same one-shot
verified session and exposes only that identity. Extra SSH options are not
accepted, so forwarding cannot override `ForwardAgent=no`. `macop ssh
host-config [example]` renders only public host metadata.

Generate repository-local Git commit/tag SSH-signing configuration for the same
Secure Enclave identity:

```bash
macop ssh git-signing-config github
# Review the three printed `git config --local` commands, then run them.
git commit -S
git tag -s v1.0.0
```

Git invokes the installed macop binary through its `ssh-keygen -Y sign`
interface. macop accepts only Git's legacy
`-Y sign -n git -f <public-key> <message-file>` shape or Apple Git's exact
`-Y sign -n git -f <public-key> -U <message-file>` agent-key shape, requires the direct
parent to be Apple's live Git image or an explicitly pinned non-Apple Git image,
accepts only owner-controlled regular
input files and an owner-controlled signature directory, and refuses
to overwrite an existing `.sig`, matches the configured public key to exactly
one backend selected by the protected migration state, and signs the canonical `SSHSIG` preimage after native macop
approval. The generated envelope is checked by the test suite with Apple
OpenSSH. No private key or stable agent socket is exported.

The same adapter supports Git verification without becoming a general
`ssh-keygen` proxy. After revalidating the direct Apple Git parent or an explicitly
registered non-Apple Git image, macop accepts
only Git's exact `find-principals`, `verify -n git`, and `check-novalidate -n git`
forms with bounded arguments and an exact verify-time, then replaces itself
with `/usr/bin/ssh-keygen` so stdin, stdout, stderr, and the exit status remain
native. Other `-Y` operations, reordered flags, and extra options fail closed.

Apple Git needs no registration. To use Homebrew or another non-Apple Git,
review and explicitly pin its selector path to the exact canonical image,
identifier, and cdhash on this Mac:

```bash
macop ssh git-client trust /opt/homebrew/bin/git
macop ssh git-client list
macop ssh git-client remove /opt/homebrew/bin/git
macop ssh git-client migrate # authenticated one-time migration from a v1 registry
macop ssh git-client reset   # authenticated recovery after protected-state loss
```

The owner-only registry is stored at
`~/Library/Application Support/macop/git-clients.json`. A package upgrade,
selector retarget, identifier change, or cdhash change fails closed; inspect the
new binary and run `trust` again. The displayed `git --version` is informational
and is not part of the trust decision. The v2 registry is canonicalized as a
whole document and MacopAuth stores only its generation and SHA-256 digest in
its private Data Protection Keychain access group. The CLI and agent never read
that state: they must obtain a same-Team broker verification for the exact
document before using a registered Git client. A protocol mismatch means all
three components should be updated together before retrying. v1 files are
inspection-only; use `git-client migrate` to re-resolve and approve every live
identity, or `git-client reset` after protected-state loss.

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
