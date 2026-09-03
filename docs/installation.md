# Installation and removal

Build, sign, install, update, expose as `op`, and remove macop. Run every command below from the repository root.

[Back to the project overview](../README.md)

For a role-by-role walkthrough, open the
[visual personal-signing guide](personal-signing-guide.html). It separates the
certificate choice from source retrieval, profile, signing, verification, and
update steps performed by the shell helper.

## Personal source installation

The supported no-Developer-ID path is a source build signed for the current
user's Mac with an Apple Development identity. The only signing choice the user
makes is which certificate to use; later installs reuse its exact fingerprint.
This is not a redistributable pre-signed binary.

First add the user's Apple ID in Xcode and create an Apple Development
certificate for the selected development team. Clone the repository and start
the one-time setup:

```bash
git clone https://github.com/slashkiko/macop.git
cd macop
scripts/personal-install.sh setup
```

The script displays the available Apple Development certificates and asks for
one number. It configures `~/.local/bin` in PATH by default; pass
`--no-configure-path` only when that is not wanted. For non-interactive use,
`--signing-identity` accepts an exact 40-character SHA-1. When replacing an
already saved identity non-interactively, combine it with `--replace-identity`:

```bash
scripts/personal-install.sh setup \
  --signing-identity NEW_40_CHARACTER_SHA1 \
  --replace-identity
```

The setup stores only the certificate fingerprint in
`~/Library/Application Support/macop/personal-signing-identity` with mode
`0600`. The private key remains in the macOS Keychain. It creates or renews the
matching profile through Xcode automatic signing, then delegates signing,
verification, and publication to the transactional installer.

For each later source update, run one command from the original checkout:

```bash
scripts/personal-install.sh update
```

`update` does not modify that checkout. It fresh-clones
`https://github.com/slashkiko/macop.git` at `main` into a temporary directory,
runs the cloned updater, and removes the temporary clone. GitHub Actions is
trusted as the source CI gate; the updater does not rerun `make ci` locally. A
clone, profile, or signing failure occurs before publication, and an installation
failure is rolled back by `build-install.sh`.

If Xcode rotates or replaces the development certificate, run setup again and
choose the replacement from the menu. The existing installer still requires the
installed and replacement generations to have the same Team ID, and the saved
fingerprint changes only after a successful installation:

```bash
scripts/personal-install.sh setup --replace-identity
```

Personal Team profiles expire and may need Xcode account access or network
access to renew. `update` renews the profile before each build and stops without
replacing the installed generation if renewal fails. Xcode must be able to issue
a profile that authorizes macop's Keychain groups; setup reports an error rather
than weakening those entitlements when the selected team cannot do so.

## Manual signing and installation

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

## `op` compatibility

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
