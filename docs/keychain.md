# Keychain and configuration

Configure legacy and managed Keychain items, Passwords AutoFill fallback, OTP, credential profiles, and macop's secret I/O boundary.

[Back to the project overview](../README.md)

## Configuration and Keychain providers

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
