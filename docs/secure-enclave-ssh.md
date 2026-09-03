# Secure Enclave SSH

Create and migrate Secure Enclave identities, run constrained SSH sessions, and configure Git signing without exporting private keys.

[Back to the project overview](../README.md)

## Identity lifecycle and migration

Create an identity through macop and print its public key:

```bash
macop ssh create github --touch-id
macop ssh public-key github
```

Register the printed public key with the Git host, then test the identity:

```bash
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

Focused and manual validation commands are documented in
[Development and CI](development.md#focused-and-manual-checks).
