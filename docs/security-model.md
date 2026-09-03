# Security model

macop is designed to keep credential selection, approval, and signing on the
Mac that performs the operation. It narrows where secret material and signing
authority can flow; it does not turn an untrusted local process or a compromised
user session into a trusted one.

[Back to the project overview](../README.md)

## Security goals

- Keep Secure Enclave private keys non-exportable and out of files.
- Keep stored secrets in the macOS Keychain rather than configuration files.
- Require explicit native approval for managed Keychain mutations and direct
  Secure Enclave signing.
- Bind broker and SSH-agent capabilities to authenticated peers, exact live
  processes, selected identities, and bounded lifetimes.
- Install the CLI, helper, and companion as one verifiable generation.
- Fail closed when identity, protocol, ownership, permissions, selection, or
  recovery state is ambiguous.
- Avoid persisting resolved secrets through macop-managed files or logs.

## Trusted components

A production installation contains four coordinated components:

- `macop`, the command-line client;
- `macop-agent`, the one-shot SSH agent;
- `MacopAuth.app`, the native approval and protected-operation broker; and
- `macop-install-manifest.json`, the installed-generation record.

The installer stages and preflights them together. The manifest records the
generation, protocol version, executable hashes, and code identities. Before
replacement is committed, the installer verifies the signed bundle and probes
the installed companion without reading protected state or requesting an
approval. An interrupted or invalid update rolls back to the prior generation.

Production broker and verified-session paths require Apple-anchored,
certificate-backed components signed by the same Apple Developer team. Ad-hoc
builds remain useful for build and negative-policy tests, but cannot satisfy
that trust boundary.

See [Installation and removal](installation.md) for the operational signing,
provisioning, update, and recovery requirements.

## Broker and IPC boundary

The CLI treats `MacopAuth.app` as a separate privileged peer, not as an
implicitly trusted local helper. The connection negotiates a closed protocol
contract and verifies the peer's same-Team identity before protected operations
are available.

Broker-facing failures are reported in safe categories such as an unavailable
companion, invalid identity, protocol mismatch, transport failure, or user
denial. Diagnostic output includes a recovery action but does not print socket
paths, request data, or secret values.

Responses are accepted only when their request identity, type, username,
operation-specific result, and mutation outcome form a valid combination. A
lost or malformed response after a request may be reported as indeterminate,
because user selection or a Keychain mutation may already have occurred. macop
does not convert an unknown result into success.

## Keychain and Passwords boundary

Configuration contains selectors and other non-secret metadata. It is not a
secret store. macop requires its configuration directory and file to be owned
by the current user with restrictive permissions, rejects unexpected ACLs and
final-path symlinks, and reads through the already-validated file descriptor.

Legacy generic- and internet-password operations require an exact selector.
Reads, edits, and deletes refuse zero or multiple matches. Create operations
require zero matches before adding and verify the returned persistent reference
afterward. If a concurrent add creates ambiguity, rollback targets only the
item created by the current operation.

Managed items live in MacopAuth's private Data Protection Keychain access group
with user-presence access control. Their reads and mutations require the native
approval UI and macOS authentication. Separately stored OTP seeds follow the
same protected boundary and are never included in configuration.

Passwords AutoFill is a fallback only after an interactive credential is known
to be missing. Cancellation, authentication errors, and other Keychain failures
do not trigger it. The system chooser is user-initiated: macop cannot enumerate
or silently query the Passwords database. A returned username must match the
configured account before the credential can be used or saved.

See [Keychain and configuration](keychain.md) for selector rules, managed and
legacy providers, OTP, profiles, and command-specific behavior.

## Secret delivery boundary

macop deliberately supports only a small set of secret-delivery paths:

- `read`, `item acquire`, `generate password`, and explicit reveal operations
  write the requested value to stdout.
- `run` resolves references only into its direct child process and masks matching
  stdout and stderr unless `--no-masking` is explicitly selected.
- `inject` accepts a template from stdin or a file and writes the expanded
  result only to stdout. Persistent secret output files are rejected.
- Keychain and OTP create/edit/import operations accept secret input through
  stdin rather than secret-bearing command arguments.
- `profile run` accepts only the configured canonical executable and injects
  only the profile's declared environment keys.

Resolved values exist in process memory while an operation is prepared and
relayed. macop does not guarantee zeroization, locked memory, or protection from
process-memory inspection, core dumps, or swap. Binary or NUL-containing
secrets, secret-bearing argv, and persistent output files are outside the
supported contract.

## Secure Enclave and SSH boundary

Secure Enclave identities use non-exportable private keys. macop exposes only
the selected public key and bounded signing capability; it does not create an
OpenSSH private-key file or a stable login-wide agent socket.

A verified SSH session reserves a private socket before launching its root
process. The requested process is started suspended, its live executable and
code identity are pinned, and it is resumed only after registry activation,
native approval, signer installation, and agent authorization complete. The
session is revoked when the registered root exits or its fixed deadline is
reached.

Requests must remain inside the registered process ancestry and use OpenSSH
session binding. Existing applications, unregistered clients, external relays,
manually exported socket paths, agent forwarding, stale sessions, and requests
outside the launched process tree are rejected.

SSH wrapper commands use an isolated configuration, public-key-only
authentication, the selected identity, and `ForwardAgent=no`. They fail rather
than silently using identities from the user's SSH configuration, another
agent, or a fallback authentication method.

Identity migration is staged. Creating a protected direct key does not imply
that its public key has been registered remotely, and activating it does not
delete the legacy identity. Registration, candidate authentication, activation,
normal-path verification, and retirement remain explicit steps.

See [Secure Enclave SSH](secure-enclave-ssh.md) for the identity lifecycle,
migration state machine, host aliases, verified-session commands, and recovery.

## Git signing boundary

The Git adapter accepts only the narrowly supported `ssh-keygen -Y` signing and
verification forms used by Git. It matches the configured public key to one
protected backend, validates owner-controlled input and signature paths, and
produces a standard `SSHSIG` envelope without exposing a private key or stable
agent socket.

Apple Git is validated as an Apple-signed live process. A non-Apple Git client
must be explicitly registered by canonical path, identifier, and code-directory
hash. An upgrade or selector change fails closed until the new executable is
reviewed and trusted. This registry authorizes Git's signing and verification
adapter only; it does not grant a verified-session SSH-agent socket.

## Installation and recovery boundary

The installation directory and installed siblings must remain user-owned and
must not be group- or world-writable. macop resolves its own installed image
rather than searching `PATH` for security-sensitive helper components.

Updates are serialized by an owner-controlled installer lock and use a staged
transaction. A mixed, missing, or manifest-mismatched generation is rejected by
`macop doctor`. Active one-shot agent sessions are not killed during an update;
their presence blocks publication of the new generation until the caller exits.

Uninstall verifies recognized component identities before removal and preserves
configuration, Keychain items, identities, and unrelated commands by default.
Protected-data deletion is a separate, authenticated opt-in operation.

## Explicit non-goals

macop does not claim to:

- provide a 1Password service, cloud vault, or complete `op` implementation;
- enumerate or silently query Apple Passwords;
- protect secrets from a compromised current-user process, process-memory
  inspection, core dumps, or swap;
- eliminate secret exposure when the user explicitly requests stdout, template
  expansion, or child-process environment delivery;
- make ad-hoc signatures equivalent to stable, same-Team production signing;
- authorize arbitrary applications, SSH relays, agent forwarding, or a
  login-wide agent;
- make a Secure Enclave private key transferable or recoverable on another Mac;
  or
- support modified or derivative builds under the repository license.

## Reporting a vulnerability

Do not disclose credentials, personal data, or vulnerability details in a
public issue. Follow the repository's
[private reporting policy](../.github/SECURITY.md).
