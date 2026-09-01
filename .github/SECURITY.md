# Security Policy

Security reports should be submitted privately through GitHub Security
Advisories. Do not include vulnerability details, credentials, or personal data
in a public issue.

## Supported versions

Before the first release, only the latest commit on `main` is reviewed for
security fixes. Historical commits, modified builds, and third-party packages
are not supported.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/slashkiko/macop/security/advisories/new).
Include the affected commit or version, affected command, security impact,
reproduction steps, and the smallest redacted log needed to reproduce the
problem.

If private reporting is unavailable, open a public issue containing only a
request for a private contact channel. Do not disclose vulnerability details in
that issue. Response and remediation times are not guaranteed.

## In scope

Reports are especially useful when they demonstrate a reachable failure in:

- Keychain selection, access control, or secret handling;
- the MacopAuth broker, peer authentication, or protocol validation;
- Secure Enclave or CryptoTokenKit signing authorization;
- verified-session process binding, IPC, sockets, or capability handling;
- installer transaction safety, ownership checks, or rollback; or
- output redaction, temporary-file handling, or the no-persistence boundary.

## Out of scope

The following reports are normally out of scope:

- vulnerabilities that require a modified build of macop;
- behavior in an unsupported historical commit;
- vulnerabilities in Apple, GitHub, 1Password, or another third-party service
  without a demonstrated macop-specific impact;
- social engineering or physical access without a macop control failure; and
- theoretical concerns without a reachable security impact.

The [license](../LICENSE) does not grant permission to modify macop for security
research. Contact the maintainer before conducting research that requires a
modified build. Do not access another person's data, disrupt a service, or use
real credentials in a report.
