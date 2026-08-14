#!/usr/bin/env python3
"""Non-mutating check that macop parses this Mac's sc_auth table faithfully."""
import json
import os
import re
import subprocess
import sys

SC_AUTH = "/usr/sbin/sc_auth"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
PROVIDER = "/usr/lib/ssh-keychain.dylib"


def run(arguments, environment=None):
    return subprocess.run(arguments, text=True, capture_output=True, env=environment)


def layout(header):
    starts = [header.find(name) for name in ("Public Key Hash", "Prot", "Label", "Common Name")]
    if any(value < 0 for value in starts) or starts != sorted(starts) or len(set(starts)) != 4:
        raise ValueError("ambiguous sc_auth table header")
    return starts


def raw_identities(text):
    header = next((line for line in text.splitlines() if "Public Key Hash" in line), None)
    if header is None:
        raise ValueError("missing sc_auth table header")
    public_hash, protocol, label, common_name = layout(header)
    values = set()
    for row in text.splitlines()[text.splitlines().index(header) + 1:]:
        if not row.strip() or set(row.strip()) == {"-"}:
            continue
        found = re.match(r"\s*([0-9A-Fa-f]+)", row[public_hash:])
        if not found:
            raise ValueError("unparseable sc_auth data row")
        public_value = found.group(1)
        if not re.fullmatch(r"[0-9A-Fa-f]{40}", public_value):
            raise ValueError("invalid sc_auth public hash")
        shift = max(0, public_hash + found.end() - protocol)
        start, end = label + shift, common_name + shift
        if len(row) <= start:
            raise ValueError("missing sc_auth label column")
        value = row[start:end].strip()
        if value:
            values.add((value, public_value.upper()))
        else:
            raise ValueError("empty sc_auth label")
    return values


def offline_fixture():
    header = "Key Type  Public Key Hash                            Prot  Label                 Common Name\n"
    row = "p-256-ne  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   bio   My SSH Key            Example User\n"
    expected = {("My SSH Key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}
    if raw_identities(header + row) != expected:
        raise RuntimeError("offline aligned sc_auth fixture parser mismatch")
    try:
        raw_identities(header + "p-256-ne  DDDD\n")
    except ValueError:
        pass
    else:
        raise RuntimeError("offline malformed sc_auth fixture did not fail closed")


def main():
    offline_fixture()
    if not (os.path.exists(SC_AUTH) and os.path.exists(SSH_KEYGEN) and os.path.exists(PROVIDER)):
        print("SKIP: required Apple SSH tooling is unavailable")
        return 0
    raw = run([SC_AUTH, "list-ctk-identities", "-t", "sha1", "-e", "hex"])
    if raw.returncode:
        print("sc_auth identity listing failed", file=sys.stderr)
        return raw.returncode
    try:
        identities = raw_identities(raw.stdout)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    if not identities:
        print("SKIP: no CTK identities")
    else:
        listed = run([".build/debug/macop", "ssh", "list", "--format=json"])
        if listed.returncode:
            print(listed.stderr, file=sys.stderr)
            return listed.returncode
        parsed = {(entry["label"], entry["public_key_hash"]) for entry in json.loads(listed.stdout)["identities"]}
        if parsed != identities:
            print("macop identity JSON differs from raw sc_auth table", file=sys.stderr)
            return 1
        for label, public_hash in identities:
            environment = os.environ | {"KEYCHAIN_CERTIFICATES": public_hash}
            keys = run([SSH_KEYGEN, "-D", PROVIDER], environment)
            key_rows = [line for line in keys.stdout.splitlines() if line.startswith(("ecdsa-", "ssh-"))]
            if keys.returncode or len(key_rows) != 1:
                print(f"provider did not return one selected key for {label}", file=sys.stderr)
                return 1
    config = run([".build/debug/macop", "config", "validate"])
    if config.returncode not in (0, 6):
        print(config.stderr, file=sys.stderr)
        return config.returncode
    doctor = run([".build/debug/macop", "doctor", "--format=json"])
    if doctor.returncode:
        print(doctor.stderr or doctor.stdout, file=sys.stderr)
        return doctor.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
