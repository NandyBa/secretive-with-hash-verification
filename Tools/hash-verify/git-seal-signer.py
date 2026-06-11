#!/usr/bin/env python3
"""
Drop-in replacement for `gpg.ssh.program` (ssh-keygen) used by `git seal`.

git invokes the signing program as:
    <program> -Y sign -n git -f <signing_key> <buffer_file>
where <buffer_file> holds the *message* (the commit payload). ssh-keygen then builds
the SSHSIG to-be-signed blob and sends it to the agent. Secretive's Touch ID prompt
shows SHA-256 of THAT blob.

This wrapper reconstructs the exact same blob from the message, prints its SHA-256 to the
controlling terminal (/dev/tty, falling back to stderr) so you can compare it with the
prompt, optionally dumps the raw blob to a file, then execs the real ssh-keygen so signing
proceeds normally.

SSHSIG signed data (https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig):
    "SSHSIG" | string namespace | string reserved | string hash_algorithm | string H(message)
For git: namespace="git", reserved="", hash_algorithm="sha512", H = SHA-512(message).
"""

import hashlib
import os
import struct
import sys

REAL_SSH_KEYGEN = "/usr/bin/ssh-keygen"
DUMP_FILE = os.environ.get("GIT_SEAL_DUMP")  # optional: path to write the raw blob (hex)


def sshstring(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def emit(text: str) -> None:
    """Show `text` live in the terminal.

    git captures the signing program's stdout/stderr and only surfaces them when signing
    fails, so a plain stderr write is swallowed on success. Writing to the controlling
    terminal (/dev/tty) bypasses that capture and shows the line in real time, before the
    Touch ID prompt is approved. Falls back to stderr when no controlling terminal exists
    (e.g. a headless/non-interactive context).
    """
    try:
        with open("/dev/tty", "w") as tty:
            tty.write(text)
            tty.flush()
    except OSError:
        sys.stderr.write(text)
        sys.stderr.flush()


def main():
    args = sys.argv[1:]

    namespace = "git"
    if "-n" in args:
        namespace = args[args.index("-n") + 1]

    key = args[args.index("-f") + 1] if "-f" in args else None

    # The message buffer is the last argv that is an existing file and isn't the key.
    buffer_file = None
    for a in args:
        if a != key and os.path.isfile(a):
            buffer_file = a

    if buffer_file is not None:
        with open(buffer_file, "rb") as f:
            message = f.read()
        digest_of_message = hashlib.sha512(message).digest()  # ssh-keygen uses sha512
        blob = (
            b"SSHSIG"
            + sshstring(namespace.encode())
            + sshstring(b"")                 # reserved
            + sshstring(b"sha512")           # hash_algorithm
            + sshstring(digest_of_message)
        )
        sha256_hex = hashlib.sha256(blob).hexdigest()
        emit(
            f"\n  \033[1m[git seal] SHA-256 to sign: {sha256_hex}\033[0m\n"
            f"  [git seal] namespace=\"{namespace}\" hash=sha512  ({len(blob)} bytes)\n"
            f"  [git seal] -> compare with Secretive's Touch ID prompt, then approve\n\n"
        )
        if DUMP_FILE:
            with open(DUMP_FILE, "w") as f:
                f.write(blob.hex())

    # Hand off to the real ssh-keygen so the actual signature happens (via the agent).
    os.execv(REAL_SSH_KEYGEN, [REAL_SSH_KEYGEN] + args)


if __name__ == "__main__":
    main()
