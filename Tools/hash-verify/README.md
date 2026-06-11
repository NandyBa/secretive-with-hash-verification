# Signature hash verification

## What this fork changes vs upstream Secretive

Upstream Secretive's Touch ID prompt tells you *which* key is signing and *which* app
requested it, but not *what* is being signed. This fork adds one thing: the prompt now also
displays the **SHA-256 of the exact bytes the agent is about to sign**, plus, for an SSHSIG
payload, the parsed `namespace` and `hash_algorithm`.

The prompt gains two lines under the usual text:

```
SHA-256: df407b138e8d984bac92d88efb89e0c66d298a3c2031f833be26e45e999d3f1f
SSHSIG namespace: "git", hash: sha512
```

The single code change lives in
`Sources/Packages/Sources/SecureEnclaveSecretKit/SecureEnclaveStore.swift`:

- `signaturePreview(for:)` computes `SHA256(data)` (CryptoKit) and lowercase-hex-encodes it,
  where `data` is the **same value passed to `key.signature(for:)`** — so the displayed hash
  and the signed bytes cannot diverge.
- `sshsigInfo(from:)` parses the SSHSIG header (no third-party code) to surface the namespace
  and hash algorithm.
- The result is appended to the `LAContext.localizedReason`. Nothing about what is signed
  changes; it is display-only. CryptoKit + standard library only (Secretive's founding rule).

This README and the tools below (`git-me`, `git-me-signer.py`, `agent-sign-hash.py`) let you
reproduce that hash on the terminal side and compare the two, so you can confirm the signature
you authorize matches the commit in front of you.

## What bytes are hashed

The hash is computed over the **raw `data` field of the SSH `SIGN_REQUEST`** — the second
length-prefixed chunk of the agent request. For a `git commit -S` this is the full **SSHSIG**
blob:

```
"SSHSIG"               (6 literal bytes, no length prefix)
string  namespace      ("git")
string  reserved       ("")
string  hash_algorithm ("sha512")
string  H(message)     (SHA-512 of the commit payload)
```

(`string` = 4-byte big-endian length + bytes.) For a git commit this blob is **95 bytes**.
Secretive hashes this **entire blob**, not just the inner `H(message)`. Encoding: **SHA-256**,
**lowercase hex, 64 chars, no separators, no truncation** — identical to `shasum -a 256`,
`openssl dgst -sha256`, or Python `hashlib.sha256().hexdigest()`.

For non-SSHSIG requests (plain SSH authentication), the same SHA-256 of the raw `data` is
shown, without the SSHSIG line.

## `git me`: sign with the Secure Enclave key and see the hash live

The workflow: a default on-disk key (`sign-ai`) auto-signs ordinary commits, while your
personal Secure Enclave key (`sign-me`, Touch ID protected) is used only via `git me`, which
prints the SHA-256 in the terminal so you can compare it with the prompt.

### How git invokes the signer

When `gpg.format=ssh`, git signs by running the program named by `gpg.ssh.program`
(default `ssh-keygen`):

```
<gpg.ssh.program>  -Y sign  -n git  -f <user.signingkey>  <buffer_file>
```

The **message** (the commit payload) is passed in a **temp file** as the last argument — not
on stdin. The signing program then computes `H = SHA-512(message)`, assembles the SSHSIG blob,
and sends it to the agent. So a wrapper around `gpg.ssh.program` sees only the *message*; to
get the hash Secretive shows, it must **reconstruct** the blob (deterministically). That is
exactly what `git-me-signer.py` does, and its output matches the agent's bytes exactly
(verified against `agent-sign-hash.py`).

### Install

`git-me-signer.py` — the wrapper that replaces `ssh-keygen`, reconstructs the blob, and prints
its SHA-256. `git-me` — a thin dispatcher so `git me ...` commits with the `sign-me` key using
that wrapper. Put `git-me` on your `PATH` (git runs `git-me` for the `git me` subcommand):

```sh
chmod +x Tools/hash-verify/git-me-signer.py Tools/hash-verify/git-me
cp Tools/hash-verify/git-me ~/bin/git-me      # ~/bin must be on $PATH
# edit ~/bin/git-me if your repo path or signing-key path differ
```

### Use

```sh
git me -m "my commit"
```

1. `git-me-signer.py` prints, **before** the Touch ID prompt:
   ```
   [git me] SHA-256 to sign: <hex>
   [git me] namespace="git" hash=sha512  (95 bytes)
   ```
2. Secretive shows the **same** `SHA-256` in the Touch ID prompt.
3. Compare the two, then approve with Touch ID.

No proxy is needed for daily use — the wrapper alone produces the terminal-side hash;
`SSH_AUTH_SOCK` just needs to point at Secretive's real agent socket.

### Why `/dev/tty`

git captures the signing program's stdout/stderr and only surfaces them **if signing fails**.
On success a plain stderr write is swallowed. `git-me-signer.py` therefore writes the hash line
to the controlling terminal (`/dev/tty`), which bypasses git's capture and shows it live, and
falls back to stderr when there is no controlling terminal (headless/non-interactive context).

### Dump the exact bytes (optional)

Set `GIT_ME_DUMP` to write the reconstructed blob (hex) to a file for inspection:

```sh
GIT_ME_DUMP=/tmp/blob.hex git me -m "x"
python3 -c "import hashlib; print(hashlib.sha256(bytes.fromhex(open('/tmp/blob.hex').read())).hexdigest())"
```

## Alternative: capture the literal wire bytes with `agent-sign-hash.py`

`git-me-signer.py` *reconstructs* the blob. If you'd rather observe the **literal** bytes the
agent receives (no reconstruction), `agent-sign-hash.py` is a transparent proxy that sits on
the agent socket, forwards every byte untouched, and prints the SHA-256 of each sign request's
`data` field. It's also how this tooling was verified: reconstruction == wire bytes == prompt.

```sh
# Terminal A — start the proxy pointed at Secretive's real socket:
./Tools/hash-verify/agent-sign-hash.py "$SSH_AUTH_SOCK"
#   -> prints: export SSH_AUTH_SOCK=/tmp/secretive-hash-proxy.sock

# Terminal B — use the proxy socket, then make a signed commit:
export SSH_AUTH_SOCK=/tmp/secretive-hash-proxy.sock
git commit -S -m "test"
```

Approve the Touch ID prompt; the proxy (Terminal A) prints:

```
[sign] SSHSIG namespace="git" hash=sha512
[sign] SHA-256: <64 hex chars>
```

Compare that `SHA-256` with the `SHA-256:` line in Secretive's prompt — they must be identical,
byte-for-byte.

> All three tools require no third-party dependencies (Python standard library only) and do not
> modify any byte on the wire.
