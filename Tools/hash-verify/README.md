# Signature hash verification

This fork makes Secretive's Touch ID prompt display the **SHA-256 of the exact
bytes it is about to sign**. You can reproduce that hash independently and compare
the two, to confirm the signature you authorize matches what you intend to sign.

## What bytes are hashed

The hash is computed over the **raw `data` field of the SSH `SIGN_REQUEST`** — the
second length-prefixed chunk of the agent request. For a `git commit -S` this is the
full **SSHSIG** blob:

```
"SSHSIG"               (6 literal bytes, no length prefix)
string  namespace      ("git")
string  reserved       ("")
string  hash_algorithm ("sha512")
string  H(message)     (SHA-512 of the commit payload)
```

Secretive hashes this **entire blob**, not just the inner `H(message)`. The prompt
also shows the parsed `namespace` and `hash_algorithm` so you can confirm it is a
git signature.

For non-SSHSIG requests (plain SSH authentication), the same SHA-256 of the raw
`data` is shown, without the SSHSIG line.

## Reproducing the hash from the terminal: `agent-sign-hash.py`

git and `ssh-keygen` build the SSHSIG blob internally and send it straight to the
agent over `$SSH_AUTH_SOCK`; they never print that buffer. The only fully reliable
place to observe the exact bytes is on the socket between the SSH client and the
agent. `agent-sign-hash.py` is a transparent proxy that forwards every byte
untouched and prints the SHA-256 of each sign request's `data` field.

```sh
# Terminal A — start the proxy pointed at Secretive's real socket:
./Tools/hash-verify/agent-sign-hash.py "$SSH_AUTH_SOCK"
#   -> prints: export SSH_AUTH_SOCK=/tmp/secretive-hash-proxy.sock

# Terminal B — use the proxy socket, then make a signed commit:
export SSH_AUTH_SOCK=/tmp/secretive-hash-proxy.sock
git commit -S -m "test"
```

Approve the Touch ID prompt. The proxy (Terminal A) prints:

```
[sign] SSHSIG namespace="git" hash=sha512
[sign] SHA-256: <64 hex chars>
```

Compare that `SHA-256` with the `SHA-256:` line in Secretive's prompt. They must be
identical, byte-for-byte.

> Note: the proxy only needs to be the `SSH_AUTH_SOCK` for the signing command.
> It requires no third-party dependencies (Python standard library only) and does
> not modify any byte on the wire.
