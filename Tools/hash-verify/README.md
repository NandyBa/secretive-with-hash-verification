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

## Building this fork with your own Apple identity

The source carries no personal identity — building for yourself is **config only**. Set your
bundle ID prefix and Apple team in the gitignored `Sources/Config/OpenSource.xcconfig`, and the
bundle IDs, XPC service names, and code-signing requirements all follow:

```
# Sources/Config/OpenSource.xcconfig  (gitignored — your machine only)
SECRETIVE_BASE_BUNDLE_ID_OSS = com.yourname.Secretive
SECRETIVE_DEVELOPMENT_TEAM_OSS = YOURTEAMID
```

Find your Team ID (the `OU` of your signing certificate):

```sh
security find-certificate -c "Apple Development: you@example.com" -p \
  | openssl x509 -noout -subject -nameopt sep_multiline | grep OU=
```

Add your Apple ID in Xcode (Settings ▸ Accounts), then build, install and point your shell at
the agent (Debug builds use `socket-debug.ssh`):

```sh
xcodebuild -project Sources/Secretive.xcodeproj -scheme Secretive \
  -configuration Debug -derivedDataPath build -allowProvisioningUpdates build
ditto build/Build/Products/Debug/Secretive.app /Applications/Secretive.app
open /Applications/Secretive.app    # then approve the login item in System Settings

export SSH_AUTH_SOCK="$HOME/Library/Containers/<your-base>.SecretAgent/Data/socket-debug.ssh"
```

What makes this config-only (these are this fork's build changes vs upstream, which would
otherwise need a source `replaceAll`):

- **XPC service names** are derived from the running bundle ID (`Bundle.secretiveBaseBundleID`)
  instead of hardcoded, so they follow `SECRETIVE_BASE_BUNDLE_ID`.
- **The team ID** is read from the running code signature (`kSecCodeInfoTeamIdentifier`) rather
  than a hardcoded constant or the `com.apple.developer.team-identifier` entitlement (absent on
  some targets on personal teams).
- **`com.apple.security.hardened-process.*` entitlements are removed** — personal Apple teams
  reject them; harmless on a paid team (re-add them in the `.entitlements` files if you have a
  paid team and want the extra hardening).

Caveats:

- A Secure Enclave key is bound to the signing team; a key created under a different team (e.g.
  the official app's) is not visible to your build — create a new one in the app.
- A free Apple team's provisioning profiles expire after 7 days, so you'll rebuild periodically.

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

## The two signing keys: `sign-ai` and `sign-me`

This setup uses two separate SSH signing identities, one per level of trust:

| Key | Where it lives | Protection | How it signs | Used for |
|-----|----------------|------------|--------------|----------|
| **`sign-ai`** | a file on disk (`~/.ssh/sign-ai`), no passphrase | filesystem permissions | automatically, no prompt | routine / automated commits — e.g. ones an **AI** coding assistant makes for you |
| **`sign-me`** | the Secure Enclave, via Secretive (non-exportable) | Touch ID on every use | only after you approve | commits *you* personally vouch for, made on purpose via `git me` |

The idea: let low-stakes, high-volume commits flow without friction (`sign-ai`), but require a
deliberate, verified human action for the ones that matter (`sign-me`) — and that's exactly where
this fork shows you the hash of what you're about to sign.

### Create the keys

```sh
# sign-ai: on-disk key, no passphrase so it signs non-interactively
ssh-keygen -t ed25519 -f ~/.ssh/sign-ai -N "" -C "sign-ai"
```

`sign-me` is created inside the Secretive app (Secure Enclave, "require authentication"); export
its public key to a file, e.g. `~/.ssh/secretive_sign-me.pub`.

### Wire them into git

`sign-ai` is the default, so ordinary commits are signed automatically with no prompt:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/sign-ai.pub
git config --global commit.gpgsign true
```

`git me` (below) overrides the key for a single commit, switching to `sign-me` plus the
hash-printing signer. Nothing else in your everyday git usage changes.

Finally, add **both** public keys to GitHub ▸ Settings ▸ *SSH and GPG keys* as **Signing Keys**,
so commits from either show up as *Verified*.

## `git me`: sign with the Secure Enclave key and see the hash live

The workflow: the default on-disk key (`sign-ai`) auto-signs ordinary commits, while your
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
