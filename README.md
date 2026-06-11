# Secretive [![Test](https://github.com/maxgoedjen/secretive/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/maxgoedjen/secretive/actions/workflows/test.yml) ![Release](https://github.com/maxgoedjen/secretive/workflows/Release/badge.svg)


Secretive is an app for protecting and managing SSH keys with the Secure Enclave.
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/.github/readme/app-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="/.github/readme/app-light.png">
  <img src="/.github/readme/app-dark.png" alt="Screenshot of Secretive" width="600">
</picture>


## This fork — check what you sign (by [Nandy Bâ](https://github.com/NandyBa))

Secretive keeps a secret key locked inside a special chip on your Mac (the Secure Enclave). A small
background program — the **SSH agent** — uses that key to sign things, like proving a Git commit
really came from you. Each time the agent is about to sign, your Mac asks you to confirm with Touch
ID, which is what unlocks the key.

This matters more than ever now that an **AI** assistant can write code and even make commits for
you. So here, *every* commit is automatically signed by an on-disk key — proof it came from your
machine, shown as *Verified* on GitHub. The commits you write *by hand* are instead signed with the
Secure Enclave key, which needs your Touch ID — a deliberate mark that *you personally* made them.
The whole point is to be sure of *what* you're approving when you do.

**The gap in the normal app:** the prompt tells you *which* key will sign and *which* app asked —
but not *what* is being signed. A hacked program, or a confused AI agent, could show you one thing
on screen and quietly ask the agent to sign something else.

**What this fork adds:** the prompt now also shows a short **code** — the SHA-256 of the exact data
about to be signed. Change even one character of that data and the code comes out completely
different. You recompute that same code yourself — from the commit in front of you, with the
included `git seal` command — and compare:

- same code → approve ✅
- different code → stop ❌

Think of it like a checksum (a short summary number): the same data always gives the same code.

Two honest notes. It doesn't *block* a bad signature on its own — it lets you *catch* one, as long
as the code you compare against comes from something you trust (the commit you actually meant to
make). And the signing itself is unchanged: the exact same data is used for the code you see and for
what actually gets signed, so the two can't drift apart.

> Want the technical details, or to build this version yourself? See
> [`Tools/hash-verify/README.md`](Tools/hash-verify/README.md).

## Why?

### Safer Storage

The most common setup for SSH keys is just keeping them on disk, guarded by proper permissions. This is fine in most cases, but it's not super hard for malicious users or malware to copy your private key. If you protect your keys with the Secure Enclave, it's impossible to export them, by design.

### Access Control

If your Mac has a Secure Enclave, it also has support for strong access controls like Touch ID, or authentication with Apple Watch. You can configure your keys so that they require Touch ID (or Watch) authentication before they're accessed.

<img src="/.github/readme/touchid.png" alt="Screenshot of Secretive authenticating with Touch ID" width="400">

### Notifications

Secretive also notifies you whenever your keys are accessed, so you're never caught off guard.

<img src="/.github/readme/notification.png" alt="Screenshot of Secretive notifying the user" width="600">

### Support for Smart Cards Too!

For Macs without Secure Enclaves, you can configure a Smart Card (such as a YubiKey) and use it for signing as well.

## Getting Started

### Installation

#### Direct Download

You can download the latest release over on the [Releases Page](https://github.com/maxgoedjen/secretive/releases)

#### Using Homebrew

    brew install secretive

### FAQ

There's a [FAQ here](FAQ.md).

### Auditable Build Process

Builds are produced by GitHub Actions with an auditable build and release generation process. Starting with Secretive 3.0, builds are attested using [GitHub Artifact Attestation](https://docs.github.com/en/actions/concepts/security/artifact-attestations). Attestations are viewable in the build log for a build, and also on the [main attestation page](https://github.com/maxgoedjen/secretive/attestations).

### A Note Around Code Signing and Keychains

While Secretive uses the Secure Enclave to protect keys, it still relies on Keychain APIs to store and access them. Keychain restricts reads of keys to the app (and specifically, the bundle ID) that created them. If you build Secretive from source, make sure you are consistent in which bundle ID you use so that the Keychain is able to locate your keys.

### Backups and Transfers to New Machines

Because secrets in the Secure Enclave are not exportable, they are not able to be backed up, and you will not be able to transfer them to a new machine. If you get a new Mac, just create a new set of secrets specific to that Mac.

## Security

Secretive's security policy is detailed in [SECURITY.md](SECURITY.md). To report security issues, please use [GitHub's private reporting feature.](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability#privately-reporting-a-security-vulnerability)

## Acknowledgements

### sekey
Secretive was inspired by the [sekey project](https://github.com/sekey/sekey).

### Localization
Secretive is localized to many languages by a generous team of volunteers. To learn more, see [LOCALIZING.md](LOCALIZING.md). Secretive's localization workflow is generously provided by [Crowdin](https://crowdin.com).
