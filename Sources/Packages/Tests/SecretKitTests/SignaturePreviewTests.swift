import Foundation
import Testing
import CryptoKit
@testable import SecureEnclaveSecretKit

/// Tests for the signature preview shown in the Touch ID prompt.
///
/// The central guarantee is that the SHA-256 shown is computed over the *exact* bytes that will be
/// signed (the raw `data` payload), so it can be reproduced from the same bytes elsewhere (e.g. a terminal).
@Suite struct SignaturePreviewTests {

    /// Builds a minimal, well-formed SSHSIG payload as a git commit signing request would produce.
    private func makeSSHSIG(namespace: String, hashAlgorithm: String, messageHash: Data) -> Data {
        func string(_ bytes: Data) -> Data {
            let length = UInt32(bytes.count)
            let prefix = Data([
                UInt8((length >> 24) & 0xFF),
                UInt8((length >> 16) & 0xFF),
                UInt8((length >> 8) & 0xFF),
                UInt8(length & 0xFF),
            ])
            return prefix + bytes
        }
        var blob = Data("SSHSIG".utf8)
        blob += string(Data(namespace.utf8))
        blob += string(Data())                       // reserved
        blob += string(Data(hashAlgorithm.utf8))
        blob += string(messageHash)
        return blob
    }

    @Test func sha256MatchesCryptoKitOverRawBytes() {
        // Arbitrary payload standing in for `dataToSign`.
        let data = Data("the exact bytes that will be signed".utf8)
        let preview = SecureEnclave.Store.signaturePreview(for: data)

        // Independently compute the expected hex, exactly as `shasum -a 256` would.
        let expected = SHA256.hash(data: data).map { ("0" + String($0, radix: 16)).suffix(2) }.joined()
        #expect(preview.contains("SHA-256: \(expected)"))
        #expect(expected.count == 64)
    }

    @Test func parsesGitSSHSIGNamespaceAndAlgorithm() {
        let messageHash = Data(repeating: 0xAB, count: 64) // sha512-sized digest
        let blob = makeSSHSIG(namespace: "git", hashAlgorithm: "sha512", messageHash: messageHash)

        let info = SecureEnclave.Store.sshsigInfo(from: blob)
        #expect(info?.namespace == "git")
        #expect(info?.hashAlgorithm == "sha512")

        let preview = SecureEnclave.Store.signaturePreview(for: blob)
        #expect(preview.contains("SSHSIG namespace: \"git\", hash: sha512"))
        // The SHA-256 is over the whole blob, not just the inner message hash.
        let expected = SHA256.hash(data: blob).map { ("0" + String($0, radix: 16)).suffix(2) }.joined()
        #expect(preview.contains("SHA-256: \(expected)"))
    }

    @Test func nonSSHSIGPayloadStillGetsHashWithoutCrashing() {
        // A plain SSH authentication payload does not start with "SSHSIG".
        let data = Data([0x00, 0x01, 0x02, 0x03, 0xFF])
        #expect(SecureEnclave.Store.sshsigInfo(from: data) == nil)

        let preview = SecureEnclave.Store.signaturePreview(for: data)
        #expect(preview.contains("SHA-256: "))
        #expect(!preview.contains("SSHSIG namespace"))
    }

    @Test func malformedSSHSIGDoesNotCrash() {
        // Starts with the magic but is truncated mid-length-prefix.
        let data = Data("SSHSIG".utf8) + Data([0x00, 0x00])
        #expect(SecureEnclave.Store.sshsigInfo(from: data) == nil)
        let preview = SecureEnclave.Store.signaturePreview(for: data)
        #expect(preview.contains("SHA-256: "))
    }
}
