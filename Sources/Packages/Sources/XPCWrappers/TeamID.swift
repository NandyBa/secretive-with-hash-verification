import Foundation
import Security

extension ProcessInfo {
    private static let fallbackTeamID = "Z72PRUAWF6"

    /// The Team ID this process is signed with, read from our own code signature.
    ///
    /// Using `kSecCodeInfoTeamIdentifier` follows whichever team actually signed the build —
    /// free or paid — so the XPC code-signing requirements match the binaries without depending
    /// on the `com.apple.developer.team-identifier` entitlement (which isn't embedded in every
    /// target on personal teams). Falls back to a hardcoded value only if the signature can't be read.
    private static let teamID: String = {
        var code: SecCode?
        guard unsafe SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else {
            return fallbackTeamID
        }
        var staticCode: SecStaticCode?
        guard unsafe SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else {
            return fallbackTeamID
        }
        var information: CFDictionary?
        guard unsafe SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let dictionary = information as? [String: Any],
              let team = dictionary[kSecCodeInfoTeamIdentifier as String] as? String else {
            return fallbackTeamID
        }
        return team
    }()

    public var teamID: String { Self.teamID }
}
