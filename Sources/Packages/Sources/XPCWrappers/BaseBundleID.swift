import Foundation

extension Bundle {

    /// The base bundle identifier shared by the app and its helpers, e.g. `com.maxgoedjen.Secretive`.
    ///
    /// Derived from the running bundle by dropping the last dot-separated component
    /// (`.Host`, `.SecretAgent`, …). XPC service names are built from this so they follow the
    /// configured `SECRETIVE_BASE_BUNDLE_ID` instead of being hardcoded — change the bundle ID in
    /// `OpenSource.xcconfig` and the agent still finds its XPC services.
    public static var secretiveBaseBundleID: String {
        let identifier = Bundle.main.bundleIdentifier ?? "com.maxgoedjen.Secretive.Host"
        let base = identifier.split(separator: ".").dropLast().joined(separator: ".")
        return base.isEmpty ? identifier : base
    }

}
