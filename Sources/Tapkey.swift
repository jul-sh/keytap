import AuthenticationServices
import CryptoKit
import AppKit
import Foundation

let tapkeyVersion = "0.1.2"

// MARK: - Bech32

enum Bech32 {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

    private static func polymod(_ values: [UInt32]) -> UInt32 {
        let gen: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        var chk: UInt32 = 1
        for v in values {
            let b = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in 0..<5 {
                chk ^= ((b >> i) & 1) != 0 ? gen[i] : 0
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: String) -> [UInt32] {
        let chars = Array(hrp.utf8)
        var result = chars.map { UInt32($0) >> 5 }
        result.append(0)
        result += chars.map { UInt32($0) & 31 }
        return result
    }

    private static func createChecksum(_ hrp: String, _ data: [UInt32]) -> [UInt32] {
        let values = hrpExpand(hrp) + data + [0, 0, 0, 0, 0, 0]
        let mod = polymod(values) ^ 1
        return (0..<6).map { (mod >> (5 * (5 - $0))) & 31 }
    }

    static func encode(hrp: String, data: Data) -> String {
        var acc: UInt32 = 0
        var bits: UInt32 = 0
        var result: [UInt32] = []
        for byte in data {
            acc = (acc << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                result.append((acc >> bits) & 31)
            }
        }
        if bits > 0 {
            result.append((acc << (5 - bits)) & 31)
        }
        let checksum = createChecksum(hrp, result)
        let encoded = (result + checksum).map { charset[Int($0)] }
        return hrp + "1" + String(encoded)
    }
}

// MARK: - OpenSSH Ed25519 Key Formatting

enum SSHKey {
    // Encode a 32-byte Ed25519 seed as an OpenSSH PEM private key.
    // Format: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
    static func privateKeyPEM(seed: Data) -> String {
        let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let pubBytes = privateKey.publicKey.rawRepresentation

        // "openssh-key-v1\0" magic
        let magic = Data("openssh-key-v1\0".utf8)

        // Cipher, KDF, KDF options (all "none" for unencrypted)
        let cipherName = sshString("none")
        let kdfName = sshString("none")
        let kdfOptions = sshString("")
        let numKeys = uint32BE(1)

        // Public key blob: string "ssh-ed25519" + string pubkey
        let pubBlob = sshString("ssh-ed25519") + sshBytes(pubBytes)
        let pubSection = sshBytes(pubBlob)

        // Private section (unencrypted)
        // checkint (random, must match)
        let checkInt = UInt32.random(in: 0...UInt32.max)
        var privPayload = Data()
        privPayload += uint32BE(checkInt)
        privPayload += uint32BE(checkInt)
        privPayload += sshString("ssh-ed25519")
        privPayload += sshBytes(pubBytes)
        // Ed25519 private key in OpenSSH format is 64 bytes: seed || pubkey
        privPayload += sshBytes(seed + pubBytes)
        privPayload += sshString("") // comment

        // Pad to block size (8 bytes for "none" cipher)
        let blockSize = 8
        var padByte: UInt8 = 1
        while privPayload.count % blockSize != 0 {
            privPayload.append(padByte)
            padByte += 1
        }

        let privSection = sshBytes(privPayload)

        let blob = magic + cipherName + kdfName + kdfOptions + numKeys + pubSection + privSection

        let b64 = blob.base64EncodedString(options: [.lineLength76Characters, .endLineWithLineFeed])
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n\(b64)\n-----END OPENSSH PRIVATE KEY-----\n"
    }

    static func publicKeyLine(seed: Data) -> String {
        let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let pubBytes = privateKey.publicKey.rawRepresentation
        let blob = sshString("ssh-ed25519") + sshBytes(pubBytes)
        return "ssh-ed25519 \(blob.base64EncodedString()) tapkey"
    }

    private static func uint32BE(_ v: UInt32) -> Data {
        var be = v.bigEndian
        return Data(bytes: &be, count: 4)
    }

    private static func sshString(_ s: String) -> Data {
        let d = Data(s.utf8)
        return uint32BE(UInt32(d.count)) + d
    }

    private static func sshBytes(_ d: Data) -> Data {
        return uint32BE(UInt32(d.count)) + d
    }
}

// MARK: - Config

struct Config {
    static let relyingParty = "tapkey.jul.sh"
    static let configDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".config/tapkey")
    static let credentialFile = configDir.appendingPathComponent("credential.json")

    // Fixed PRF salt — public, deterministic. Changing this would change all derived keys.
    static let prfSalt: Data = {
        let hash = SHA256.hash(data: Data("tapkey:prf-salt-v1".utf8))
        return Data(hash)
    }()
}

// MARK: - Output Format

enum OutputFormat: String {
    case hex, base64, age, raw, ssh
}

// MARK: - Credential Storage

struct StoredCredential: Codable {
    let credentialID: Data
    let createdAt: String

    init(credentialID: Data) {
        self.credentialID = credentialID
        let fmt = ISO8601DateFormatter()
        self.createdAt = fmt.string(from: Date())
    }
}

func saveCredential(_ credential: StoredCredential) throws {
    try FileManager.default.createDirectory(at: Config.configDir, withIntermediateDirectories: true)
    let encoder = JSONEncoder()
    encoder.outputFormatting = .prettyPrinted
    let data = try encoder.encode(credential)
    try data.write(to: Config.credentialFile)
}

func loadCredential() throws -> StoredCredential {
    let data = try Data(contentsOf: Config.credentialFile)
    return try JSONDecoder().decode(StoredCredential.self, from: data)
}

// MARK: - Key Derivation

/// Derive 32 bytes from PRF output, domain-separated by name.
/// HKDF info = "tapkey:<name>" — different names yield different keys from the same passkey.
func deriveRawKey(from prfOutput: SymmetricKey, name: String) -> Data {
    let info = Data("tapkey:\(name)".utf8)
    let key = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: prfOutput,
        info: info,
        outputByteCount: 32
    )
    return key.withUnsafeBytes { Data($0) }
}

func formatKey(_ rawKey: Data, format: OutputFormat) -> String {
    switch format {
    case .hex:
        return rawKey.map { String(format: "%02x", $0) }.joined()
    case .base64:
        return rawKey.base64EncodedString()
    case .age:
        let bech32 = Bech32.encode(hrp: "age-secret-key-", data: rawKey)
        return bech32.uppercased()
    case .raw:
        // Handled separately — writes raw bytes to stdout
        fatalError("raw format should be handled before calling formatKey")
    case .ssh:
        return SSHKey.privateKeyPEM(seed: rawKey)
    }
}

func formatPublicKey(_ rawKey: Data, format: OutputFormat) -> String {
    switch format {
    case .age:
        let privateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawKey)
        let pubKeyData = privateKey.publicKey.rawRepresentation
        return Bech32.encode(hrp: "age", data: pubKeyData)
    case .ssh:
        return SSHKey.publicKeyLine(seed: rawKey)
    case .hex:
        let privateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawKey)
        return privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    case .base64:
        let privateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawKey)
        return privateKey.publicKey.rawRepresentation.base64EncodedString()
    case .raw:
        fatalError("raw format should be handled before calling formatPublicKey")
    }
}

// MARK: - Argument Parsing

struct Arguments {
    enum Command {
        case register
        case derive
        case publicKey
        case version
    }

    let command: Command
    let name: String
    let format: OutputFormat

    static func parse() -> Arguments {
        let args = Array(CommandLine.arguments.dropFirst())

        if args.contains("--version") || args.contains("-v") {
            return Arguments(command: .version, name: "default", format: .hex)
        }

        if args.contains("--help") || args.contains("-h") || args.isEmpty {
            printUsage()
            exit(0)
        }

        guard let cmd = args.first else {
            printUsage()
            exit(1)
        }

        let command: Command
        switch cmd {
        case "register":
            command = .register
        case "derive":
            command = .derive
        case "public-key":
            command = .publicKey
        default:
            fputs("error: unknown command '\(cmd)'\n", stderr)
            printUsage()
            exit(1)
        }

        var name = "default"
        var format = OutputFormat.hex

        var i = 1
        while i < args.count {
            switch args[i] {
            case "--name":
                guard i + 1 < args.count else {
                    fputs("error: --name requires a value\n", stderr)
                    exit(1)
                }
                i += 1
                name = args[i]
                if name.isEmpty {
                    fputs("error: --name cannot be empty\n", stderr)
                    exit(1)
                }
                if name.utf8.count > 1024 {
                    fputs("error: --name must be at most 1024 bytes\n", stderr)
                    exit(1)
                }
                if !name.allSatisfy({ $0.isASCII }) {
                    fputs("error: --name must contain only ASCII characters\n", stderr)
                    exit(1)
                }
            case "--format":
                guard i + 1 < args.count else {
                    fputs("error: --format requires a value (hex, base64, age, raw, ssh)\n", stderr)
                    exit(1)
                }
                i += 1
                guard let f = OutputFormat(rawValue: args[i]) else {
                    fputs("error: unknown format '\(args[i])'. Use: hex, base64, age, raw, ssh\n", stderr)
                    exit(1)
                }
                format = f
            default:
                fputs("error: unknown option '\(args[i])'\n", stderr)
                exit(1)
            }
            i += 1
        }

        // Default format for public-key depends on context
        if command == .publicKey && format == .hex {
            // If user didn't specify --format, default to age for public-key
            let hasExplicitFormat = args.contains("--format")
            if !hasExplicitFormat {
                format = .age
            }
        }

        return Arguments(command: command, name: name, format: format)
    }

    static func printUsage() {
        fputs("""
        Usage: tapkey <command> [options]

        Commands:
          register       Create a passkey (one-time setup)
          derive         Derive a symmetric key from your passkey
          public-key     Show the public key for a derived key

        Options:
          --name <name>    Key name for domain separation (default: "default")
          --format <fmt>   Output format: hex, base64, age, raw, ssh (default: hex)
          --version        Show version

        Examples:
          tapkey register
          tapkey derive
          tapkey derive --name backup --format base64
          tapkey derive --name age --format age
          tapkey derive --name ssh --format ssh > ~/.ssh/id_tapkey
          tapkey public-key --name ssh --format ssh >> ~/.ssh/authorized_keys


        """, stderr)
    }
}

// MARK: - App Delegate

class AppDelegate: NSObject, NSApplicationDelegate {
    let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 1, height: 1),
        styleMask: [],
        backing: .buffered,
        defer: true
    )

    let arguments: Arguments

    init(arguments: Arguments) {
        self.arguments = arguments
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        switch arguments.command {
        case .version:
            print("tapkey \(tapkeyVersion)")
            exit(0)
        case .register:
            performRegistration()
        case .derive:
            performAssertion(mode: .derive)
        case .publicKey:
            performAssertion(mode: .publicKey)
        }
    }

    enum AssertionMode {
        case derive
        case publicKey
    }

    func performRegistration() {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: Config.relyingParty
        )

        let challenge = Data(SHA256.hash(data: Data("tapkey:registration".utf8)))
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: "tapkey",
            userID: Data("tapkey-user".utf8)
        )

        if #available(macOS 15.0, *) {
            request.prf = .checkForSupport
        } else {
            fputs("error: tapkey requires macOS 15.0 or later (PRF extension)\n", stderr)
            exit(1)
        }

        let controller = ASAuthorizationController(authorizationRequests: [request])
        let delegate = RegistrationDelegate()
        controller.delegate = delegate
        controller.presentationContextProvider = self
        controller.performRequests()

        objc_setAssociatedObject(controller, "delegate", delegate, .OBJC_ASSOCIATION_RETAIN)
    }

    func performAssertion(mode: AssertionMode) {
        let credential: StoredCredential
        do {
            credential = try loadCredential()
        } catch {
            fputs("error: no registered credential found\n", stderr)
            fputs("  Run 'tapkey register' first to create a passkey.\n", stderr)
            exit(1)
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: Config.relyingParty
        )

        let challenge = Data(SHA256.hash(data: Data("tapkey:assertion".utf8)))
        let request = provider.createCredentialAssertionRequest(
            challenge: challenge
        )
        request.allowedCredentials = [
            ASAuthorizationPlatformPublicKeyCredentialDescriptor(
                credentialID: credential.credentialID
            )
        ]

        if #available(macOS 15.0, *) {
            let inputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues
                .saltInput1(Config.prfSalt)
            request.prf = .inputValues(inputValues)
        } else {
            fputs("error: tapkey requires macOS 15.0 or later (PRF extension)\n", stderr)
            exit(1)
        }

        let controller = ASAuthorizationController(authorizationRequests: [request])
        let delegate = AssertionDelegate(mode: mode, name: arguments.name, format: arguments.format)
        controller.delegate = delegate
        controller.presentationContextProvider = self
        controller.performRequests()

        objc_setAssociatedObject(controller, "delegate", delegate, .OBJC_ASSOCIATION_RETAIN)
    }
}

extension AppDelegate: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return window
    }
}

// MARK: - Registration Delegate

class RegistrationDelegate: NSObject, ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            fputs("error: unexpected credential type\n", stderr)
            exit(1)
        }

        if #available(macOS 15.0, *) {
            guard let prfOutput = credential.prf,
                  prfOutput.isSupported else {
                fputs("error: passkey created but PRF not supported by this authenticator\n", stderr)
                fputs("  Platform passkeys on macOS 15+ should support PRF.\n", stderr)
                fputs("  If using a hardware security key, it may not support the PRF extension.\n", stderr)
                exit(1)
            }
        }

        let stored = StoredCredential(credentialID: credential.credentialID)
        do {
            try saveCredential(stored)
        } catch {
            fputs("error: failed to save credential: \(error.localizedDescription)\n", stderr)
            exit(1)
        }

        fputs("Passkey registered successfully.\n", stderr)
        fputs("Credential saved to \(Config.credentialFile.path)\n", stderr)
        exit(0)
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithError error: Error) {
        let nsError = error as NSError
        if nsError.domain == ASAuthorizationError.errorDomain {
            switch ASAuthorizationError.Code(rawValue: nsError.code) {
            case .canceled:
                fputs("Registration cancelled.\n", stderr)
            case .failed:
                fputs("error: registration failed — ensure you're signed into iCloud\n", stderr)
            case .notHandled:
                fputs("error: registration not handled — Associated Domains may not be configured\n", stderr)
                fputs("  The AASA file at tapkey.jul.sh may not be cached yet (takes up to 24h).\n", stderr)
            default:
                fputs("error: registration failed: \(error.localizedDescription)\n", stderr)
            }
        } else {
            fputs("error: registration failed: \(error.localizedDescription)\n", stderr)
        }
        exit(1)
    }
}

// MARK: - Assertion Delegate

class AssertionDelegate: NSObject, ASAuthorizationControllerDelegate {
    let mode: AppDelegate.AssertionMode
    let name: String
    let format: OutputFormat

    init(mode: AppDelegate.AssertionMode, name: String, format: OutputFormat) {
        self.mode = mode
        self.name = name
        self.format = format
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            fputs("error: unexpected credential type\n", stderr)
            exit(1)
        }

        if #available(macOS 15.0, *) {
            guard let prfOutput = credential.prf else {
                fputs("error: PRF output not available\n", stderr)
                fputs("  Your passkey may not support the PRF extension.\n", stderr)
                exit(1)
            }

            let rawKey = deriveRawKey(from: prfOutput.first, name: name)

            switch mode {
            case .derive:
                if format == .raw {
                    FileHandle.standardOutput.write(rawKey)
                } else {
                    let output = formatKey(rawKey, format: format)
                    // SSH format already includes trailing newline
                    if format == .ssh {
                        print(output, terminator: "")
                    } else {
                        print(output)
                    }
                }
            case .publicKey:
                if format == .raw {
                    fputs("error: --format raw not supported for public-key\n", stderr)
                    exit(1)
                }
                print(formatPublicKey(rawKey, format: format))
            }
        } else {
            fputs("error: tapkey requires macOS 15.0 or later\n", stderr)
            exit(1)
        }

        exit(0)
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithError error: Error) {
        let nsError = error as NSError
        if nsError.domain == ASAuthorizationError.errorDomain {
            switch ASAuthorizationError.Code(rawValue: nsError.code) {
            case .canceled:
                fputs("Authentication cancelled.\n", stderr)
            case .failed:
                fputs("error: authentication failed — biometric or passkey authentication may have failed\n", stderr)
            case .notHandled:
                fputs("error: not handled — credential may not be available on this device\n", stderr)
                fputs("  If you registered on another device, ensure your passkey provider has synced.\n", stderr)
            default:
                fputs("error: authentication failed: \(error.localizedDescription)\n", stderr)
            }
        } else {
            fputs("error: authentication failed: \(error.localizedDescription)\n", stderr)
        }
        exit(1)
    }
}

// MARK: - Main

let arguments = Arguments.parse()
let app = NSApplication.shared
let appDelegate = AppDelegate(arguments: arguments)
app.delegate = appDelegate
app.run()
