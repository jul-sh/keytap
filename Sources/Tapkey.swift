import AppKit
import AuthenticationServices
import CryptoKit
import Foundation
import WebKit

private let fallbackTapkeyVersion = "0.1.2"

func currentTapkeyVersion() -> String {
    Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        ?? fallbackTapkeyVersion
}

// MARK: - Data Helpers

extension Data {
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }

        guard let decoded = Data(base64Encoded: base64) else {
            return nil
        }
        self = decoded
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

func randomChallenge() -> Data {
    Data((0..<32).map { _ in UInt8.random(in: 0...UInt8.max) })
}

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
    private static let checkIntLabel = Data("tapkey:ssh-checkint".utf8)

    static func privateKeyPEM(seed: Data) -> String {
        let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let publicKey = privateKey.publicKey.rawRepresentation

        let magic = Data("openssh-key-v1\0".utf8)
        let cipherName = sshString("none")
        let kdfName = sshString("none")
        let kdfOptions = sshString("")
        let numberOfKeys = uint32BE(1)

        let publicBlob = sshString("ssh-ed25519") + sshBytes(publicKey)
        let publicSection = sshBytes(publicBlob)

        let checkInt = deterministicCheckInt(seed: seed)
        var privatePayload = Data()
        privatePayload += uint32BE(checkInt)
        privatePayload += uint32BE(checkInt)
        privatePayload += sshString("ssh-ed25519")
        privatePayload += sshBytes(publicKey)
        privatePayload += sshBytes(seed + publicKey)
        privatePayload += sshString("")

        let blockSize = 8
        var padByte: UInt8 = 1
        while privatePayload.count % blockSize != 0 {
            privatePayload.append(padByte)
            padByte += 1
        }

        let privateSection = sshBytes(privatePayload)
        let blob = magic + cipherName + kdfName + kdfOptions + numberOfKeys + publicSection + privateSection
        let encoded = blob.base64EncodedString(options: [.lineLength76Characters, .endLineWithLineFeed])
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n\(encoded)\n-----END OPENSSH PRIVATE KEY-----\n"
    }

    static func publicKeyLine(seed: Data) -> String {
        let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let publicKey = privateKey.publicKey.rawRepresentation
        let blob = sshString("ssh-ed25519") + sshBytes(publicKey)
        return "ssh-ed25519 \(blob.base64EncodedString()) tapkey"
    }

    private static func deterministicCheckInt(seed: Data) -> UInt32 {
        var input = checkIntLabel
        input.append(seed)
        return SHA256.hash(data: input).prefix(4).reduce(0) { ($0 << 8) | UInt32($1) }
    }

    private static func uint32BE(_ value: UInt32) -> Data {
        var bigEndian = value.bigEndian
        return Data(bytes: &bigEndian, count: 4)
    }

    private static func sshString(_ string: String) -> Data {
        let data = Data(string.utf8)
        return uint32BE(UInt32(data.count)) + data
    }

    private static func sshBytes(_ data: Data) -> Data {
        uint32BE(UInt32(data.count)) + data
    }
}

// MARK: - Config

struct Config {
    static let relyingParty = "tapkey.jul.sh"
    static let nearbyPageURL = URL(string: "https://tapkey.jul.sh/nearby.html")!
    static let registrationName = "tapkey"
    static let registrationUserID = Data("tapkey-user".utf8)
    static let hkdfInfo = Data("tapkey:key".utf8)

    static let configDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".config/tapkey")
    static let credentialFile = configDir.appendingPathComponent("credential.json")

    static func prfSalt(for name: String) -> Data {
        let input = Data("tapkey:prf:\(name)".utf8)
        return Data(SHA256.hash(data: input))
    }
}

// MARK: - Output

enum OutputFormat: String {
    case hex
    case base64
    case age
    case raw
    case ssh
}

enum KeyAccessMode {
    case localOrNearby
    case nearbyOnly
}

struct KeyOptions {
    let name: String
    let format: OutputFormat
    let accessMode: KeyAccessMode
}

struct RegisterOptions {
    let replaceExisting: Bool
    let accessMode: KeyAccessMode
}

// MARK: - Credential Storage

struct StoredCredential: Codable, Equatable {
    let credentialID: Data
    let createdAt: String

    init(credentialID: Data) {
        self.credentialID = credentialID
        let formatter = ISO8601DateFormatter()
        self.createdAt = formatter.string(from: Date())
    }
}

func saveCredential(_ credential: StoredCredential) throws {
    try FileManager.default.createDirectory(at: Config.configDir, withIntermediateDirectories: true)
    let encoder = JSONEncoder()
    encoder.outputFormatting = .prettyPrinted
    let data = try encoder.encode(credential)
    try data.write(to: Config.credentialFile, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: Config.credentialFile.path)
}

func loadCredential() throws -> StoredCredential {
    let data = try Data(contentsOf: Config.credentialFile)
    return try JSONDecoder().decode(StoredCredential.self, from: data)
}

func cacheCredentialIDIfNeeded(_ credentialID: Data) throws {
    if let stored = try? loadCredential(), stored.credentialID == credentialID {
        return
    }
    try saveCredential(StoredCredential(credentialID: credentialID))
}

// MARK: - Key Derivation

func deriveRawKey(from prfOutput: SymmetricKey) -> Data {
    let key = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: prfOutput,
        info: Config.hkdfInfo,
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
        return Bech32.encode(hrp: "age-secret-key-", data: rawKey).uppercased()
    case .raw:
        fatalError("raw format should be handled before calling formatKey")
    case .ssh:
        return SSHKey.privateKeyPEM(seed: rawKey)
    }
}

func formatPublicKey(_ rawKey: Data, format: OutputFormat) -> String {
    switch format {
    case .age:
        let privateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawKey)
        return Bech32.encode(hrp: "age", data: privateKey.publicKey.rawRepresentation)
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

// MARK: - Commands

enum Command {
    case register(RegisterOptions)
    case derive(KeyOptions)
    case publicKey(KeyOptions)
    case version
}

struct Arguments {
    let command: Command

    static func parse() -> Arguments {
        let args = Array(CommandLine.arguments.dropFirst())

        if args.contains("--version") || args.contains("-v") {
            return Arguments(command: .version)
        }

        if args.contains("--help") || args.contains("-h") || args.isEmpty {
            printUsage()
            exit(0)
        }

        guard let subcommand = args.first else {
            printUsage()
            exit(1)
        }

        switch subcommand {
        case "register":
            return Arguments(command: parseRegister(arguments: Array(args.dropFirst())))
        case "derive":
            return Arguments(command: .derive(parseKeyOptions(arguments: Array(args.dropFirst()), defaultFormat: .hex)))
        case "public-key":
            return Arguments(command: .publicKey(parseKeyOptions(arguments: Array(args.dropFirst()), defaultFormat: .age)))
        default:
            fputs("error: unknown command '\(subcommand)'\n", stderr)
            printUsage()
            exit(1)
        }
    }

    private static func parseRegister(arguments: [String]) -> Command {
        var replaceExisting = false
        var accessMode = KeyAccessMode.localOrNearby

        for argument in arguments {
            switch argument {
            case "--replace":
                replaceExisting = true
            case "--nearby":
                accessMode = .nearbyOnly
            default:
                fputs("error: unknown option '\(argument)'\n", stderr)
                exit(1)
            }
        }

        return .register(RegisterOptions(replaceExisting: replaceExisting, accessMode: accessMode))
    }

    private static func parseKeyOptions(arguments: [String], defaultFormat: OutputFormat) -> KeyOptions {
        var name = "default"
        var format = defaultFormat
        var accessMode = KeyAccessMode.localOrNearby

        var index = 0
        while index < arguments.count {
            switch arguments[index] {
            case "--name":
                guard index + 1 < arguments.count else {
                    fputs("error: --name requires a value\n", stderr)
                    exit(1)
                }
                index += 1
                name = arguments[index]
                validateKeyName(name)
            case "--format":
                guard index + 1 < arguments.count else {
                    fputs("error: --format requires a value (hex, base64, age, raw, ssh)\n", stderr)
                    exit(1)
                }
                index += 1
                guard let parsedFormat = OutputFormat(rawValue: arguments[index]) else {
                    fputs("error: unknown format '\(arguments[index])'. Use: hex, base64, age, raw, ssh\n", stderr)
                    exit(1)
                }
                format = parsedFormat
            case "--nearby":
                accessMode = .nearbyOnly
            default:
                fputs("error: unknown option '\(arguments[index])'\n", stderr)
                exit(1)
            }
            index += 1
        }

        return KeyOptions(name: name, format: format, accessMode: accessMode)
    }

    private static func validateKeyName(_ name: String) {
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
    }

    static func printUsage() {
        fputs("""
        Usage: tapkey <command> [options]

        Commands:
          register [--replace] [--nearby]  Create the passkey root
          derive [--nearby]                Derive key material from your passkey
          public-key [--nearby]            Show the public key for a derived key

        Options:
          --name <name>                    Key name for domain separation (default: "default")
          --format <fmt>                   Output format: hex, base64, age, raw, ssh
          --nearby                         Use nearby-device passkey flow in a web view
          --replace                        Replace the locally registered passkey root
          --version                        Show version

        Examples:
          tapkey register
          tapkey derive
          tapkey derive --nearby --name ssh --format ssh
          tapkey public-key --nearby --name ssh --format ssh
          tapkey register --replace

        Without --nearby, tapkey first tries a local/synced passkey and then falls
        back to nearby-device passkey flow if no local credential is available.

        """, stderr)
    }
}

// MARK: - Nearby Web Flow

struct NearbyPageConfig: Codable {
    enum Operation: String, Codable {
        case register
        case assert
    }

    let operation: Operation
    let rpId: String
    let challengeBase64URL: String
    let prfSaltBase64URL: String
    let keyName: String?
    let userIDBase64URL: String?
    let userName: String?
}

enum NearbyResult {
    case register(credentialID: Data, prfSupported: Bool)
    case assert(keyOptions: KeyOptions, credentialID: Data, prfOutput: SymmetricKey)
}

enum NearbyMessage: Decodable {
    struct SuccessPayload: Decodable {
        let credentialId: String
        let prfFirst: String?
        let prfSupported: Bool?
    }

    struct ErrorPayload: Decodable {
        let code: String?
        let message: String
    }

    case success(SuccessPayload)
    case error(ErrorPayload)

    private enum CodingKeys: String, CodingKey {
        case type
        case credentialId
        case prfFirst
        case prfSupported
        case code
        case message
    }

    private enum MessageType: String, Decodable {
        case success
        case error
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(MessageType.self, forKey: .type) {
        case .success:
            self = .success(
                SuccessPayload(
                    credentialId: try container.decode(String.self, forKey: .credentialId),
                    prfFirst: try container.decodeIfPresent(String.self, forKey: .prfFirst),
                    prfSupported: try container.decodeIfPresent(Bool.self, forKey: .prfSupported)
                )
            )
        case .error:
            self = .error(
                ErrorPayload(
                    code: try container.decodeIfPresent(String.self, forKey: .code),
                    message: try container.decode(String.self, forKey: .message)
                )
            )
        }
    }
}

final class NearbyWebFlowController: NSObject, NSWindowDelegate, WKNavigationDelegate, WKScriptMessageHandler {
    enum Operation {
        case register
        case assert(KeyOptions)
    }

    enum State {
        case loadingPage
        case awaitingWebAuthnResult
        case finished
    }

    private let operation: Operation
    private let onSuccess: (NearbyResult) -> Void
    private let onFailure: (String) -> Void

    private var state: State = .loadingPage
    private var window: NSWindow?
    private var webView: WKWebView?

    init(operation: Operation,
         onSuccess: @escaping (NearbyResult) -> Void,
         onFailure: @escaping (String) -> Void) {
        self.operation = operation
        self.onSuccess = onSuccess
        self.onFailure = onFailure
    }

    func start() {
        let contentController = WKUserContentController()
        contentController.add(self, name: "tapkey")

        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.userContentController = contentController
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 520),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = title(for: operation)
        window.contentView = webView
        window.center()
        window.delegate = self
        window.makeKeyAndOrderFront(nil)

        NSApp.activate(ignoringOtherApps: true)

        self.window = window
        self.webView = webView

        webView.load(URLRequest(url: Config.nearbyPageURL))
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "tapkey" else {
            return
        }

        guard let json = message.body as? String,
              let data = json.data(using: .utf8) else {
            finishFailure("nearby-device flow returned an unreadable response")
            return
        }

        let decoded: NearbyMessage
        do {
            decoded = try JSONDecoder().decode(NearbyMessage.self, from: data)
        } catch {
            finishFailure("nearby-device flow returned an unexpected response: \(error.localizedDescription)")
            return
        }

        switch decoded {
        case .success(let payload):
            handleSuccess(payload)
        case .error(let payload):
            let detail = payload.code.map { "\($0): \(payload.message)" } ?? payload.message
            finishFailure("nearby-device flow failed: \(detail)")
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        state = .awaitingWebAuthnResult
        let script = injectedScript()
        webView.evaluateJavaScript(script) { _, error in
            if let error {
                self.finishFailure("failed to initialize nearby-device flow: \(error.localizedDescription)")
            }
        }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        finishFailure("failed to load nearby-device flow: \(error.localizedDescription)")
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        finishFailure("failed to load nearby-device flow: \(error.localizedDescription)")
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }

        let isExpectedHost = url.scheme == Config.nearbyPageURL.scheme
            && url.host == Config.nearbyPageURL.host
        let isExpectedPath = url.path == Config.nearbyPageURL.path

        decisionHandler(isExpectedHost && isExpectedPath ? .allow : .cancel)
    }

    func windowWillClose(_ notification: Notification) {
        switch state {
        case .finished:
            break
        case .loadingPage, .awaitingWebAuthnResult:
            finishFailure("nearby-device flow cancelled")
        }
    }

    private func handleSuccess(_ payload: NearbyMessage.SuccessPayload) {
        guard let credentialID = Data(base64URLEncoded: payload.credentialId) else {
            finishFailure("nearby-device flow returned an invalid credential ID")
            return
        }

        switch operation {
        case .register:
            finishSuccess(.register(credentialID: credentialID, prfSupported: payload.prfSupported ?? false))
        case .assert(let keyOptions):
            guard let prfFirst = payload.prfFirst,
                  let prfData = Data(base64URLEncoded: prfFirst) else {
                finishFailure("nearby-device flow did not return PRF output")
                return
            }
            finishSuccess(.assert(keyOptions: keyOptions, credentialID: credentialID, prfOutput: SymmetricKey(data: prfData)))
        }
    }

    private func finishSuccess(_ result: NearbyResult) {
        guard state != .finished else {
            return
        }
        state = .finished
        cleanup()
        onSuccess(result)
    }

    private func finishFailure(_ message: String) {
        guard state != .finished else {
            return
        }
        state = .finished
        cleanup()
        onFailure(message)
    }

    private func cleanup() {
        webView?.configuration.userContentController.removeScriptMessageHandler(forName: "tapkey")
        webView?.navigationDelegate = nil
        window?.delegate = nil
        if let window {
            window.orderOut(nil)
            window.close()
        }
        webView = nil
        window = nil
    }

    private func title(for operation: Operation) -> String {
        switch operation {
        case .register:
            return "Tapkey Register"
        case .assert:
            return "Tapkey Nearby Passkey"
        }
    }

    private func injectedScript() -> String {
        let config = pageConfig(for: operation)
        let jsonData = try! JSONEncoder().encode(config)
        let json = String(data: jsonData, encoding: .utf8)!

        return """
        (() => {
          const config = \(json);
          const bridge = window.webkit?.messageHandlers?.tapkey;
          const post = (payload) => {
            if (bridge) {
              bridge.postMessage(JSON.stringify(payload));
            } else {
              console.log(payload);
            }
          };
          const title = document.getElementById('title');
          const summary = document.getElementById('summary');
          const details = document.getElementById('details');
          const button = document.getElementById('start');
          const status = document.getElementById('status');

          const decodeBase64URL = (value) => {
            const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
            const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
            const binary = atob(padded);
            return Uint8Array.from(binary, (char) => char.charCodeAt(0));
          };

          const encodeBase64URL = (value) => {
            const bytes = value instanceof Uint8Array
              ? value
              : value instanceof ArrayBuffer
                ? new Uint8Array(value)
                : new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength);
            let binary = '';
            for (const byte of bytes) {
              binary += String.fromCharCode(byte);
            }
            return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
          };

          const update = (message) => {
            status.textContent = message;
          };

          const fail = (error) => {
            const message = error?.message || String(error);
            const code = error?.name || null;
            update(message);
            button.disabled = false;
            button.textContent = config.operation === 'register' ? 'Try Register Again' : 'Try Again';
            post({ type: 'error', code, message });
          };

          const runRegister = async () => {
            update('Waiting for passkey creation...');
            const credential = await navigator.credentials.create({
              publicKey: {
                challenge: decodeBase64URL(config.challengeBase64URL),
                rp: {
                  id: config.rpId,
                  name: 'tapkey'
                },
                user: {
                  id: decodeBase64URL(config.userIDBase64URL),
                  name: config.userName,
                  displayName: config.userName
                },
                pubKeyCredParams: [
                  { type: 'public-key', alg: -7 },
                  { type: 'public-key', alg: -257 }
                ],
                authenticatorSelection: {
                  residentKey: 'required',
                  userVerification: 'required'
                },
                attestation: 'none',
                timeout: 120000,
                extensions: {
                  prf: {
                    eval: { first: decodeBase64URL(config.prfSaltBase64URL) }
                  }
                }
              }
            });

            const extensionResults = credential.getClientExtensionResults?.() || {};
            const prfSupported = extensionResults.prf?.enabled === true;

            post({
              type: 'success',
              credentialId: encodeBase64URL(credential.rawId),
              prfSupported
            });
          };

          const runAssert = async () => {
            update('Waiting for passkey approval...');
            const credential = await navigator.credentials.get({
              publicKey: {
                challenge: decodeBase64URL(config.challengeBase64URL),
                rpId: config.rpId,
                userVerification: 'required',
                timeout: 120000,
                extensions: {
                  prf: {
                    eval: { first: decodeBase64URL(config.prfSaltBase64URL) }
                  }
                }
              }
            });

            const extensionResults = credential.getClientExtensionResults?.() || {};
            const prfFirst = extensionResults.prf?.results?.first;
            if (!prfFirst) {
              throw new Error('PRF output was not returned by this passkey flow.');
            }

            post({
              type: 'success',
              credentialId: encodeBase64URL(credential.rawId),
              prfFirst: encodeBase64URL(prfFirst)
            });
          };

          const start = async () => {
            button.disabled = true;
            button.textContent = config.operation === 'register' ? 'Registering...' : 'Waiting...';
            try {
              if (!window.PublicKeyCredential || !navigator.credentials) {
                throw new Error('WebAuthn is not available in this web view.');
              }

              if (config.operation === 'register') {
                await runRegister();
              } else {
                await runAssert();
              }
            } catch (error) {
              fail(error);
            }
          };

          title.textContent = config.operation === 'register' ? 'Create Tapkey Passkey' : 'Use Nearby Passkey';
          summary.textContent = config.operation === 'register'
            ? 'Create the tapkey passkey. If you do not want the passkey on this Mac, choose the nearby-device option and approve it on your iPhone.'
            : 'Approve a tapkey assertion. If the passkey is not on this Mac, choose the nearby-device option and scan the QR code with your iPhone.';
          details.textContent = config.operation === 'register'
            ? 'This creates the passkey root used by tapkey.'
            : `Requested key name: ${config.keyName}`;
          button.disabled = false;
          button.textContent = config.operation === 'register' ? 'Continue To Register' : 'Continue To Authenticate';
          update('Ready.');
          button.addEventListener('click', start);
        })();
        """
    }

    private func pageConfig(for operation: Operation) -> NearbyPageConfig {
        switch operation {
        case .register:
            return NearbyPageConfig(
                operation: .register,
                rpId: Config.relyingParty,
                challengeBase64URL: randomChallenge().base64URLEncodedString(),
                prfSaltBase64URL: Config.prfSalt(for: "default").base64URLEncodedString(),
                keyName: nil,
                userIDBase64URL: Config.registrationUserID.base64URLEncodedString(),
                userName: Config.registrationName
            )
        case .assert(let keyOptions):
            return NearbyPageConfig(
                operation: .assert,
                rpId: Config.relyingParty,
                challengeBase64URL: randomChallenge().base64URLEncodedString(),
                prfSaltBase64URL: Config.prfSalt(for: keyOptions.name).base64URLEncodedString(),
                keyName: keyOptions.name,
                userIDBase64URL: nil,
                userName: nil
            )
        }
    }
}

// MARK: - App Delegate

enum AssertionNotHandledAction {
    case retry(message: String, perform: () -> Void)
    case nearbyFlow(message: String, perform: () -> Void)
    case fail(lines: [String])
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    enum AssertionCommand {
        case derive(KeyOptions)
        case publicKey(KeyOptions)
    }

    enum CredentialSelection {
        case stored(StoredCredential)
        case discoverable
    }

    let anchorWindow = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 1, height: 1),
        styleMask: [],
        backing: .buffered,
        defer: true
    )

    let command: Command
    var activeController: ASAuthorizationController?
    var activeDelegate: NSObject?
    var activeNearbyFlow: NearbyWebFlowController?

    init(command: Command) {
        self.command = command
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        switch command {
        case .version:
            print("tapkey \(currentTapkeyVersion())")
            exit(0)
        case .register(let options):
            performRegistration(options: options)
        case .derive(let options):
            performAssertion(command: .derive(options))
        case .publicKey(let options):
            performAssertion(command: .publicKey(options))
        }
    }

    func performRegistration(options: RegisterOptions) {
        if (try? loadCredential()) != nil && !options.replaceExisting {
            fputs("error: a tapkey passkey is already registered on this Mac\n", stderr)
            fputs("  Run 'tapkey derive' to use it.\n", stderr)
            fputs("  Use 'tapkey register --replace' only if you intend to rotate every derived key.\n", stderr)
            exit(1)
        }

        switch options.accessMode {
        case .nearbyOnly:
            startNearbyRegistration()
        case .localOrNearby:
            startNativeRegistration()
        }
    }

    func performAssertion(command: AssertionCommand) {
        let accessMode = keyOptions(for: command).accessMode

        switch accessMode {
        case .nearbyOnly:
            startNearbyAssertion(command: command)
        case .localOrNearby:
            let selection: CredentialSelection
            if let stored = try? loadCredential() {
                selection = .stored(stored)
            } else {
                selection = .discoverable
            }
            startNativeAssertion(command: command, selection: selection)
        }
    }

    private func startNativeRegistration() {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: Config.relyingParty)
        let request = provider.createCredentialRegistrationRequest(
            challenge: randomChallenge(),
            name: Config.registrationName,
            userID: Config.registrationUserID
        )

        if #available(macOS 15.0, *) {
            request.prf = .checkForSupport
        } else {
            fputs("error: tapkey requires macOS 15.0 or later (PRF extension)\n", stderr)
            exit(1)
        }

        let controller = ASAuthorizationController(authorizationRequests: [request])
        let delegate = RegistrationDelegate()
        beginAuthorization(controller: controller, delegate: delegate)
    }

    private func startNativeAssertion(command: AssertionCommand, selection: CredentialSelection) {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: Config.relyingParty)
        let request = provider.createCredentialAssertionRequest(challenge: randomChallenge())

        switch selection {
        case .stored(let stored):
            request.allowedCredentials = [
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: stored.credentialID)
            ]
        case .discoverable:
            break
        }

        if #available(macOS 15.0, *) {
            let inputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues
                .saltInput1(Config.prfSalt(for: keyOptions(for: command).name))
            request.prf = .inputValues(inputValues)
        } else {
            fputs("error: tapkey requires macOS 15.0 or later (PRF extension)\n", stderr)
            exit(1)
        }

        let action = notHandledAction(for: command, selection: selection)
        let controller = ASAuthorizationController(authorizationRequests: [request])
        let delegate = AssertionDelegate(command: command, notHandledAction: action)
        beginAuthorization(controller: controller, delegate: delegate)
    }

    private func startNearbyRegistration() {
        let flow = NearbyWebFlowController(
            operation: .register,
            onSuccess: { [weak self] result in
                self?.handleNearbyResult(result)
            },
            onFailure: { message in
                fputs("error: \(message)\n", stderr)
                exit(1)
            }
        )
        activeNearbyFlow = flow
        activeController = nil
        activeDelegate = nil
        flow.start()
    }

    private func startNearbyAssertion(command: AssertionCommand) {
        let flow = NearbyWebFlowController(
            operation: .assert(keyOptions(for: command)),
            onSuccess: { [weak self] result in
                self?.handleNearbyResult(result)
            },
            onFailure: { message in
                fputs("error: \(message)\n", stderr)
                exit(1)
            }
        )
        activeNearbyFlow = flow
        activeController = nil
        activeDelegate = nil
        flow.start()
    }

    private func handleNearbyResult(_ result: NearbyResult) {
        activeNearbyFlow = nil

        switch result {
        case .register(let credentialID, let prfSupported):
            guard prfSupported else {
                fputs("error: passkey created but PRF is not supported by this nearby-device flow\n", stderr)
                exit(1)
            }

            do {
                try saveCredential(StoredCredential(credentialID: credentialID))
            } catch {
                fputs("error: failed to save credential: \(error.localizedDescription)\n", stderr)
                exit(1)
            }

            fputs("Passkey registered successfully.\n", stderr)
            fputs("Credential saved to \(Config.credentialFile.path)\n", stderr)
            exit(0)

        case .assert(let keyOptions, let credentialID, let prfOutput):
            do {
                try cacheCredentialIDIfNeeded(credentialID)
            } catch {
                fputs("error: failed to cache credential: \(error.localizedDescription)\n", stderr)
                exit(1)
            }

            let rawKey = deriveRawKey(from: prfOutput)
            emit(rawKey: rawKey, for: keyOptions, command: result)
        }
    }

    private func notHandledAction(for command: AssertionCommand, selection: CredentialSelection) -> AssertionNotHandledAction {
        switch selection {
        case .stored:
            return .retry(
                message: "Stored credential selection was not available on this Mac. Retrying with discoverable passkeys...",
                perform: { [weak self] in
                    self?.startNativeAssertion(command: command, selection: .discoverable)
                }
            )
        case .discoverable:
            return .nearbyFlow(
                message: "No local tapkey passkey was available. Opening nearby-device passkey flow...",
                perform: { [weak self] in
                    self?.startNearbyAssertion(command: command)
                }
            )
        }
    }

    private func keyOptions(for command: AssertionCommand) -> KeyOptions {
        switch command {
        case .derive(let options), .publicKey(let options):
            return options
        }
    }

    private func beginAuthorization(controller: ASAuthorizationController, delegate: NSObject & ASAuthorizationControllerDelegate) {
        controller.delegate = delegate
        controller.presentationContextProvider = self
        activeController = controller
        activeDelegate = delegate
        controller.performRequests()
    }

    private func emit(rawKey: Data, for keyOptions: KeyOptions, command result: NearbyResult) {
        switch result {
        case .register:
            fatalError("register results should not be emitted as key material")
        case .assert:
            break
        }

        switch commandFrom(keyOptions: keyOptions) {
        case .derive:
            if keyOptions.format == .raw {
                FileHandle.standardOutput.write(rawKey)
            } else {
                let output = formatKey(rawKey, format: keyOptions.format)
                if keyOptions.format == .ssh {
                    print(output, terminator: "")
                } else {
                    print(output)
                }
            }
        case .publicKey:
            if keyOptions.format == .raw {
                fputs("error: --format raw is not supported for public-key\n", stderr)
                exit(1)
            }
            print(formatPublicKey(rawKey, format: keyOptions.format))
        }

        exit(0)
    }

    private enum EmissionCommand {
        case derive
        case publicKey
    }

    private func commandFrom(keyOptions: KeyOptions) -> EmissionCommand {
        switch command {
        case .derive:
            return .derive
        case .publicKey:
            return .publicKey
        case .register, .version:
            fatalError("unexpected command for key emission")
        }
    }
}

extension AppDelegate: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        anchorWindow
    }
}

// MARK: - Registration Delegate

final class RegistrationDelegate: NSObject, ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            fputs("error: unexpected credential type\n", stderr)
            exit(1)
        }

        if #available(macOS 15.0, *) {
            guard let prfOutput = credential.prf, prfOutput.isSupported else {
                fputs("error: passkey created but PRF is not supported by this authenticator\n", stderr)
                fputs("  Platform passkeys on macOS 15+ should support PRF.\n", stderr)
                fputs("  Hardware security keys may not support the PRF extension.\n", stderr)
                exit(1)
            }
        }

        do {
            try saveCredential(StoredCredential(credentialID: credential.credentialID))
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
                fputs("error: registration failed — ensure your passkey provider is available\n", stderr)
            case .notHandled:
                fputs("error: registration not handled — Associated Domains may not be configured\n", stderr)
                fputs("  The AASA file at tapkey.jul.sh may not be cached yet.\n", stderr)
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

final class AssertionDelegate: NSObject, ASAuthorizationControllerDelegate {
    let command: AppDelegate.AssertionCommand
    let notHandledAction: AssertionNotHandledAction

    init(command: AppDelegate.AssertionCommand, notHandledAction: AssertionNotHandledAction) {
        self.command = command
        self.notHandledAction = notHandledAction
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            fputs("error: unexpected credential type\n", stderr)
            exit(1)
        }

        if #available(macOS 15.0, *) {
            guard let prfOutput = credential.prf else {
                fputs("error: PRF output not available\n", stderr)
                fputs("  Your passkey may not support the PRF extension.\n", stderr)
                exit(1)
            }

            do {
                try cacheCredentialIDIfNeeded(credential.credentialID)
            } catch {
                fputs("error: failed to cache credential: \(error.localizedDescription)\n", stderr)
                exit(1)
            }

            let rawKey = deriveRawKey(from: prfOutput.first)
            let keyOptions = keyOptions(for: command)

            switch command {
            case .derive:
                if keyOptions.format == .raw {
                    FileHandle.standardOutput.write(rawKey)
                } else {
                    let output = formatKey(rawKey, format: keyOptions.format)
                    if keyOptions.format == .ssh {
                        print(output, terminator: "")
                    } else {
                        print(output)
                    }
                }
            case .publicKey:
                if keyOptions.format == .raw {
                    fputs("error: --format raw is not supported for public-key\n", stderr)
                    exit(1)
                }
                print(formatPublicKey(rawKey, format: keyOptions.format))
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
                exit(1)
            case .failed:
                fputs("error: authentication failed — biometric or passkey authentication may have failed\n", stderr)
                exit(1)
            case .notHandled:
                switch notHandledAction {
                case .retry(let message, let perform), .nearbyFlow(let message, let perform):
                    fputs("\(message)\n", stderr)
                    perform()
                case .fail(let lines):
                    lines.forEach { fputs("\($0)\n", stderr) }
                    exit(1)
                }
            default:
                fputs("error: authentication failed: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        } else {
            fputs("error: authentication failed: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }

    private func keyOptions(for command: AppDelegate.AssertionCommand) -> KeyOptions {
        switch command {
        case .derive(let options), .publicKey(let options):
            return options
        }
    }
}

// MARK: - Main

let arguments = Arguments.parse()
let app = NSApplication.shared
let appDelegate = AppDelegate(command: arguments.command)
app.delegate = appDelegate
app.run()
