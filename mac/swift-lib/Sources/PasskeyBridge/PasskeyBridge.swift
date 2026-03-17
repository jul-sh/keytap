import AppKit
import AuthenticationServices
import CryptoKit

// MARK: - FFI callback type

/// Called from Swift into Rust when an auth operation completes.
///   context:   opaque pointer passed through from Rust
///   status:    0 = success, 1 = error
///   data/len:  credential_id (success) or UTF-8 error message (error)
///   extra/len: prf_output bytes (assertion success only), otherwise NULL/0
typealias Callback = @convention(c) (
    UInt64,                     // context
    Int32,                      // status
    UnsafePointer<UInt8>?,      // data
    UInt,                       // data_len
    UnsafePointer<UInt8>?,      // extra
    UInt                        // extra_len
) -> Void

// MARK: - Exported functions

@_cdecl("tapkey_register")
func tapkeyRegister(context: UInt64, callback: Callback) {
    let (app, window) = setupApp()
    let delegate = PasskeyDelegate(window: window, context: context, callback: callback)

    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "tapkey.jul.sh")
    let request = provider.createCredentialRegistrationRequest(
        challenge: randomChallenge(), name: "tapkey", userID: Data("tapkey-user".utf8)
    )
    request.prf = .checkForSupport

    let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = delegate
    controller.presentationContextProvider = delegate
    delegate.retainController(controller)
    controller.performRequests()

    app.run()
}

@_cdecl("tapkey_assert")
func tapkeyAssert(
    saltPtr: UnsafePointer<UInt8>, saltLen: UInt,
    context: UInt64, callback: Callback
) {
    let (app, window) = setupApp()
    let delegate = PasskeyDelegate(window: window, context: context, callback: callback)

    let salt = Data(bytes: saltPtr, count: Int(saltLen))
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "tapkey.jul.sh")
    let request = provider.createCredentialAssertionRequest(challenge: randomChallenge())

    let inputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues.saltInput1(salt)
    request.prf = .inputValues(inputValues)

    let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = delegate
    controller.presentationContextProvider = delegate
    delegate.retainController(controller)

    if #available(macOS 14.0, *) {
        controller.performRequests(options: .preferImmediatelyAvailableCredentials)
    } else {
        controller.performRequests()
    }

    app.run()
}

// MARK: - Delegate

private class PasskeyDelegate: NSObject, ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding
{
    let window: NSWindow
    let context: UInt64
    let cb: Callback
    var controller: ASAuthorizationController?

    init(window: NSWindow, context: UInt64, callback: Callback) {
        self.window = window
        self.context = context
        self.cb = callback
    }

    func retainController(_ c: ASAuthorizationController) { controller = c }

    func presentationAnchor(for _: ASAuthorizationController) -> ASPresentationAnchor { window }

    func authorizationController(controller _: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization)
    {
        if let reg = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            guard let prf = reg.prf, prf.isSupported else {
                fail("passkey created but PRF is not supported by this authenticator")
                return
            }
            succeed(data: reg.credentialID)
        } else if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            guard let prfResult = assertion.prf else {
                fail("PRF output not available. Your passkey may not support the PRF extension.")
                return
            }
            let prfData = prfResult.first.withUnsafeBytes { Data($0) }
            succeed(data: assertion.credentialID, extra: prfData)
        } else {
            fail("unexpected credential type")
        }
    }

    func authorizationController(controller _: ASAuthorizationController, didCompleteWithError error: Error) {
        let nsError = error as NSError
        switch nsError.code {
        case 1001: fail("cancelled")
        case 1004: fail("authentication failed — ensure your passkey provider is available")
        default: fail(nsError.localizedDescription)
        }
    }

    private func succeed(data: Data, extra: Data? = nil) {
        data.withUnsafeBytes { dataPtr in
            if let extra {
                extra.withUnsafeBytes { extraPtr in
                    cb(context, 0,
                       dataPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), UInt(data.count),
                       extraPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), UInt(extra.count))
                }
            } else {
                cb(context, 0,
                   dataPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), UInt(data.count),
                   nil, 0)
            }
        }
    }

    private func fail(_ message: String) {
        let bytes = Array(message.utf8)
        bytes.withUnsafeBufferPointer { buf in
            cb(context, 1, buf.baseAddress, UInt(buf.count), nil, 0)
        }
    }
}

// MARK: - Helpers

private func setupApp() -> (NSApplication, NSWindow) {
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 1, height: 1),
        styleMask: [], backing: .buffered, defer: true
    )
    window.center()
    window.makeKeyAndOrderFront(nil)
    app.activate(ignoringOtherApps: true)
    return (app, window)
}

private func randomChallenge() -> Data {
    Data((0..<32).map { _ in UInt8.random(in: 0...255) })
}
