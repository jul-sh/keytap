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

@_cdecl("keytap_register")
func keytapRegister(context: UInt64, callback: Callback) {
    let (app, window) = setupApp()
    let delegate = PasskeyDelegate(window: window, context: context, callback: callback)

    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "keytap.jul.sh")
    let request = provider.createCredentialRegistrationRequest(
        challenge: randomChallenge(), name: "keytap", userID: Data("keytap-user".utf8)
    )
    request.prf = .checkForSupport

    let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = delegate
    controller.presentationContextProvider = delegate
    delegate.retainController(controller)
    controller.performRequests()
    activateAfterDelay()

    app.run()
}

@_cdecl("keytap_assert")
func keytapAssert(
    saltPtr: UnsafePointer<UInt8>, saltLen: UInt,
    context: UInt64, callback: Callback
) {
    let (app, window) = setupApp()
    let delegate = PasskeyDelegate(window: window, context: context, callback: callback)

    let salt = Data(bytes: saltPtr, count: Int(saltLen))
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "keytap.jul.sh")
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
    activateAfterDelay()

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
        stopRunLoop()
    }

    private func fail(_ message: String) {
        let bytes = Array(message.utf8)
        bytes.withUnsafeBufferPointer { buf in
            cb(context, 1, buf.baseAddress, UInt(buf.count), nil, 0)
        }
        stopRunLoop()
    }

    private func stopRunLoop() {
        let app = NSApplication.shared
        app.stop(nil)
        // NSApplication.stop(_:) sets a flag but doesn't unblock the run loop
        // immediately. Post a dummy event so the loop wakes up and exits.
        let event = NSEvent.otherEvent(
            with: .applicationDefined,
            location: .zero,
            modifierFlags: [],
            timestamp: 0,
            windowNumber: 0,
            context: nil,
            subtype: 0,
            data1: 0,
            data2: 0
        )
        if let event { app.postEvent(event, atStart: true) }
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

    // Pump the run loop briefly so NSApplication and the authorization
    // framework finish lazy initialization before we issue a passkey
    // request.  Without this, the first invocation in a fresh process
    // can fail with error 1004 ("passkey provider not available").
    let deadline = Date(timeIntervalSinceNow: 0.2)
    while Date() < deadline {
        app.nextEvent(matching: .any, until: deadline, inMode: .default, dequeue: true)
    }

    return (app, window)
}

/// Re-activate the app after the authorization UI has been presented,
/// ensuring the TouchID dialog is focused and the sensor engages.
private func activateAfterDelay() {
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
        let app = NSApplication.shared
        if #available(macOS 14.0, *) {
            app.activate()
        } else {
            app.activate(ignoringOtherApps: true)
        }
        // Also bring any authorization windows to the front
        for window in app.windows where window.isVisible {
            window.makeKeyAndOrderFront(nil)
        }
    }
}

private func randomChallenge() -> Data {
    Data((0..<32).map { _ in UInt8.random(in: 0...255) })
}
