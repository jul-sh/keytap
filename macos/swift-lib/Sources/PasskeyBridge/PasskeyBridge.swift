import AppKit
import AuthenticationServices

// MARK: - Rust callback ABI

/// Signals that the process's assertion controller is retained and cancellable.
typealias ControllerReadyCallback = @convention(c) (UnsafeMutableRawPointer?) -> Void

/// Delivers the one terminal result for a bridge entry point.
///
/// The Rust context is opaque to Swift. Data pointers are borrowed only for the
/// duration of this call, so Rust must copy them before returning.
typealias CompletionCallback =
  @convention(c) (
    UnsafeMutableRawPointer?,
    Int32,
    UnsafePointer<UInt8>?,
    UInt,
    UnsafePointer<UInt8>?,
    UInt
  ) -> Void

private let statusSuccess: Int32 = 0
private let statusError: Int32 = 1
private let statusCancelled: Int32 = 2
private let credentialDiscoverable: Int32 = 0
private let credentialConstrained: Int32 = 1

private let requiredSaltLength: UInt = 32
private let maximumCredentialIDLength: UInt = 1_024

/// `ASAuthorizationController` holds its delegates weakly. This main-actor slot
/// is therefore the strong owner for the whole ceremony. `NSApplication.run()`
/// and `stop(_:)` are process-global, so two native ceremonies cannot safely be
/// driven concurrently in one process.
@MainActor private var activeOperation: PasskeyOperation?

// MARK: - Exported functions

/// Synchronous FFI contract:
///
/// - This function blocks until it invokes `callback` exactly once.
/// - The callback is invoked before this function returns.
/// - No callback can occur after this function returns.
/// - Rust must keep `context` valid for this call's full duration.
@_cdecl("keytap_register")
func keytapRegister(
  context: sending UnsafeMutableRawPointer?,
  callback: sending CompletionCallback
) {
  guard Thread.isMainThread else {
    deliverDirectError(
      "native passkey operations must run on the process main thread",
      context: context,
      callback: callback
    )
    return
  }

  MainActor.assumeIsolated {
    registerPasskey(context: context, callback: callback)
  }
}

/// Synchronous FFI contract:
///
/// - This function blocks until it invokes `callback` exactly once.
/// - The callback is invoked before this function returns.
/// - No callback can occur after this function returns.
/// - Rust must keep `context`, `saltPtr`, and `credentialIDPtr` valid until the
///   bridge has synchronously copied the input bytes.
@_cdecl("keytap_assert")
func keytapAssert(
  saltPtr: UnsafePointer<UInt8>?,
  saltLen: UInt,
  credentialMode: Int32,
  credentialIDPtr: UnsafePointer<UInt8>?,
  credentialIDLen: UInt,
  context: sending UnsafeMutableRawPointer?,
  controllerReady: sending ControllerReadyCallback,
  callback: sending CompletionCallback
) {
  guard Thread.isMainThread else {
    deliverDirectError(
      "native passkey operations must run on the process main thread",
      context: context,
      callback: callback
    )
    return
  }
  guard saltLen == requiredSaltLength, let saltPtr else {
    deliverDirectError(
      "native assertion PRF salt must contain exactly 32 bytes",
      context: context,
      callback: callback
    )
    return
  }
  // Copy all Rust-owned input before entering the AppKit run loop.
  let salt = Data(bytes: saltPtr, count: Int(saltLen))
  let credential: AssertionCredential
  switch credentialMode {
  case credentialDiscoverable:
    guard credentialIDPtr == nil, credentialIDLen == 0 else {
      deliverDirectError(
        "discoverable native assertion included a credential ID",
        context: context,
        callback: callback
      )
      return
    }
    credential = .discoverable
  case credentialConstrained:
    guard
      (1...maximumCredentialIDLength).contains(credentialIDLen),
      let credentialIDPtr
    else {
      deliverDirectError(
        "constrained native assertion has an invalid credential ID",
        context: context,
        callback: callback
      )
      return
    }
    credential = .constrained(
      credentialID: Data(bytes: credentialIDPtr, count: Int(credentialIDLen))
    )
  default:
    deliverDirectError(
      "native assertion has an unknown credential mode",
      context: context,
      callback: callback
    )
    return
  }

  MainActor.assumeIsolated {
    assertPasskey(
      salt: salt,
      credential: credential,
      context: context,
      controllerReady: controllerReady,
      callback: callback
    )
  }
}

/// Thread-safe assertion cancellation entry point. Delivery is enqueued on the
/// main actor so a cancellation requested by `controllerReady` cannot run until
/// `performRequests()` has installed the authorization request.
@_cdecl("keytap_cancel")
func keytapCancel() {
  Task { @MainActor in
    activeOperation?.requestAssertionCancellation()
  }
}

// MARK: - Ceremony setup

@MainActor
private func registerPasskey(
  context: UnsafeMutableRawPointer?,
  callback: CompletionCallback
) {
  guard ensureOperationSlotAvailable(context: context, callback: callback) else {
    return
  }

  let (application, window) = prepareApplication()
  let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
    relyingPartyIdentifier: "keytap.jul.sh"
  )
  let request = provider.createCredentialRegistrationRequest(
    challenge: randomChallenge(),
    name: "keytap",
    userID: Data("keytap-user".utf8)
  )
  request.prf = .checkForSupport

  let controller = ASAuthorizationController(authorizationRequests: [request])
  runOperation(
    expectedCeremony: .registration,
    context: context,
    callback: callback,
    application: application,
    window: window,
    controller: controller
  )
}

@MainActor
private func assertPasskey(
  salt: Data,
  credential: AssertionCredential,
  context: UnsafeMutableRawPointer?,
  controllerReady: ControllerReadyCallback,
  callback: CompletionCallback
) {
  guard ensureOperationSlotAvailable(context: context, callback: callback) else {
    return
  }

  let (application, window) = prepareApplication()
  let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
    relyingPartyIdentifier: "keytap.jul.sh"
  )
  let request = provider.createCredentialAssertionRequest(challenge: randomChallenge())
  switch credential {
  case .discoverable:
    break
  case .constrained(let credentialID):
    request.allowedCredentials = [
      ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credentialID)
    ]
  }
  let inputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues.saltInput1(
    salt
  )
  request.prf = .inputValues(inputValues)

  let controller = ASAuthorizationController(authorizationRequests: [request])
  runOperation(
    expectedCeremony: .assertion(controllerReady: controllerReady),
    context: context,
    callback: callback,
    application: application,
    window: window,
    controller: controller
  )
}

@MainActor
private func ensureOperationSlotAvailable(
  context: UnsafeMutableRawPointer?,
  callback: CompletionCallback
) -> Bool {
  switch activeOperation {
  case .none:
    return true
  case .some:
    deliverDirectError(
      "another native passkey operation is already running",
      context: context,
      callback: callback
    )
    return false
  }
}

@MainActor
private func runOperation(
  expectedCeremony: ExpectedCeremony,
  context: UnsafeMutableRawPointer?,
  callback: CompletionCallback,
  application: NSApplication,
  window: NSWindow,
  controller: ASAuthorizationController
) {
  let operation = PasskeyOperation(
    expectedCeremony: expectedCeremony,
    controller: controller,
    window: window,
    context: context,
    callback: callback
  )
  controller.delegate = operation
  controller.presentationContextProvider = operation
  activeOperation = operation

  operation.announceControllerReadiness()
  controller.performRequests()
  operation.scheduleDelayedActivation()
  operation.blockUntilTerminalCallback(application: application)
}

// MARK: - Typed operation state

private enum ExpectedCeremony {
  case registration
  case assertion(controllerReady: ControllerReadyCallback)
}

private enum AssertionCredential {
  case discoverable
  case constrained(credentialID: Data)
}

private enum OperationLifecycle {
  case prepared(controller: ASAuthorizationController)
  case awaitingResult(
    controller: ASAuthorizationController,
    delayedActivation: Task<Void, Never>
  )
  case cancellationRequested(controller: ASAuthorizationController)
  case finished
}

private enum TerminalCompletion {
  case registration(credentialID: Data)
  case assertion(credentialID: Data, prfOutput: Data)
  case cancelled
  case failure(message: String)
}

enum AuthorizationErrorOutcome {
  case cancelled
  case failure(message: String)
}

func authorizationErrorOutcome(for error: Error) -> AuthorizationErrorOutcome {
  let nsError = error as NSError
  guard nsError.domain == ASAuthorizationError.errorDomain else {
    return .failure(message: nsError.localizedDescription)
  }
  guard let code = ASAuthorizationError.Code(rawValue: nsError.code) else {
    return .failure(message: nsError.localizedDescription)
  }

  switch code {
  case .canceled:
    return .cancelled
  case .failed:
    return .failure(
      message: "native passkey authorization failed: \(nsError.localizedDescription). "
        + "Possible causes include Keytap.app not being registered with LaunchServices, "
        + "a missing webcredentials association with keytap.jul.sh, or an unavailable "
        + "passkey provider."
    )
  default:
    return .failure(message: nsError.localizedDescription)
  }
}

// MARK: - Authorization delegate

@MainActor
private final class PasskeyOperation: NSObject, ASAuthorizationControllerDelegate,
  ASAuthorizationControllerPresentationContextProviding
{
  private let expectedCeremony: ExpectedCeremony
  private let window: NSWindow
  private let context: UnsafeMutableRawPointer?
  private let callback: CompletionCallback
  private var lifecycle: OperationLifecycle

  init(
    expectedCeremony: ExpectedCeremony,
    controller: ASAuthorizationController,
    window: NSWindow,
    context: UnsafeMutableRawPointer?,
    callback: CompletionCallback
  ) {
    self.expectedCeremony = expectedCeremony
    self.window = window
    self.context = context
    self.callback = callback
    lifecycle = .prepared(controller: controller)
  }

  func presentationAnchor(for _: ASAuthorizationController) -> ASPresentationAnchor {
    window
  }

  func announceControllerReadiness() {
    switch expectedCeremony {
    case .registration:
      break
    case .assertion(let controllerReady):
      controllerReady(context)
    }
  }

  func scheduleDelayedActivation() {
    switch lifecycle {
    case .prepared(let controller):
      let task = Task { @MainActor [weak self] in
        do {
          try await Task.sleep(for: .milliseconds(300))
        } catch {
          return
        }
        self?.performDelayedActivation()
      }
      lifecycle = .awaitingResult(
        controller: controller,
        delayedActivation: task
      )
    case .awaitingResult, .cancellationRequested, .finished:
      break
    }
  }

  func requestAssertionCancellation() {
    switch expectedCeremony {
    case .registration:
      return
    case .assertion:
      break
    }

    switch lifecycle {
    case .prepared(let controller):
      lifecycle = .cancellationRequested(controller: controller)
      controller.cancel()
    case .awaitingResult(let controller, let delayedActivation):
      delayedActivation.cancel()
      lifecycle = .cancellationRequested(controller: controller)
      controller.cancel()
    case .cancellationRequested, .finished:
      break
    }
  }

  func blockUntilTerminalCallback(application: NSApplication) {
    switch lifecycle {
    case .finished:
      return
    case .prepared, .awaitingResult, .cancellationRequested:
      application.run()
    }

    // A normal success, error, or cancellation invokes the terminal
    // callback before waking `application.run()`. Fail closed if an
    // unrelated process-global event ever causes the loop to return.
    switch lifecycle {
    case .finished:
      return
    case .prepared(let controller),
      .awaitingResult(let controller, _),
      .cancellationRequested(let controller):
      finish(
        .failure(
          message: "native passkey application run loop stopped before authorization completed"
        )
      )
      controller.cancel()
    }
  }

  func authorizationController(
    controller _: ASAuthorizationController,
    didCompleteWithAuthorization authorization: ASAuthorization
  ) {
    switch expectedCeremony {
    case .registration:
      guard
        let registration = authorization.credential
          as? ASAuthorizationPlatformPublicKeyCredentialRegistration
      else {
        finish(
          .failure(
            message: "registration completed with an unexpected credential type"
          )
        )
        return
      }
      guard let prf = registration.prf, prf.isSupported else {
        finish(
          .failure(
            message: "passkey created but PRF is not supported by this authenticator"
          )
        )
        return
      }
      finish(.registration(credentialID: registration.credentialID))

    case .assertion:
      guard
        let assertion = authorization.credential
          as? ASAuthorizationPlatformPublicKeyCredentialAssertion
      else {
        finish(
          .failure(
            message: "assertion completed with an unexpected credential type"
          )
        )
        return
      }
      guard let prfResult = assertion.prf else {
        finish(
          .failure(
            message: "PRF output not available. Your passkey may not support the PRF extension."
          )
        )
        return
      }
      let prfOutput = prfResult.first.withUnsafeBytes { Data($0) }
      finish(
        .assertion(
          credentialID: assertion.credentialID,
          prfOutput: prfOutput
        )
      )
    }
  }

  func authorizationController(
    controller _: ASAuthorizationController,
    didCompleteWithError error: Error
  ) {
    switch authorizationErrorOutcome(for: error) {
    case .cancelled:
      finish(.cancelled)
    case .failure(let message):
      finish(.failure(message: message))
    }
  }

  private func performDelayedActivation() {
    switch lifecycle {
    case .prepared, .cancellationRequested, .finished:
      return
    case .awaitingResult:
      activateApplication()
      for visibleWindow in NSApplication.shared.windows where visibleWindow.isVisible {
        visibleWindow.makeKeyAndOrderFront(nil)
      }
    }
  }

  private func finish(_ completion: TerminalCompletion) {
    switch lifecycle {
    case .finished:
      return
    case .prepared:
      lifecycle = .finished
    case .awaitingResult(_, let delayedActivation):
      delayedActivation.cancel()
      lifecycle = .finished
    case .cancellationRequested:
      lifecycle = .finished
    }

    activeOperation = nil
    window.orderOut(nil)
    window.close()
    deliver(completion)
    stopApplicationRunLoop()
  }

  private func deliver(_ completion: TerminalCompletion) {
    switch completion {
    case .registration(let credentialID):
      withBorrowedBytes(credentialID) { credentialPointer, credentialLength in
        callback(
          context,
          statusSuccess,
          credentialPointer,
          credentialLength,
          nil,
          0
        )
      }

    case .assertion(let credentialID, let prfOutput):
      withBorrowedBytes(credentialID) { credentialPointer, credentialLength in
        withBorrowedBytes(prfOutput) { prfPointer, prfLength in
          callback(
            context,
            statusSuccess,
            credentialPointer,
            credentialLength,
            prfPointer,
            prfLength
          )
        }
      }

    case .cancelled:
      callback(context, statusCancelled, nil, 0, nil, 0)

    case .failure(let message):
      withBorrowedBytes(Data(message.utf8)) { messagePointer, messageLength in
        callback(
          context,
          statusError,
          messagePointer,
          messageLength,
          nil,
          0
        )
      }
    }
  }
}

// MARK: - Helpers

private func deliverDirectError(
  _ message: String,
  context: UnsafeMutableRawPointer?,
  callback: CompletionCallback
) {
  withBorrowedBytes(Data(message.utf8)) { pointer, length in
    callback(context, statusError, pointer, length, nil, 0)
  }
}

private func withBorrowedBytes(
  _ data: Data,
  _ body: (UnsafePointer<UInt8>?, UInt) -> Void
) {
  data.withUnsafeBytes { rawBuffer in
    body(
      rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
      UInt(data.count)
    )
  }
}

@MainActor
private func stopApplicationRunLoop() {
  let application = NSApplication.shared
  application.stop(nil)

  // `stop(_:)` only flips a flag. Wake the loop so `run()` can observe it and
  // return to the synchronous FFI entry point.
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
  if let event {
    application.postEvent(event, atStart: true)
  }
}

@MainActor
private func prepareApplication() -> (NSApplication, NSWindow) {
  let application = NSApplication.shared
  application.setActivationPolicy(.regular)
  let window = NSWindow(
    contentRect: NSRect(x: 0, y: 0, width: 1, height: 1),
    styleMask: [],
    backing: .buffered,
    defer: true
  )
  window.center()
  window.makeKeyAndOrderFront(nil)
  activateApplication()

  // Warm AppKit and AuthenticationServices before the first request. Any
  // event dequeued here must still be dispatched; silently discarding it can
  // lose focus or lifecycle events.
  let deadline = Date(timeIntervalSinceNow: 0.2)
  while Date() < deadline {
    if let event = application.nextEvent(
      matching: .any,
      until: deadline,
      inMode: .default,
      dequeue: true
    ) {
      application.sendEvent(event)
    }
  }

  return (application, window)
}

@MainActor
private func activateApplication() {
  NSRunningApplication.current.activate(options: [])
}

private func randomChallenge() -> Data {
  Data((0..<32).map { _ in UInt8.random(in: 0...255) })
}
