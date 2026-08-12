import AuthenticationServices
import XCTest

@testable import PasskeyBridge

final class AuthorizationErrorTests: XCTestCase {
  func testFailedAuthorizationNamesDistinctLikelyCauses() {
    let underlyingDescription = "The authorization request could not be completed"
    let error = NSError(
      domain: ASAuthorizationError.errorDomain,
      code: ASAuthorizationError.Code.failed.rawValue,
      userInfo: [NSLocalizedDescriptionKey: underlyingDescription]
    )

    guard case .fallbackToNearby(let message) = authorizationErrorOutcome(for: error) else {
      XCTFail("expected a failed native attempt to permit nearby fallback")
      return
    }

    XCTAssertTrue(message.contains(underlyingDescription))
    XCTAssertTrue(message.contains("registered with LaunchServices"))
    XCTAssertTrue(message.contains("webcredentials association with keytap.jul.sh"))
    XCTAssertTrue(message.contains("passkey provider"))
  }

  func testUnserviceableNativeRequestsPermitNearbyFallback() {
    for code in [
      ASAuthorizationError.Code.notHandled.rawValue,
      ASAuthorizationError.Code.notInteractive.rawValue,
    ] {
      let error = NSError(
        domain: ASAuthorizationError.errorDomain,
        code: code,
        userInfo: [NSLocalizedDescriptionKey: "native request unavailable"]
      )

      guard case .fallbackToNearby = authorizationErrorOutcome(for: error) else {
        XCTFail("expected authorization error \(code) to permit nearby fallback")
        continue
      }
    }
  }

  func testCanceledAuthorizationRemainsCancellation() {
    let error = NSError(
      domain: ASAuthorizationError.errorDomain,
      code: ASAuthorizationError.Code.canceled.rawValue
    )

    guard case .cancelled = authorizationErrorOutcome(for: error) else {
      XCTFail("expected canceled authorization to map to cancellation")
      return
    }
  }

  func testForeignErrorPreservesItsDescription() {
    let description = "bridge failure"
    let error = NSError(
      domain: "sh.jul.keytap.tests",
      code: 1,
      userInfo: [NSLocalizedDescriptionKey: description]
    )

    guard case .indeterminate(let message) = authorizationErrorOutcome(for: error) else {
      XCTFail("expected a foreign error to remain indeterminate")
      return
    }

    XCTAssertEqual(message, description)
  }

  func testDeviceNotConfiguredMakesNativeRegistrationUnavailable() {
    let description = "This device is not set up to create passkeys"
    let error = NSError(
      domain: ASAuthorizationError.errorDomain,
      code: 1010,
      userInfo: [NSLocalizedDescriptionKey: description]
    )

    guard case .fallbackToNearby(let message) = authorizationErrorOutcome(for: error) else {
      XCTFail("expected an unconfigured device to make native registration unavailable")
      return
    }

    XCTAssertEqual(message, description)
  }

  func testInvalidAndUnknownAuthorizationErrorsRemainIndeterminate() {
    for code in [
      ASAuthorizationError.Code.invalidResponse.rawValue,
      ASAuthorizationError.Code.unknown.rawValue,
      9_999,
    ] {
      let error = NSError(
        domain: ASAuthorizationError.errorDomain,
        code: code,
        userInfo: [NSLocalizedDescriptionKey: "indeterminate failure"]
      )

      guard case .indeterminate = authorizationErrorOutcome(for: error) else {
        XCTFail("expected authorization error \(code) to remain indeterminate")
        continue
      }
    }
  }

  func testNearbyFallbackHasADistinctFFIStatus() {
    let fallback = TerminalCompletion.registrationFallbackToNearby(message: "provider unavailable")
    let indeterminate = TerminalCompletion.registrationIndeterminate(
      message: "credential result malformed"
    )
    let assertionFailure = TerminalCompletion.assertionFailure(message: "assertion failed")

    XCTAssertEqual(fallback.callbackStatus, 3)
    XCTAssertEqual(indeterminate.callbackStatus, 1)
    XCTAssertEqual(assertionFailure.callbackStatus, 1)
  }
}
