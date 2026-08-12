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

    guard case .failure(let message) = authorizationErrorOutcome(for: error) else {
      XCTFail("expected failed authorization to map to a failure")
      return
    }

    XCTAssertTrue(message.contains(underlyingDescription))
    XCTAssertTrue(message.contains("registered with LaunchServices"))
    XCTAssertTrue(message.contains("webcredentials association with keytap.jul.sh"))
    XCTAssertTrue(message.contains("passkey provider"))
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

    guard case .failure(let message) = authorizationErrorOutcome(for: error) else {
      XCTFail("expected foreign error to map to a failure")
      return
    }

    XCTAssertEqual(message, description)
  }
}
