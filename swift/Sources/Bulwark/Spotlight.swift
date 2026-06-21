// Spotlighting: random-nonce delimiting, data-marking, and base64 isolation.
// Based on spotlighting (Hines et al., Microsoft, 2024).

import Foundation

public let defaultMarker = "▁"  // ▁ LOWER ONE EIGHTH BLOCK — reads as a space marker
public let defaultTag = "untrusted_content"

private func randomHex(_ nBytes: Int = 9) -> String {
    var rng = SystemRandomNumberGenerator()  // cryptographically secure
    var s = ""
    s.reserveCapacity(nBytes * 2)
    for _ in 0..<nBytes {
        s += String(format: "%02x", UInt8.random(in: 0...255, using: &rng))
    }
    return s
}

public func makeNonce(_ nBytes: Int = 9) -> String { randomHex(nBytes) }

public func delimit(_ text: String, nonce: String? = nil, tag: String = defaultTag) -> (wrapped: String, nonce: String) {
    let n = nonce ?? makeNonce()
    let open = "<\(tag) data-nonce=\"\(n)\">"
    let close = "</\(tag) data-nonce=\"\(n)\">"
    return ("\(open)\n\(text)\n\(close)", n)
}

public func datamark(_ text: String, marker: String = defaultMarker) -> String {
    text.replacingOccurrences(of: " ", with: marker)
}

public func encodeBase64(_ text: String) -> String {
    Data(text.utf8).base64EncodedString()
}

public struct SpotlightOptions {
    public var methods: [String]
    public var nonce: String?
    public var marker: String
    public var tag: String

    public init(methods: [String] = ["delimit"], nonce: String? = nil, marker: String = defaultMarker, tag: String = defaultTag) {
        self.methods = methods
        self.nonce = nonce
        self.marker = marker
        self.tag = tag
    }
}

public func spotlight(_ text: String, options: SpotlightOptions = SpotlightOptions()) -> SpotlightResult {
    var applied: [String] = []
    var content = text
    var usedMarker: String? = nil
    var base64Encoded = false

    if options.methods.contains("base64") {
        content = encodeBase64(content)
        base64Encoded = true
        applied.append("base64")
    } else if options.methods.contains("datamark") {
        content = datamark(content, marker: options.marker)
        usedMarker = options.marker
        applied.append("datamark")
    }

    let d = delimit(content, nonce: options.nonce, tag: options.tag)
    applied.append("delimit")

    return SpotlightResult(content: d.wrapped, nonce: d.nonce, methods: applied, marker: usedMarker, base64Encoded: base64Encoded)
}
