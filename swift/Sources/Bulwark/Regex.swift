// Thin wrapper over NSRegularExpression.

import Foundation

final class CompiledRegex: @unchecked Sendable {
    let re: NSRegularExpression

    init(_ pattern: String, options: NSRegularExpression.Options = [.caseInsensitive, .anchorsMatchLines]) {
        // Patterns are vetted constants; a bad one is a programming error.
        re = try! NSRegularExpression(pattern: pattern, options: options)
    }

    private func fullRange(_ text: String) -> NSRange {
        NSRange(location: 0, length: (text as NSString).length)
    }

    func firstMatch(_ text: String) -> NSTextCheckingResult? {
        re.firstMatch(in: text, options: [], range: fullRange(text))
    }

    func test(_ text: String) -> Bool { firstMatch(text) != nil }

    func allMatches(_ text: String) -> [NSTextCheckingResult] {
        re.matches(in: text, options: [], range: fullRange(text))
    }

    func count(_ text: String) -> Int { allMatches(text).count }

    func replaceAll(_ text: String, with template: String) -> String {
        re.stringByReplacingMatches(in: text, options: [], range: fullRange(text), withTemplate: template)
    }
}

extension NSTextCheckingResult {
    func string(in text: String) -> String { (text as NSString).substring(with: range) }

    func group(_ idx: Int, in text: String) -> String? {
        guard idx < numberOfRanges else { return nil }
        let r = range(at: idx)
        if r.location == NSNotFound { return nil }
        return (text as NSString).substring(with: r)
    }
}
