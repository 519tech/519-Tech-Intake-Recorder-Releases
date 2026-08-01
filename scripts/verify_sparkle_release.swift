import CryptoKit
import Foundation

enum VerificationError: Error, CustomStringConvertible {
    case failed(String)

    var description: String {
        switch self {
        case .failed(let message): message
        }
    }
}

func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    guard condition() else { throw VerificationError.failed(message) }
}

func strictBase64(_ value: String, byteCount: Int, label: String) throws -> Data {
    guard
        let data = Data(base64Encoded: value),
        data.count == byteCount,
        data.base64EncodedString() == value
    else {
        throw VerificationError.failed("\(label) is not canonical Base64 for \(byteCount) bytes")
    }
    return data
}

func oneNode(_ parent: XMLNode, xpath: String, label: String) throws -> XMLNode {
    let nodes = try parent.nodes(forXPath: xpath)
    try require(nodes.count == 1, "Expected exactly one \(label), found \(nodes.count)")
    return nodes[0]
}

func trimmedText(_ node: XMLNode, label: String) throws -> String {
    guard let value = node.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
        throw VerificationError.failed("\(label) is empty")
    }
    return value
}

func regularFileSize(_ url: URL, maximum: Int, label: String) throws -> Int {
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
    guard
        values.isRegularFile == true,
        values.isSymbolicLink != true,
        let size = values.fileSize,
        size > 0,
        size <= maximum
    else {
        throw VerificationError.failed("\(label) is not a bounded regular file")
    }
    return size
}

func run() throws {
    guard CommandLine.arguments.count == 8 else {
        throw VerificationError.failed(
            "Usage: verify_sparkle_release.swift <appcast> <dmg> <public-key> <version> <build> <url> <minimum-system-version>"
        )
    }

    let appcastURL = URL(fileURLWithPath: CommandLine.arguments[1])
    let dmgURL = URL(fileURLWithPath: CommandLine.arguments[2])
    let publicKeyBase64 = CommandLine.arguments[3]
    let expectedVersion = CommandLine.arguments[4]
    let expectedBuild = CommandLine.arguments[5]
    let expectedDownloadURL = CommandLine.arguments[6]
    let expectedMinimumSystemVersion = CommandLine.arguments[7]

    let appcastSize = try regularFileSize(appcastURL, maximum: 2_000_000, label: "appcast")
    let dmgSize = try regularFileSize(dmgURL, maximum: 250_000_000, label: "DMG")
    let publicKeyData = try strictBase64(publicKeyBase64, byteCount: 32, label: "Sparkle public key")
    let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)

    let appcastData = try Data(contentsOf: appcastURL, options: .mappedIfSafe)
    try require(appcastData.count == appcastSize, "Appcast size changed while it was being verified")

    let prefix = Data("<!-- sparkle-signatures:\n".utf8)
    let suffix = Data("-->".utf8)
    var markerCount = 0
    var searchStart = appcastData.startIndex
    var markerRange: Range<Data.Index>?
    while searchStart < appcastData.endIndex,
          let range = appcastData.range(of: prefix, in: searchStart..<appcastData.endIndex) {
        markerCount += 1
        markerRange = range
        searchStart = range.upperBound
    }
    try require(markerCount == 1, "Expected exactly one Sparkle feed-signature block")
    guard
        let markerRange,
        let suffixRange = appcastData.range(of: suffix, in: markerRange.upperBound..<appcastData.endIndex)
    else {
        throw VerificationError.failed("Sparkle feed-signature block is incomplete")
    }

    let trailingData = appcastData[suffixRange.upperBound..<appcastData.endIndex]
    try require(trailingData.isEmpty || Data(trailingData) == Data("\n".utf8), "Unsigned bytes follow the feed signature")

    let signedContent = Data(appcastData[appcastData.startIndex..<markerRange.lowerBound])
    let signingBlockData = Data(appcastData[markerRange.upperBound..<suffixRange.lowerBound])
    guard let signingBlock = String(data: signingBlockData, encoding: .utf8) else {
        throw VerificationError.failed("Feed-signature block is not UTF-8")
    }

    var feedSignatureValue: String?
    var signedLengthValue: String?
    for line in signingBlock.split(separator: "\n", omittingEmptySubsequences: true) {
        if line.hasPrefix("edSignature:") {
            try require(feedSignatureValue == nil, "Feed-signature block repeats edSignature")
            feedSignatureValue = line.dropFirst("edSignature:".count).trimmingCharacters(in: .whitespaces)
        } else if line.hasPrefix("length:") {
            try require(signedLengthValue == nil, "Feed-signature block repeats length")
            signedLengthValue = line.dropFirst("length:".count).trimmingCharacters(in: .whitespaces)
        } else {
            throw VerificationError.failed("Feed-signature block contains an unknown field")
        }
    }

    guard
        let feedSignatureValue,
        let signedLengthValue,
        let signedLength = Int(signedLengthValue)
    else {
        throw VerificationError.failed("Feed-signature block is missing required fields")
    }
    try require(String(signedLength) == signedLengthValue, "Feed-signature length is not canonical")
    try require(signedLength == signedContent.count, "Feed-signature length does not match signed content")
    let feedSignature = try strictBase64(feedSignatureValue, byteCount: 64, label: "Feed signature")
    try require(publicKey.isValidSignature(feedSignature, for: signedContent), "Feed signature is invalid")

    let xmlOptions: XMLNode.Options = [
        .nodeLoadExternalEntitiesNever,
        .nodePreserveCDATA,
        .nodePreserveWhitespace,
    ]
    let document = try XMLDocument(data: signedContent, options: xmlOptions)
    let item = try oneNode(
        document,
        xpath: "/*[local-name()='rss']/*[local-name()='channel']/*[local-name()='item']",
        label: "release item"
    )
    let sparkleNamespace = "http://www.andymatuschak.org/xml-namespaces/sparkle"
    let versionNode = try oneNode(item, xpath: "./*[local-name()='version']", label: "Sparkle build version")
    let shortVersionNode = try oneNode(item, xpath: "./*[local-name()='shortVersionString']", label: "Sparkle short version")
    let minimumSystemVersionNode = try oneNode(item, xpath: "./*[local-name()='minimumSystemVersion']", label: "minimum system version")
    try require(versionNode.uri == sparkleNamespace, "Build version uses the wrong XML namespace")
    try require(shortVersionNode.uri == sparkleNamespace, "Short version uses the wrong XML namespace")
    try require(minimumSystemVersionNode.uri == sparkleNamespace, "Minimum system version uses the wrong XML namespace")
    let version = try trimmedText(versionNode, label: "Sparkle build version")
    let shortVersion = try trimmedText(shortVersionNode, label: "Sparkle short version")
    let minimumSystemVersion = try trimmedText(minimumSystemVersionNode, label: "minimum system version")
    try require(version == expectedBuild, "Appcast build version does not match the app")
    try require(shortVersion == expectedVersion, "Appcast short version does not match the release tag")
    try require(minimumSystemVersion == expectedMinimumSystemVersion, "Appcast minimum system version is unexpected")

    guard let enclosure = try oneNode(item, xpath: "./*[local-name()='enclosure']", label: "enclosure") as? XMLElement else {
        throw VerificationError.failed("Enclosure is not an XML element")
    }
    try require(enclosure.uri == nil || enclosure.uri == "", "Enclosure uses an unexpected XML namespace")
    let enclosureURL = enclosure.attribute(forName: "url")?.stringValue
    let enclosureLengthValue = enclosure.attribute(forName: "length")?.stringValue
    let enclosureType = enclosure.attribute(forName: "type")?.stringValue
    let enclosureSignatureValue = enclosure.attribute(
        forLocalName: "edSignature",
        uri: sparkleNamespace
    )?.stringValue

    try require(enclosureURL == expectedDownloadURL, "Enclosure URL does not match the tagged public release")
    try require(enclosureType == "application/octet-stream", "Enclosure MIME type is unexpected")
    guard let enclosureLengthValue, let enclosureLength = Int(enclosureLengthValue) else {
        throw VerificationError.failed("Enclosure length is missing or invalid")
    }
    try require(String(enclosureLength) == enclosureLengthValue, "Enclosure length is not canonical")
    try require(enclosureLength == dmgSize, "Enclosure length does not match the DMG")
    guard let enclosureSignatureValue else {
        throw VerificationError.failed("Enclosure Ed25519 signature is missing")
    }
    let enclosureSignature = try strictBase64(
        enclosureSignatureValue,
        byteCount: 64,
        label: "Enclosure signature"
    )

    let dmgData = try Data(contentsOf: dmgURL, options: .mappedIfSafe)
    try require(dmgData.count == dmgSize, "DMG size changed while it was being verified")
    try require(publicKey.isValidSignature(enclosureSignature, for: dmgData), "DMG enclosure signature is invalid")

    print("Sparkle feed and DMG enclosure signatures are valid.")
}

do {
    try run()
} catch {
    fputs("Sparkle verification failed: \(error)\n", stderr)
    exit(1)
}
