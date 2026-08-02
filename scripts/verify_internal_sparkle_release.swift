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

private let sparkleNamespace = "http://www.andymatuschak.org/xml-namespaces/sparkle"
private let bridgeVersion = "0.1.2"
private let bridgeDownloadURL = "https://github.com/519tech/519-Tech-Intake-Recorder-Releases/releases/download/internal-v0.1.2/519-Tech-Intake-Recorder-0.1.2.dmg"

enum FeedChannelPolicy {
    case defaultChannel
    case internalChannel
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

func requirePlainElement(_ node: XMLNode, name: String, value: String, label: String) throws {
    guard let element = node as? XMLElement else {
        throw VerificationError.failed("\(label) is not an XML element")
    }
    try require(element.name == name, "\(label) has an unexpected element name")
    try require(element.uri == nil || element.uri == "", "\(label) uses an unexpected XML namespace")
    try require((element.attributes ?? []).isEmpty, "\(label) must not have attributes")
    try require(element.children?.allSatisfy { $0.kind == .text } != false, "\(label) must contain text only")
    try require(element.stringValue == value, "\(label) is not canonical")
}

func extractSignedContent(_ appcastData: Data, publicKey: Curve25519.Signing.PublicKey) throws -> Data {
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
    var fieldCount = 0
    for line in signingBlock.split(separator: "\n", omittingEmptySubsequences: true) {
        fieldCount += 1
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
    try require(fieldCount == 2, "Feed-signature block must contain exactly two fields")

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
    return signedContent
}

func verifyReleaseItem(
    _ item: XMLNode,
    label: String,
    dmgURL: URL,
    dmgSize: Int,
    publicKey: Curve25519.Signing.PublicKey,
    expectedVersion: String,
    expectedBuild: String,
    expectedDownloadURL: String,
    expectedMinimumSystemVersion: String,
    channelPolicy: FeedChannelPolicy
) throws {
    try require(item.uri == nil || item.uri == "", "\(label) uses an unexpected XML namespace")

    let versionNode = try oneNode(item, xpath: "./*[local-name()='version']", label: "\(label) Sparkle build version")
    let shortVersionNode = try oneNode(item, xpath: "./*[local-name()='shortVersionString']", label: "\(label) Sparkle short version")
    let minimumSystemVersionNode = try oneNode(
        item,
        xpath: "./*[local-name()='minimumSystemVersion']",
        label: "\(label) minimum system version"
    )
    try require(versionNode.uri == sparkleNamespace, "\(label) build version uses the wrong XML namespace")
    try require(shortVersionNode.uri == sparkleNamespace, "\(label) short version uses the wrong XML namespace")
    try require(minimumSystemVersionNode.uri == sparkleNamespace, "\(label) minimum system version uses the wrong XML namespace")
    let version = try trimmedText(versionNode, label: "\(label) Sparkle build version")
    let shortVersion = try trimmedText(shortVersionNode, label: "\(label) Sparkle short version")
    let minimumSystemVersion = try trimmedText(minimumSystemVersionNode, label: "\(label) minimum system version")
    try require(version == expectedBuild, "\(label) build version does not match the app")
    try require(shortVersion == expectedVersion, "\(label) short version is unexpected")
    try require(minimumSystemVersion == expectedMinimumSystemVersion, "\(label) minimum system version is unexpected")

    let channelNodes = try item.nodes(forXPath: "./*[local-name()='channel']")
    switch channelPolicy {
    case .defaultChannel:
        try require(channelNodes.isEmpty, "\(label) must be on Sparkle's default channel")
    case .internalChannel:
        try require(channelNodes.count == 1, "\(label) must declare exactly one channel")
        let internalChannel = channelNodes[0]
        try require(internalChannel.uri == sparkleNamespace, "\(label) channel uses the wrong XML namespace")
        let internalChannelName = try trimmedText(internalChannel, label: "\(label) channel")
        try require(internalChannelName == "internal", "\(label) must use the internal channel")
    }

    guard let enclosure = try oneNode(item, xpath: "./*[local-name()='enclosure']", label: "\(label) enclosure") as? XMLElement else {
        throw VerificationError.failed("\(label) enclosure is not an XML element")
    }
    try require(enclosure.uri == nil || enclosure.uri == "", "\(label) enclosure uses an unexpected XML namespace")
    try require((enclosure.attributes ?? []).count == 4, "\(label) enclosure must have exactly four attributes")

    let enclosureURL = enclosure.attribute(forName: "url")?.stringValue
    let enclosureLengthValue = enclosure.attribute(forName: "length")?.stringValue
    let enclosureType = enclosure.attribute(forName: "type")?.stringValue
    let enclosureSignatureValue = enclosure.attribute(
        forLocalName: "edSignature",
        uri: sparkleNamespace
    )?.stringValue
    try require(enclosureURL == expectedDownloadURL, "\(label) enclosure URL is unexpected")
    try require(enclosureType == "application/octet-stream", "\(label) enclosure MIME type is unexpected")

    guard let enclosureLengthValue, let enclosureLength = Int(enclosureLengthValue) else {
        throw VerificationError.failed("\(label) enclosure length is missing or invalid")
    }
    try require(String(enclosureLength) == enclosureLengthValue, "\(label) enclosure length is not canonical")
    try require(enclosureLength == dmgSize, "\(label) enclosure length does not match the DMG")
    guard let enclosureSignatureValue else {
        throw VerificationError.failed("\(label) enclosure Ed25519 signature is missing")
    }
    let enclosureSignature = try strictBase64(
        enclosureSignatureValue,
        byteCount: 64,
        label: "\(label) enclosure signature"
    )

    let dmgData = try Data(contentsOf: dmgURL, options: .mappedIfSafe)
    try require(dmgData.count == dmgSize, "\(label) DMG size changed while it was being verified")
    try require(publicKey.isValidSignature(enclosureSignature, for: dmgData), "\(label) DMG enclosure signature is invalid")
}

func verifyAppcastStructure(
    signedContent: Data,
    dmgURL: URL,
    dmgSize: Int,
    bridgeDMGURL: URL,
    bridgeDMGSize: Int,
    publicKey: Curve25519.Signing.PublicKey,
    expectedVersion: String,
    expectedBuild: String,
    expectedBridgeBuild: String,
    expectedDownloadURL: String,
    expectedMinimumSystemVersion: String
) throws {
    let xmlOptions: XMLNode.Options = [
        .nodeLoadExternalEntitiesNever,
        .nodePreserveCDATA,
        .nodePreserveWhitespace,
    ]
    let document = try XMLDocument(data: signedContent, options: xmlOptions)
    try require(document.dtd == nil, "Appcast must not contain a DTD")

    guard let root = document.rootElement() else {
        throw VerificationError.failed("Appcast has no root element")
    }
    try require(root.name == "rss", "Appcast root element must be rss")
    try require(root.uri == nil || root.uri == "", "Appcast root uses an unexpected namespace")
    try require((root.attributes ?? []).count == 1, "Appcast root must have only the version attribute")
    try require(root.attribute(forName: "version")?.stringValue == "2.0", "Appcast RSS version must be 2.0")

    let expectedItemCount = expectedVersion == bridgeVersion ? 1 : 2
    let channels = try root.nodes(forXPath: "./*[local-name()='channel']")
    try require(channels.count == 1, "Expected exactly one appcast channel")
    let channel = channels[0]
    try require(channel.uri == nil || channel.uri == "", "Appcast channel uses an unexpected namespace")
    guard let channelElement = channel as? XMLElement else {
        throw VerificationError.failed("Appcast channel is not an XML element")
    }
    try require((channelElement.attributes ?? []).isEmpty, "Appcast channel must not have attributes")
    let childElementNames = (channelElement.children ?? []).compactMap { ($0 as? XMLElement)?.localName }
    let expectedChildElementNames = ["title"] + Array(repeating: "item", count: expectedItemCount)
    try require(childElementNames == expectedChildElementNames, "Appcast channel elements are not canonical")

    let allItems = try document.nodes(forXPath: "//*[local-name()='item']")
    try require(
        allItems.count == expectedItemCount,
        "Expected exactly \(expectedItemCount) release item(s), found \(allItems.count)"
    )
    let items = try channel.nodes(forXPath: "./*[local-name()='item']")
    try require(items.count == expectedItemCount, "Release items must be direct children of the appcast channel")

    let title = try oneNode(channel, xpath: "./*[local-name()='title']", label: "channel title")
    try requirePlainElement(title, name: "title", value: "519 Tech Intake Recorder", label: "channel title")

    try verifyReleaseItem(
        items[0],
        label: expectedVersion == bridgeVersion ? "bridge item" : "newest internal item",
        dmgURL: dmgURL,
        dmgSize: dmgSize,
        publicKey: publicKey,
        expectedVersion: expectedVersion,
        expectedBuild: expectedBuild,
        expectedDownloadURL: expectedDownloadURL,
        expectedMinimumSystemVersion: expectedMinimumSystemVersion,
        channelPolicy: expectedVersion == bridgeVersion ? .defaultChannel : .internalChannel
    )

    if expectedVersion != bridgeVersion {
        try verifyReleaseItem(
            items[1],
            label: "durable bridge item",
            dmgURL: bridgeDMGURL,
            dmgSize: bridgeDMGSize,
            publicKey: publicKey,
            expectedVersion: bridgeVersion,
            expectedBuild: expectedBridgeBuild,
            expectedDownloadURL: bridgeDownloadURL,
            expectedMinimumSystemVersion: expectedMinimumSystemVersion,
            channelPolicy: .defaultChannel
        )
    }
}

func run() throws {
    guard CommandLine.arguments.count == 10 else {
        throw VerificationError.failed(
            "Usage: verify_internal_sparkle_release.swift <appcast> <dmg> <bridge-dmg> <public-key> <version> <build> <bridge-build> <url> <minimum-system-version>"
        )
    }

    let appcastURL = URL(fileURLWithPath: CommandLine.arguments[1])
    let dmgURL = URL(fileURLWithPath: CommandLine.arguments[2])
    let bridgeDMGURL = URL(fileURLWithPath: CommandLine.arguments[3])
    let publicKeyBase64 = CommandLine.arguments[4]
    let expectedVersion = CommandLine.arguments[5]
    let expectedBuild = CommandLine.arguments[6]
    let expectedBridgeBuild = CommandLine.arguments[7]
    let expectedDownloadURL = CommandLine.arguments[8]
    let expectedMinimumSystemVersion = CommandLine.arguments[9]

    let versionParts = expectedVersion.split(separator: ".", omittingEmptySubsequences: false)
    try require(versionParts.count == 3, "Expected version is not semantic versioning")
    try require(versionParts.allSatisfy { part in
        !part.isEmpty && part.allSatisfy(\.isNumber) && (part == "0" || part.first != "0")
    }, "Expected version is not canonical semantic versioning")
    try require(!expectedBuild.isEmpty && expectedBuild.allSatisfy(\.isNumber), "Expected build is not numeric")
    try require(expectedBuild.first != "0", "Expected build is not a positive canonical integer")
    try require(!expectedBridgeBuild.isEmpty && expectedBridgeBuild.allSatisfy(\.isNumber), "Bridge build is not numeric")
    try require(expectedBridgeBuild.first != "0", "Bridge build is not a positive canonical integer")
    guard let buildNumber = Int(expectedBuild), let bridgeBuildNumber = Int(expectedBridgeBuild) else {
        throw VerificationError.failed("Build numbers are outside the supported integer range")
    }
    if expectedVersion == bridgeVersion {
        try require(buildNumber == bridgeBuildNumber, "Bridge release build numbers do not agree")
    } else {
        try require(buildNumber > bridgeBuildNumber, "Newest internal build must be newer than the durable bridge build")
    }

    let appcastSize = try regularFileSize(appcastURL, maximum: 2_000_000, label: "appcast")
    let dmgSize = try regularFileSize(dmgURL, maximum: 250_000_000, label: "DMG")
    let bridgeDMGSize = try regularFileSize(bridgeDMGURL, maximum: 250_000_000, label: "bridge DMG")
    let publicKeyData = try strictBase64(publicKeyBase64, byteCount: 32, label: "Sparkle public key")
    let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)

    let appcastData = try Data(contentsOf: appcastURL, options: .mappedIfSafe)
    try require(appcastData.count == appcastSize, "Appcast size changed while it was being verified")
    let signedContent = try extractSignedContent(appcastData, publicKey: publicKey)
    try verifyAppcastStructure(
        signedContent: signedContent,
        dmgURL: dmgURL,
        dmgSize: dmgSize,
        bridgeDMGURL: bridgeDMGURL,
        bridgeDMGSize: bridgeDMGSize,
        publicKey: publicKey,
        expectedVersion: expectedVersion,
        expectedBuild: expectedBuild,
        expectedBridgeBuild: expectedBridgeBuild,
        expectedDownloadURL: expectedDownloadURL,
        expectedMinimumSystemVersion: expectedMinimumSystemVersion
    )

    print("Internal Sparkle feed and DMG enclosure signatures are valid.")
}

do {
    try run()
} catch {
    fputs("Internal Sparkle verification failed: \(error)\n", stderr)
    exit(1)
}
