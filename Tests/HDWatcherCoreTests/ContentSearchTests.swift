import XCTest
@testable import HDWatcherCore

/// Searching names only finds what you already knew to look for. These cover
/// searching what is actually inside the captured bytes.
final class ContentSearchTests: XCTestCase {

    private var directory: URL!
    private var keys: VaultKeys!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-search-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let manager = VaultKeyManager(vaultURL: directory.appendingPathComponent("vault.json"))
        try manager.createVault(password: "content-search-password", enableQuickUnlock: false)
        keys = manager.currentKeys!
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    // MARK: - Extraction

    func testReadsRecordFilesAsParsedRecords() throws {
        let segb = Data(base64Encoded: "U0VHQgIAAAAAAAAAaSDHQQAAAAAAAAAAAAAAAAAAAACdzpo0AAAAAAoaY29tLmFwcGxlLlF1aWNrVGltZVBsYXllclgQ8yAZAAAABWkgx0H4xrgKAAAAAAodY28ucGl4ZWx3b3JzaGlwLnNlY3VyZS1maW5kZXISDwgHEgtBQiQwREM1Q0E4NzAAAAABAAAAAAAAAGkgx0FoAAAAAwAAAAAAgABpIMdB")!
        let (text, source) = ContentSearchEngine.extract(from: segb)
        XCTAssertEqual(source, .records)
        let rendered = try XCTUnwrap(text)
        XCTAssertTrue(rendered.contains("com.apple.QuickTimePlayerX"))
        // A timestamp the reader can see on screen has to be searchable too; it
        // exists nowhere in the raw bytes as text.
        XCTAssertTrue(rendered.contains("2025-08-04"))
    }

    func testReadsPlainTextAsItself() {
        let (text, source) = ContentSearchEngine.extract(from: Data("hello there, friend".utf8))
        XCTAssertEqual(source, .text)
        XCTAssertEqual(text, "hello there, friend")
    }

    func testBinariesAreSearchedAsBytesNotDecodedFirst() {
        // Decoding a large binary into a String to look for one phrase costs
        // more than the search does.
        let data = Data([0x00, 0x01, 0xFF]) + Data("needle-in-here".utf8)
        XCTAssertNil(ContentSearchEngine.extract(from: data).0)

        let found = ContentSearchEngine.locateBytes("needle-in", in: data)
        XCTAssertEqual(found.count, 1)
        XCTAssertTrue(found.snippets[0].contains("needle-in"))
    }

    func testFindsUTF16TextInsideBinaries() {
        // macOS stores plenty of text as UTF-16, which in a byte view is
        // letters separated by NULs — invisible to a plain byte search.
        var data = Data([0xFF, 0xFE])
        for character in "RecipientHandles".utf8 { data.append(character); data.append(0) }
        let found = ContentSearchEngine.locateBytes("recipienthandles", in: data)
        XCTAssertEqual(found.count, 1)
        XCTAssertTrue(found.snippets[0].contains("RecipientHandles"),
                      "the NULs must not survive into the snippet: \(found.snippets)")
    }

    func testByteSearchIgnoresCaseBothWays() {
        let data = Data("Account Number 4029".utf8)
        XCTAssertEqual(ContentSearchEngine.locateBytes("ACCOUNT", in: data).count, 1)
        XCTAssertEqual(ContentSearchEngine.locateBytes("account number", in: data).count, 1)
        XCTAssertEqual(ContentSearchEngine.locateBytes("missing", in: data).count, 0)
    }

    func testByteSearchStaysFastOnLargeContent() {
        // Thirty megabytes with the match at the very end: the scan has to be
        // linear, not a decode-then-search.
        var data = Data(repeating: 0x41, count: 30_000_000)
        data.append(Data("terminal-marker".utf8))
        let started = Date()
        XCTAssertEqual(ContentSearchEngine.locateBytes("terminal-marker", in: data).count, 1)
        XCTAssertLessThan(Date().timeIntervalSince(started), 10)
    }

    // MARK: - Matching

    func testCountsMatchesAndLiftsContext() {
        let text = "the quick brown fox jumps over the lazy dog, and the fox runs on"
        let found = ContentSearchEngine.locate("fox", in: text)
        XCTAssertEqual(found.count, 2)
        XCTAssertEqual(found.snippets.count, 2)
        XCTAssertTrue(found.snippets[0].contains("brown fox jumps"))
    }

    func testMatchingIgnoresCase() {
        XCTAssertEqual(ContentSearchEngine.locate("FOX", in: "a Fox and a fox").count, 2)
    }

    func testSnippetsAreTrimmedAndMarkedWhereTheyWereCut() {
        let text = String(repeating: "x", count: 300) + "target" + String(repeating: "y", count: 300)
        let snippet = ContentSearchEngine.locate("target", in: text).snippets[0]
        XCTAssertTrue(snippet.hasPrefix("…"))
        XCTAssertTrue(snippet.hasSuffix("…"))
        XCTAssertLessThan(snippet.count, 200)
        XCTAssertTrue(snippet.contains("target"))
    }

    // MARK: - Scanning a vault

    private func makeVault(named name: String) throws -> ContentVault {
        var config = ContentVault.Configuration()
        config.debounceSeconds = 0
        config.excludePatterns = []
        return ContentVault(keys: keys, url: directory.appendingPathComponent(name), config: config)
    }

    func testFindsTheFileHoldingThePhrase() throws {
        let vault = try makeVault(named: "one.hdw")
        let hay = directory.appendingPathComponent("hay.txt")
        let needle = directory.appendingPathComponent("needle.txt")
        try "nothing of interest here".write(to: hay, atomically: true, encoding: .utf8)
        try "the account number is 4029-1188".write(to: needle, atomically: true, encoding: .utf8)
        _ = vault.capture(path: hay.path, volumeID: nil, reason: .modified)
        _ = vault.capture(path: needle.path, volumeID: nil, reason: .modified)

        let engine = ContentSearchEngine(vaults: [vault])
        var final: ContentSearchEngine.Progress?
        engine.run(query: "4029-1188", snapshots: vault.allSnapshots(),
                   isCancelled: { false }, progress: { if $0.finished { final = $0 } })

        let result = try XCTUnwrap(final)
        XCTAssertEqual(result.hits.count, 1)
        XCTAssertEqual(result.hits.first?.snapshot.path, needle.path)
        XCTAssertEqual(result.scanned, 2)
        XCTAssertTrue(result.finished)
        vault.close()
    }

    func testReportsProgressAndCanBeStopped() throws {
        let vault = try makeVault(named: "many.hdw")
        for index in 0..<60 {
            let file = directory.appendingPathComponent("file\(index).txt")
            try "contents number \(index) mentioning apples".write(to: file, atomically: true, encoding: .utf8)
            _ = vault.capture(path: file.path, volumeID: nil, reason: .modified)
        }

        let engine = ContentSearchEngine(vaults: [vault])
        var updates = 0
        var stopped = false
        engine.run(query: "apples", snapshots: vault.allSnapshots(), reportEvery: 10,
                   isCancelled: { stopped },
                   progress: { update in
                       updates += 1
                       // Stopping has to take effect part-way through, not at
                       // the end of a full pass over the vault.
                       if update.scanned >= 20 { stopped = true }
                   })
        XCTAssertGreaterThan(updates, 1)
        XCTAssertLessThan(updates * 10, 60)
        vault.close()
    }

    func testIdenticalContentIsOnlyReadOnce() throws {
        let vault = try makeVault(named: "dupes.hdw")
        for index in 0..<5 {
            let file = directory.appendingPathComponent("copy\(index).txt")
            try "exactly the same words in every copy".write(to: file, atomically: true, encoding: .utf8)
            _ = vault.capture(path: file.path, volumeID: nil, reason: .modified)
        }

        let engine = ContentSearchEngine(vaults: [vault])
        var final: ContentSearchEngine.Progress?
        engine.run(query: "same words", snapshots: vault.allSnapshots(),
                   isCancelled: { false }, progress: { if $0.finished { final = $0 } })

        // Deduplicated bytes cannot differ in what they contain, so only the
        // first copy is reported.
        XCTAssertEqual(final?.hits.count, 1)
        vault.close()
    }

    func testShortQueriesAreRefusedRatherThanScanningEverything() throws {
        let vault = try makeVault(named: "short.hdw")
        let file = directory.appendingPathComponent("a.txt")
        try "aaa".write(to: file, atomically: true, encoding: .utf8)
        _ = vault.capture(path: file.path, volumeID: nil, reason: .modified)

        let engine = ContentSearchEngine(vaults: [vault])
        var final: ContentSearchEngine.Progress?
        engine.run(query: "a", snapshots: vault.allSnapshots(),
                   isCancelled: { false }, progress: { final = $0 })
        XCTAssertEqual(final?.scanned, 0)
        XCTAssertTrue(final?.hits.isEmpty ?? false)
        vault.close()
    }
}
