import XCTest
@testable import HDWatcherCore

/// The formats everything else stores data in. Each is unreadable as bytes and
/// obvious once parsed, which is the whole reason these readers exist.
final class PlistReaderTests: XCTestCase {

    private func binaryPlist(_ object: Any) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: object, format: .binary, options: 0)
    }

    func testReadsABinaryPlist() throws {
        let data = try binaryPlist([
            "bundleID": "com.apple.Safari",
            "count": 42,
            "when": Date(timeIntervalSinceReferenceDate: 776_000_000),
            "nested": ["a", "b"],
        ] as [String: Any])

        XCTAssertTrue(PlistReader.detect(data))
        let document = try XCTUnwrap(PlistReader.read(data))
        XCTAssertEqual(document.format, "Binary property list")
        XCTAssertFalse(document.isKeyedArchive)
        XCTAssertTrue(document.text.contains("bundleID: com.apple.Safari"))
        XCTAssertTrue(document.text.contains("count: 42"))
        XCTAssertTrue(document.text.contains("2025-08-04"), document.text)
    }

    func testReadsAnXMLPlist() throws {
        let data = try PropertyListSerialization.data(
            fromPropertyList: ["key": "value"], format: .xml, options: 0)
        XCTAssertTrue(PlistReader.detect(data))
        XCTAssertEqual(PlistReader.read(data)?.format, "XML property list")
    }

    func testFollowsKeyedArchiveReferences() throws {
        // An archive stores a table of objects plus integer references, so the
        // raw decode is a list of fragments and a pile of CF$UIDs. Following
        // the references is what makes it readable.
        let archived = try NSKeyedArchiver.archivedData(
            withRootObject: ["sender": "+12057254200", "body": "meet at six"],
            requiringSecureCoding: false)

        let document = try XCTUnwrap(PlistReader.read(archived))
        XCTAssertTrue(document.isKeyedArchive)
        XCTAssertTrue(document.text.contains("+12057254200"), document.text)
        XCTAssertTrue(document.text.contains("meet at six"), document.text)
    }

    func testOpensPlistsNestedInsidePlists() throws {
        let inner = try binaryPlist(["secret": "inner value"])
        let outer = try binaryPlist(["payload": inner])
        let document = try XCTUnwrap(PlistReader.read(outer))
        XCTAssertTrue(document.text.contains("inner value"),
                      "a data blob that is itself a plist is worth opening: \(document.text)")
    }

    func testRejectsThingsThatAreNotPlists() {
        XCTAssertFalse(PlistReader.detect(Data("just some text".utf8)))
        XCTAssertNil(PlistReader.read(Data(repeating: 0x41, count: 200)))
    }
}

final class SQLiteReaderTests: XCTestCase {

    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-sqlite-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    /// Builds a real database with the sqlite3 command line, so the bytes under
    /// test are the bytes a real database has.
    private func database(_ sql: String) throws -> Data {
        let file = directory.appendingPathComponent("build.db")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        process.arguments = [file.path, sql]
        try process.run()
        process.waitUntilExit()
        return try Data(contentsOf: file)
    }

    func testReadsTablesAndRows() throws {
        let data = try database("""
            CREATE TABLE messages (id INTEGER PRIMARY KEY, handle TEXT, body TEXT);
            INSERT INTO messages VALUES (1, '+12057254200', 'meet at six');
            INSERT INTO messages VALUES (2, 'alfredchiesa@icloud.com', 'on my way');
            CREATE TABLE empty_table (a TEXT);
            """)

        XCTAssertTrue(SQLiteReader.detect(data))
        let document = try XCTUnwrap(SQLiteReader.read(data))
        XCTAssertEqual(document.tables.map(\.name), ["empty_table", "messages"])
        XCTAssertEqual(document.totalRows, 2)

        let messages = try XCTUnwrap(document.tables.first { $0.name == "messages" })
        XCTAssertEqual(messages.columns, ["id", "handle", "body"])
        XCTAssertEqual(messages.rows.count, 2)
        XCTAssertFalse(messages.clipped)

        let rendered = SQLiteReader.render(document)
        XCTAssertTrue(rendered.contains("handle: +12057254200"))
        XCTAssertTrue(rendered.contains("body: on my way"))
    }

    func testUnpacksPlistBlobsStoredInColumns() throws {
        // Attributed message bodies, settings payloads: a blob column holding a
        // whole plist is routine, and reading it is usually the point.
        let plist = try PropertyListSerialization.data(
            fromPropertyList: ["marker": "inside the blob"], format: .binary, options: 0)
        let hex = plist.map { String(format: "%02X", $0) }.joined()
        let data = try database("""
            CREATE TABLE payloads (id INTEGER, blob BLOB);
            INSERT INTO payloads VALUES (1, X'\(hex)');
            """)

        let document = try XCTUnwrap(SQLiteReader.read(data))
        XCTAssertTrue(SQLiteReader.render(document).contains("inside the blob"))
    }

    func testBoundsWhatItReadsFromAHugeTable() throws {
        var sql = "CREATE TABLE big (n INTEGER);"
        for index in 0..<900 { sql += "INSERT INTO big VALUES (\(index));" }
        let document = try XCTUnwrap(SQLiteReader.read(try database(sql), rowsPerTable: 100))
        let table = try XCTUnwrap(document.tables.first)
        XCTAssertEqual(table.rowCount, 900, "the count is of the whole table")
        XCTAssertEqual(table.rows.count, 100, "but only a window is read")
        XCTAssertTrue(table.clipped)
        XCTAssertTrue(SQLiteReader.render(document).contains("800 further rows"))
    }

    func testRefusesThingsThatAreNotDatabases() {
        XCTAssertFalse(SQLiteReader.detect(Data("SQLite format 2".utf8)))
        XCTAssertNil(SQLiteReader.read(Data(repeating: 0, count: 4_096)))
    }

    func testSurvivesATruncatedDatabase() throws {
        // Half a captured file must produce an answer or nothing — never a
        // crash, and never a write to the bytes we were given.
        let data = try database("CREATE TABLE t (a TEXT); INSERT INTO t VALUES ('x');")
        for length in stride(from: 100, to: data.count, by: 512) {
            _ = SQLiteReader.read(data.prefix(length))
        }
    }
}

final class GunzipAndJSONTests: XCTestCase {

    func testInflatesGzip() throws {
        let original = String(repeating: "log line with repeated content\n", count: 200)
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-\(UUID().uuidString).txt")
        try original.write(to: file, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: file) }
        defer { try? FileManager.default.removeItem(at: file.appendingPathExtension("gz")) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/gzip")
        process.arguments = ["-k", "-f", file.path]
        try process.run()
        process.waitUntilExit()

        let compressed = try Data(contentsOf: file.appendingPathExtension("gz"))
        XCTAssertTrue(Gunzip.detect(compressed))
        let inflated = try XCTUnwrap(Gunzip.inflate(compressed))
        XCTAssertEqual(String(data: inflated, encoding: .utf8), original)
    }

    func testGunzipRejectsOtherContent() {
        XCTAssertFalse(Gunzip.detect(Data("not compressed at all, honestly".utf8)))
        XCTAssertNil(Gunzip.inflate(Data([0x1F, 0x8B, 0x08] + [UInt8](repeating: 0, count: 40))))
    }

    func testPrettyPrintsJSON() throws {
        let data = Data(#"{"b":2,"a":[1,2,{"c":"three"}]}"#.utf8)
        XCTAssertTrue(JSONReader.detect(data))
        let pretty = try XCTUnwrap(JSONReader.read(data))
        XCTAssertTrue(pretty.contains("\"a\" : ["))
        XCTAssertTrue(pretty.contains("\"three\""))
        XCTAssertLessThan(pretty.range(of: "\"a\"")!.lowerBound,
                          pretty.range(of: "\"b\"")!.lowerBound, "keys are sorted")
    }

    func testJSONDetectionIgnoresLeadingWhitespaceAndRejectsProse() {
        XCTAssertTrue(JSONReader.detect(Data("\n  {\"a\":1}".utf8)))
        XCTAssertFalse(JSONReader.detect(Data("plain text".utf8)))
        XCTAssertNil(JSONReader.read(Data("{not json}".utf8)))
    }
}

final class StructuredReadTests: XCTestCase {

    func testPicksTheRightReaderForEachFormat() throws {
        let plist = try PropertyListSerialization.data(
            fromPropertyList: ["a": "b"], format: .binary, options: 0)
        XCTAssertEqual(StructuredRead.read(plist)?.format, .plist)

        let json = Data(#"{"a":1,"b":[2,3]}"#.utf8)
        XCTAssertEqual(StructuredRead.read(json)?.format, .json)

        let segb = Data(base64Encoded: "U0VHQgIAAAAAAAAAaSDHQQAAAAAAAAAAAAAAAAAAAACdzpo0AAAAAAoaY29tLmFwcGxlLlF1aWNrVGltZVBsYXllclgQ8yAZAAAABWkgx0H4xrgKAAAAAAodY28ucGl4ZWx3b3JzaGlwLnNlY3VyZS1maW5kZXISDwgHEgtBQiQwREM1Q0E4NzAAAAABAAAAAAAAAGkgx0FoAAAAAwAAAAAAgABpIMdB")!
        XCTAssertEqual(StructuredRead.read(segb)?.format, .records)

        XCTAssertNil(StructuredRead.read(Data(repeating: 0x00, count: 500)))
        XCTAssertNil(StructuredRead.read(Data()))
    }

    func testNamesTheBiomeStreamWhenThePathSaysWhichItIs() {
        let segb = Data(base64Encoded: "U0VHQgIAAAAAAAAAaSDHQQAAAAAAAAAAAAAAAAAAAACdzpo0AAAAAAoaY29tLmFwcGxlLlF1aWNrVGltZVBsYXllclgQ8yAZAAAABWkgx0H4xrgKAAAAAAodY28ucGl4ZWx3b3JzaGlwLnNlY3VyZS1maW5kZXISDwgHEgtBQiQwREM1Q0E4NzAAAAABAAAAAAAAAGkgx0FoAAAAAwAAAAAAgABpIMdB")!
        let reading = StructuredRead.read(
            segb, path: "/Users/x/Library/Biome/streams/restricted/App.InFocus/local/79")
        XCTAssertEqual(reading?.title, "SEGB v2 · In Focus")
    }

    func testLooksInsideCompressedContent() throws {
        // A gzipped file is opaque to every other reading: no strings, no
        // structure. What is inside is usually perfectly readable.
        let json = Data(#"{"buried":"treasure"}"#.utf8)
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-\(UUID().uuidString).json")
        try json.write(to: file)
        defer {
            try? FileManager.default.removeItem(at: file)
            try? FileManager.default.removeItem(at: file.appendingPathExtension("gz"))
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/gzip")
        process.arguments = ["-k", "-f", file.path]
        try process.run()
        process.waitUntilExit()

        let compressed = try Data(contentsOf: file.appendingPathExtension("gz"))
        let reading = try XCTUnwrap(StructuredRead.read(compressed))
        XCTAssertEqual(reading.format, .json)
        XCTAssertTrue(reading.decompressed)
        XCTAssertTrue(reading.title.hasPrefix("gzip →"))
        XCTAssertTrue(reading.text.contains("treasure"))
    }

    func testDoesNotClaimSmallBuffersArePr0tobuf() {
        // Short byte sequences decode as protobuf by coincidence all the time;
        // claiming one is a message produces confident nonsense.
        XCTAssertNil(StructuredRead.read(Data([0x08, 0x01])))
    }

    func testContentSearchReadsInsideDatabasesAndPlists() throws {
        let plist = try PropertyListSerialization.data(
            fromPropertyList: ["contact": "+12057254200"], format: .binary, options: 0)
        let (text, source) = ContentSearchEngine.extract(from: plist)
        XCTAssertEqual(source, .parsed(.plist))
        // The number is in the bytes, but so is a length prefix and a type
        // marker; what matters is that the search sees the value in context.
        XCTAssertTrue(try XCTUnwrap(text).contains("contact: +12057254200"))
    }
}
