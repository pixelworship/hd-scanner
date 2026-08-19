import XCTest
@testable import HDWatcherCore

/// The fixtures below are byte-for-byte the files checked against CCL
/// Forensics' `ccl_segb`, the reference reader for this format: both records in
/// each file parse there with the same offsets, timestamps, states and CRC
/// results asserted here.
final class SEGBTests: XCTestCase {

    private let v1 = Data(base64Encoded: "0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNFR0IoAAAAAQAAAAAAAABpIMdBAABAAGkgx0Gdzpo0AAAAAAoaY29tLmFwcGxlLlF1aWNrVGltZVBsYXllclgQ8yAZAAAABWkgx0EwAAAAAQAAAAAAgABpIMdBAADAAGkgx0H4xrgKAAAAAAodY28ucGl4ZWx3b3JzaGlwLnNlY3VyZS1maW5kZXISDwgHEgtBQiQwREM1Q0E4Nw==")!
    private let v2 = Data(base64Encoded: "U0VHQgIAAAAAAAAAaSDHQQAAAAAAAAAAAAAAAAAAAACdzpo0AAAAAAoaY29tLmFwcGxlLlF1aWNrVGltZVBsYXllclgQ8yAZAAAABWkgx0H4xrgKAAAAAAodY28ucGl4ZWx3b3JzaGlwLnNlY3VyZS1maW5kZXISDwgHEgtBQiQwREM1Q0E4NzAAAAABAAAAAAAAAGkgx0FoAAAAAwAAAAAAgABpIMdB")!

    func testDetectsBothLayouts() {
        // v1 hides the magic at the end of the header; v2 leads with it.
        XCTAssertEqual(SEGB.detect(v1), .v1)
        XCTAssertEqual(SEGB.detect(v2), .v2)
        XCTAssertNil(SEGB.detect(Data("not a record file at all, just text".utf8)))
        XCTAssertNil(SEGB.detect(Data()))
    }

    func testReadsV1Records() throws {
        let document = try XCTUnwrap(SEGB.parse(v1))
        XCTAssertEqual(document.version, .v1)
        XCTAssertEqual(document.records.count, 2)

        let first = document.records[0]
        XCTAssertEqual(first.offset, 88)
        XCTAssertEqual(first.data.count, 40)
        XCTAssertEqual(first.state, .written)
        XCTAssertEqual(first.timestamp?.timeIntervalSinceReferenceDate, 776_000_000)
        XCTAssertEqual(first.secondaryTimestamp?.timeIntervalSinceReferenceDate, 776_000_000.5)
        XCTAssertTrue(first.crcPassed)

        // Records are padded to eight bytes, so the second does not begin where
        // the first ends.
        XCTAssertEqual(document.records[1].offset, 160)
        XCTAssertEqual(document.records[1].data.count, 48)
        XCTAssertTrue(document.records[1].crcPassed)
    }

    func testReadsV2RecordsFromTheTrailer() throws {
        let document = try XCTUnwrap(SEGB.parse(v2))
        XCTAssertEqual(document.version, .v2)
        XCTAssertEqual(document.created?.timeIntervalSinceReferenceDate, 776_000_000)
        XCTAssertEqual(document.records.count, 2)
        XCTAssertEqual(document.records.map(\.state), [.written, .deleted])
        XCTAssertEqual(document.records.map(\.data.count), [40, 48])
        XCTAssertTrue(document.records.allSatisfy(\.crcPassed))
        XCTAssertEqual(document.deletedCount, 1)
    }

    func testCatchesACorruptedRecord() throws {
        // Flip a byte in the first payload: the stored CRC no longer matches,
        // which is exactly the signal that a record was tampered with.
        var damaged = v2
        damaged[45] ^= 0xFF
        let document = try XCTUnwrap(SEGB.parse(damaged))
        XCTAssertFalse(document.records[0].crcPassed)
        XCTAssertEqual(document.failedCRCCount, 1)
    }

    func testSurvivesTruncationWithoutCrashing() {
        // A capture can be cut short, and half a file must not take the app
        // down or invent records.
        for length in stride(from: 4, to: v2.count, by: 7) {
            let document = SEGB.parse(v2.prefix(length))
            XCTAssertLessThanOrEqual(document?.records.count ?? 0, 2)
        }
        for length in stride(from: 4, to: v1.count, by: 7) {
            let document = SEGB.parse(v1.prefix(length))
            XCTAssertLessThanOrEqual(document?.records.count ?? 0, 2)
        }
    }

    func testRendersRecordsAsReadableText() throws {
        let document = try XCTUnwrap(SEGB.parse(v2))
        let text = SEGB.render(document)
        XCTAssertTrue(text.contains("SEGB v2 · 2 records"))
        XCTAssertTrue(text.contains("com.apple.QuickTimePlayerX"),
                      "the whole point is that the payload becomes readable")
        XCTAssertTrue(text.contains("co.pixelworship.secure-finder"))
        XCTAssertTrue(text.contains("Deleted"))
    }

    func testCRC32MatchesZlib() {
        // Values from zlib.crc32, which is what writes these files.
        XCTAssertEqual(CRC32.checksum(Data()), 0)
        XCTAssertEqual(CRC32.checksum(Data("123456789".utf8)), 0xCBF4_3926)
        XCTAssertEqual(CRC32.checksum(Data("The quick brown fox jumps over the lazy dog".utf8)), 0x414F_A339)
    }
}

final class ProtobufSnoopTests: XCTestCase {

    /// field 1 (string) = "hello", field 2 (varint) = 300
    private let message = Data([0x0A, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x10, 0xAC, 0x02])

    func testDecodesStringsAndVarints() throws {
        let fields = try XCTUnwrap(ProtobufSnoop.decode(message))
        XCTAssertEqual(fields.count, 2)
        guard case .text(let text) = fields[0].value else { return XCTFail("expected a string") }
        XCTAssertEqual(text, "hello")
        guard case .varint(let number) = fields[1].value else { return XCTFail("expected a varint") }
        XCTAssertEqual(number, 300)
    }

    func testDecodesNestedMessages() throws {
        var nested = Data([0x12, UInt8(message.count)])
        nested.append(message)
        let fields = try XCTUnwrap(ProtobufSnoop.decode(nested))
        guard case .message(let inner) = fields[0].value else { return XCTFail("expected nesting") }
        XCTAssertEqual(inner.count, 2)
    }

    func testRejectsThingsThatAreNotProtobuf() {
        // Loose parsing would turn any blob into a plausible tree of nonsense,
        // so a decode that does not consume the buffer exactly must fail.
        XCTAssertNil(ProtobufSnoop.decode(Data()))
        XCTAssertNil(ProtobufSnoop.decode(Data([0x0A, 0x40, 0x01])))          // length past the end
        XCTAssertNil(ProtobufSnoop.decode(Data(repeating: 0xFF, count: 32)))  // no terminating varint byte
        XCTAssertNil(ProtobufSnoop.decode(Data([0x0F, 0x01])))                // wire type 7
    }

    func testDescribesTimestampsAsDates() throws {
        // 8 bytes of double, tagged as field 3 fixed64: Apple's reference-date
        // seconds, which read as a number are meaningless.
        var data = Data([0x19])
        withUnsafeBytes(of: Double(776_000_000).bitPattern.littleEndian) { data.append(contentsOf: $0) }
        let fields = try XCTUnwrap(ProtobufSnoop.decode(data))
        let described = ProtobufSnoop.describe(fields).joined()
        XCTAssertTrue(described.contains("2025-08-04"), "got: \(described)")
    }
}

/// The browser window renders every record once, up front, so that scrolling
/// and searching never re-parse. These cover that preparation step.
final class ParsedRecordPreparationTests: XCTestCase {

    private let v2 = Data(base64Encoded: "U0VHQgIAAAAAAAAAaSDHQQAAAAAAAAAAAAAAAAAAAACdzpo0AAAAAAoaY29tLmFwcGxlLlF1aWNrVGltZVBsYXllclgQ8yAZAAAABWkgx0H4xrgKAAAAAAodY28ucGl4ZWx3b3JzaGlwLnNlY3VyZS1maW5kZXISDwgHEgtBQiQwREM1Q0E4NzAAAAABAAAAAAAAAGkgx0FoAAAAAwAAAAAAgABpIMdB")!

    func testRendersEveryRecordWithoutTheDocumentLevelCap() throws {
        let document = try XCTUnwrap(SEGB.parse(v2, maxRecords: 200_000))
        XCTAssertEqual(document.records.count, 2)
        // Whole-file rendering must not silently stop partway through: the
        // window exists precisely to show what the preview clipped.
        let text = SEGB.render(document, maxRecords: 200_000)
        XCTAssertFalse(text.contains("further records not shown"))
        XCTAssertTrue(text.contains("#2"))
    }

    func testEmptyRecordFileIsStillADocument() {
        // A stream that has been created but never written to: valid, just
        // empty. It must not read as "not a record file".
        var header = Data("SEGB".utf8)
        header.append(contentsOf: [0, 0, 0, 0])
        header.append(Data(repeating: 0, count: 24))
        let document = SEGB.parse(header)
        XCTAssertNotNil(document)
        XCTAssertEqual(document?.records.count, 0)
        XCTAssertNil(document?.problem)
    }
}
