import XCTest
@testable import HDWatcherCore

final class BinaryDiffTests: XCTestCase {

    private func data(_ bytes: [UInt8]) -> Data { Data(bytes) }

    func testIdenticalContentReportsNoChange() {
        let blob = Data((0..<1_000).map { UInt8($0 % 251) })
        let summary = BinaryDiff.summarize(blob, blob)
        XCTAssertTrue(summary.identical)
        XCTAssertNil(summary.firstDifferenceOffset)
        XCTAssertEqual(summary.differingByteCount, 0)
        XCTAssertFalse(BinaryDiff.compare(blob, blob).hasChanges)
    }

    func testFindsWhereTwoVersionsFirstDisagree() {
        var old = Data(repeating: 0xAA, count: 500)
        var new = old
        new[321] = 0x01
        let summary = BinaryDiff.summarize(old, new)
        XCTAssertFalse(summary.identical)
        XCTAssertEqual(summary.firstDifferenceOffset, 321)
        XCTAssertEqual(summary.differingByteCount, 1)

        old.append(contentsOf: [1, 2, 3])
        XCTAssertEqual(BinaryDiff.summarize(old, new).sizeDelta, -3)
        // Sizes differ, so the bytes no longer line up and counting them would
        // be a fiction.
        XCTAssertNil(BinaryDiff.summarize(old, new).differingByteCount)
    }

    func testEditInPlaceIsPairedAsOneChangedRow() throws {
        let old = Data((0..<160).map { UInt8($0) })
        var new = old
        new[70] = 0xFF
        new[71] = 0xFE

        let result = BinaryDiff.compare(old, new)
        XCTAssertEqual(result.changedRowCount, 1, "an overwrite is one row changed, not a delete plus an insert")
        XCTAssertEqual(result.addedRowCount, 0)
        XCTAssertEqual(result.removedRowCount, 0)

        let changed = try XCTUnwrap(result.rows.first { $0.kind == .changed })
        XCTAssertEqual(changed.differingColumns, [6, 7])
        XCTAssertEqual(changed.oldOffset, 64)
    }

    func testInsertionShiftsRatherThanRewritingEverythingAfterIt() {
        let old = Data((0..<320).map { UInt8($0 % 97) })
        var new = old
        new.insert(contentsOf: Data(repeating: 0x5A, count: 16), at: 160)

        let result = BinaryDiff.compare(old, new)
        XCTAssertTrue(result.hasChanges)
        // The whole tail matches at a 16-byte shift, so exactly one row is new.
        XCTAssertEqual(result.addedRowCount, 1)
        XCTAssertEqual(result.removedRowCount, 0)
        XCTAssertEqual(result.changedRowCount, 0)
    }

    func testLongIdenticalRegionsAreSkippedNotListed() {
        var old = Data(repeating: 0x00, count: 64_000)
        old.replaceSubrange(32_000..<32_004, with: Data([1, 2, 3, 4]))
        var new = old
        new.replaceSubrange(32_000..<32_004, with: Data([9, 9, 9, 9]))

        let result = BinaryDiff.compare(old, new)
        // 4,000 rows of unchanged zeros must not become 4,000 rows of UI.
        XCTAssertLessThan(result.rows.count, 40)
        XCTAssertTrue(result.rows.contains { $0.kind == .gap && $0.skipped > 1_000 })
        XCTAssertEqual(result.changedRowCount, 1)
    }

    func testComparesAgainstEmptyContent() {
        let blob = Data((0..<64).map { UInt8($0) })
        let added = BinaryDiff.compare(Data(), blob)
        XCTAssertEqual(added.addedRowCount, 4)
        XCTAssertEqual(added.summary.sizeDelta, 64)

        let removed = BinaryDiff.compare(blob, Data())
        XCTAssertEqual(removed.removedRowCount, 4)

        XCTAssertTrue(BinaryDiff.compare(Data(), Data()).rows.isEmpty)
    }

    func testStaysBoundedOnLargeUnrelatedContent() {
        // Two megabytes with nothing in common: the comparison has to come back
        // in reasonable time and reasonable size, not build a quadratic table
        // over 130,000 rows.
        let old = Data((0..<2_000_000).map { _ in UInt8.random(in: 0...255) })
        let new = Data((0..<2_000_000).map { _ in UInt8.random(in: 0...255) })
        let started = Date()
        let result = BinaryDiff.compare(old, new)
        XCTAssertLessThan(Date().timeIntervalSince(started), 30)
        XCTAssertTrue(result.truncated)
        XCTAssertLessThan(result.rows.count, 6_000)
    }
}

final class RawTextViewTests: XCTestCase {

    func testShowsEveryByteNotJustTheReadableRuns() {
        // The complaint this exists for: extraction found one string in a
        // megabyte, so the preview looked empty next to the same file opened in
        // a text editor.
        var data = Data("SEGB".utf8)
        data.append(Data((0..<400).map { UInt8($0 % 256) }))

        let extracted = BinaryText.runs(in: data).map(\.text).joined()
        let raw = BinaryText.rawLines(of: data).lines.map(\.text).joined()
        XCTAssertGreaterThan(raw.count, extracted.count * 2)
        XCTAssertTrue(raw.hasPrefix("SEGB"))
    }

    func testBreaksOnNewlinesAndAtTheWrapWidth() {
        let text = Data("first line\nsecond line\n".utf8)
        let lines = BinaryText.rawLines(of: text).lines
        XCTAssertEqual(lines.map(\.text), ["first line", "second line"])
        XCTAssertEqual(lines[1].offset, 11)

        let long = Data(String(repeating: "x", count: 300).utf8)
        let wrapped = BinaryText.rawLines(of: long, width: 100).lines
        XCTAssertEqual(wrapped.count, 3)
        XCTAssertEqual(wrapped[2].offset, 200)
    }

    func testControlBytesStayVisible() {
        // A NUL that renders as nothing makes a line look shorter than it is.
        let data = Data([0x41, 0x00, 0x42, 0x07, 0x43])
        XCTAssertEqual(BinaryText.rawLines(of: data).lines.first?.text, "A·B·C")
    }

    func testReportsWhenItStopsEarly() {
        let big = Data(repeating: 0x41, count: 10_000)
        let result = BinaryText.rawLines(of: big, width: 10, limit: 50)
        XCTAssertTrue(result.truncated)
        XCTAssertEqual(result.lines.count, 50)
    }
}

final class AnalysisPromptTests: XCTestCase {

    private func snapshot(path: String, size: Int64) -> FileSnapshot {
        FileSnapshot(path: path, capturedAt: Date(), byteSize: size,
                     contentHash: Data(), offset: 0, storedLength: UInt32(size),
                     reason: .modified)
    }

    func testDescribesARecordFileByItsRecords() {
        let segb = Data(base64Encoded: "U0VHQgIAAAAAAAAAaSDHQQAAAAAAAAAAAAAAAAAAAACdzpo0AAAAAAoaY29tLmFwcGxlLlF1aWNrVGltZVBsYXllclgQ8yAZAAAABWkgx0H4xrgKAAAAAAodY28ucGl4ZWx3b3JzaGlwLnNlY3VyZS1maW5kZXISDwgHEgtBQiQwREM1Q0E4NzAAAAABAAAAAAAAAGkgx0FoAAAAAwAAAAAAgABpIMdB")!
        let payload = AnalysisPrompt.describe(
            snapshot: snapshot(path: "/Users/x/Library/Biome/streams/restricted/App.MediaUsage/local/79", size: Int64(segb.count)),
            data: segb, kind: .records)

        XCTAssertTrue(payload.text.contains("SEGB v2"))
        XCTAssertTrue(payload.text.contains("Library/Biome"))
        XCTAssertTrue(payload.text.contains("com.apple.QuickTimePlayerX"),
                      "the decoded records are the useful part of the question")
        XCTAssertFalse(payload.truncated)
    }

    func testKeepsLargeFilesWithinBudget() {
        let big = Data((0..<400_000).map { _ in UInt8.random(in: 32...126) })
        let payload = AnalysisPrompt.describe(snapshot: snapshot(path: "/tmp/big.bin", size: 400_000),
                                              data: big, kind: .binary)
        XCTAssertTrue(payload.truncated)
        XCTAssertLessThan(payload.text.count, AnalysisPrompt.defaultBudget + 2_000)
    }

    func testOnlyBuildsALinkWhenTheWholePromptFits() {
        let short = AnalysisPrompt.chatGPTURL(for: "what is this file")
        XCTAssertEqual(short?.host, "chatgpt.com")
        XCTAssertTrue(short?.query?.contains("what%20is%20this%20file") ?? false)

        // A link that silently dropped its tail would send a truncated file
        // with no sign anything was missing.
        XCTAssertNil(AnalysisPrompt.chatGPTURL(for: String(repeating: "x", count: 20_000)))
    }
}
