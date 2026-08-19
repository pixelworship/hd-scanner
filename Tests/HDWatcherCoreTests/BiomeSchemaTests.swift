import XCTest
@testable import HDWatcherCore

/// Field numbers alone are structurally correct and nearly useless. These cover
/// the layer that turns them into names and meanings.
final class BiomeSchemaTests: XCTestCase {

    func testKnowsAWorthwhileNumberOfStreams() {
        XCTAssertGreaterThan(BiomeSchema.streamCount, 70)
        XCTAssertNotNil(BiomeSchema.stream(named: "App.InFocus"))
        XCTAssertNotNil(BiomeSchema.stream(named: "Media.NowPlaying"))
        XCTAssertNil(BiomeSchema.stream(named: "Not.A.Real.Stream"))
    }

    func testIdentifiesTheStreamFromWhereTheFileSits() {
        // Biome files are named by number, so the path is the only clue.
        let stream = BiomeSchema.stream(
            forFilePath: "/Users/x/Library/Biome/streams/restricted/App.InFocus/local/797995217225977")
        XCTAssertEqual(stream?.name, "App.InFocus")

        // Remote device streams sit one level deeper on the other side.
        let bluetooth = BiomeSchema.stream(
            forFilePath: "/Users/x/Library/Biome/streams/restricted/Device.Wireless.Bluetooth/remote/15A1C2EC-281A")
        XCTAssertEqual(bluetooth?.name, "Device.Wireless.Bluetooth")

        XCTAssertNil(BiomeSchema.stream(forFilePath: "/Users/x/Desktop/notes.txt"))
        XCTAssertNil(BiomeSchema.stream(forFilePath: "streams"))
    }

    func testNamesFieldsIncludingNestedOnes() throws {
        let focus = try XCTUnwrap(BiomeSchema.stream(named: "App.InFocus"))
        XCTAssertEqual(focus.field(at: "6")?.label, "Bundle ID")
        XCTAssertEqual(focus.field(at: "4")?.kind, .appleTime)

        // A field inside a nested message is addressed by its path.
        let install = try XCTUnwrap(BiomeSchema.stream(named: "_DKEvent.App.Install"))
        XCTAssertEqual(install.field(at: "4.3")?.label, "Bundle ID")
    }

    func testKnowsWhatParticularValuesMean() throws {
        let focus = try XCTUnwrap(BiomeSchema.stream(named: "App.InFocus"))
        let action = try XCTUnwrap(focus.field(at: "3"))
        XCTAssertEqual(action.values[1], "Foreground")
        XCTAssertEqual(action.values[0], "Background")
        XCTAssertEqual(BiomeSchema.describe(1, field: action), "Foreground")
        XCTAssertNil(BiomeSchema.describe(7, field: action), "an unlisted value must not be invented")
    }

    func testRendersAppleReferenceDatesAsDates() throws {
        let focus = try XCTUnwrap(BiomeSchema.stream(named: "App.InFocus"))
        let start = try XCTUnwrap(focus.field(at: "4"))

        // Shown in the reader's own time zone, like every other timestamp in
        // the app; a records view that silently switched to UTC would be a trap.
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let expected = formatter.string(from: Date(timeIntervalSinceReferenceDate: 776_000_000))
        XCTAssertEqual(BiomeSchema.describe(776_000_000, field: start), expected)
    }

    func testDescribesNothingWithoutAField() {
        XCTAssertNil(BiomeSchema.describe(776_000_000, field: nil))
    }

    func testDecodedRecordsCarryTheNames() throws {
        // field 6 = "com.apple.mobilesafari", field 3 = 1
        var data = Data([0x32, 0x16])
        data.append(Data("com.apple.mobilesafari".utf8))
        data.append(contentsOf: [0x18, 0x01])

        let fields = try XCTUnwrap(ProtobufSnoop.decode(data))
        let named = ProtobufSnoop.describe(fields, stream: BiomeSchema.stream(named: "App.InFocus"))
            .joined(separator: "\n")
        XCTAssertTrue(named.contains("Bundle ID (6)"), named)
        XCTAssertTrue(named.contains("Foreground"), named)

        // Without a schema the structure survives; only the names are missing.
        let anonymous = ProtobufSnoop.describe(fields).joined(separator: "\n")
        XCTAssertTrue(anonymous.contains("6: \"com.apple.mobilesafari\""))
        XCTAssertFalse(anonymous.contains("Bundle ID"))
    }

    func testSchemaSuppressesTheTimestampGuess() throws {
        // Without a schema, any value in the plausible range is annotated as a
        // date. A field the schema says is a count must not be.
        let plugged = try XCTUnwrap(BiomeSchema.stream(named: "Device.Power.PluggedIn"))
        let state = try XCTUnwrap(plugged.field(at: "1"))
        XCTAssertEqual(BiomeSchema.describe(1, field: state), "Plugged In")
        XCTAssertEqual(BiomeSchema.describe(0, field: state), "Not Plugged In")

        var data = Data([0x08])   // field 1, varint
        var value = UInt64(776_000_000)
        while value >= 0x80 { data.append(UInt8(value & 0x7F | 0x80)); value >>= 7 }
        data.append(UInt8(value))

        let fields = try XCTUnwrap(ProtobufSnoop.decode(data))
        let described = ProtobufSnoop.describe(fields, stream: plugged).joined()
        XCTAssertFalse(described.contains("2025-"),
                       "the schema says this field is a state, not a date: \(described)")
    }
}
