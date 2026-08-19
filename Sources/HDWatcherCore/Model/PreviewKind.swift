import Foundation

/// How a captured version should be presented.
///
/// Decided from the actual bytes first and the file extension second. A
/// screenshot saved without an extension is still an image, and something named
/// `.txt` that turns out to be binary should not be rendered as mangled text.
public enum PreviewKind: String, Sendable, CaseIterable {
    case image
    case pdf
    case text
    case audio
    case video
    case archive
    case binary
    /// Apple's SEGB record files, as used by Biome.
    case records

    public var displayName: String {
        switch self {
        case .image:   return "Image"
        case .pdf:     return "PDF"
        case .text:    return "Text"
        case .audio:   return "Audio"
        case .video:   return "Video"
        case .archive: return "Archive"
        case .binary:  return "Binary"
        case .records: return "Records"
        }
    }

    public var symbolName: String {
        switch self {
        case .image:   return "photo"
        case .pdf:     return "doc.richtext"
        case .text:    return "doc.plaintext"
        case .audio:   return "waveform"
        case .video:   return "film"
        case .archive: return "shippingbox"
        case .binary:  return "doc.badge.gearshape"
        case .records: return "list.bullet.rectangle"
        }
    }

    /// True when two versions can be compared line by line.
    public var supportsTextDiff: Bool { self == .text }
    /// True when two versions can be shown side by side.
    public var supportsVisualDiff: Bool { self == .image || self == .pdf }
    /// True when the app can render it itself rather than handing it off.
    public var isRenderable: Bool { self == .image || self == .pdf || self == .text }

    // MARK: - Detection

    /// Leading bytes that identify a format regardless of what it is called.
    private static let signatures: [(bytes: [UInt8], kind: PreviewKind)] = [
        ([0x89, 0x50, 0x4E, 0x47], .image),               // PNG
        ([0xFF, 0xD8, 0xFF], .image),                     // JPEG
        ([0x47, 0x49, 0x46, 0x38], .image),               // GIF
        ([0x42, 0x4D], .image),                           // BMP
        ([0x49, 0x49, 0x2A, 0x00], .image),               // TIFF little endian
        ([0x4D, 0x4D, 0x00, 0x2A], .image),               // TIFF big endian
        ([0x25, 0x50, 0x44, 0x46], .pdf),                 // %PDF
        ([0x50, 0x4B, 0x03, 0x04], .archive),             // zip and friends
        ([0x1F, 0x8B], .archive),                         // gzip
        ([0x42, 0x5A, 0x68], .archive),                   // bzip2
        ([0xFD, 0x37, 0x7A, 0x58, 0x5A], .archive),       // xz
        ([0x49, 0x44, 0x33], .audio),                     // MP3 with ID3
        ([0x4F, 0x67, 0x67, 0x53], .audio),               // Ogg
        ([0x66, 0x4C, 0x61, 0x43], .audio),               // FLAC
    ]

    private static let extensionMap: [String: PreviewKind] = [
        "png": .image, "jpg": .image, "jpeg": .image, "gif": .image, "bmp": .image,
        "tiff": .image, "tif": .image, "heic": .image, "heif": .image, "webp": .image,
        "icns": .image, "ico": .image, "svg": .image,
        "pdf": .pdf,
        "mp3": .audio, "wav": .audio, "aiff": .audio, "aif": .audio, "m4a": .audio,
        "flac": .audio, "ogg": .audio, "aac": .audio,
        "mp4": .video, "mov": .video, "avi": .video, "mkv": .video, "m4v": .video,
        "webm": .video, "wmv": .video,
        "zip": .archive, "gz": .archive, "tar": .archive, "bz2": .archive, "xz": .archive,
        "dmg": .archive, "7z": .archive, "rar": .archive,
    ]

    /// Classifies content. `data` may be a prefix; only the first bytes matter.
    public static func detect(data: Data, fileName: String) -> PreviewKind {
        // A record file is readable in a way no other binary is, so it is
        // worth identifying before anything else.
        if SEGB.detect(data) != nil { return .records }

        // Magic bytes beat the name: a file's contents are what it actually is.
        if !data.isEmpty {
            let prefix = [UInt8](data.prefix(16))
            for signature in signatures where prefix.starts(with: signature.bytes) {
                return signature.kind
            }
            // RIFF containers: WAVE and WEBP share a header.
            if prefix.count >= 12, Array(prefix[0..<4]) == Array("RIFF".utf8) {
                let form = String(bytes: prefix[8..<12], encoding: .ascii) ?? ""
                if form == "WEBP" { return .image }
                if form == "WAVE" { return .audio }
                if form == "AVI " { return .video }
            }
            // ISO base media: HEIC, MP4, MOV all carry "ftyp" at offset 4.
            if prefix.count >= 12, Array(prefix[4..<8]) == Array("ftyp".utf8) {
                let brand = String(bytes: prefix[8..<12], encoding: .ascii) ?? ""
                if brand.hasPrefix("heic") || brand.hasPrefix("heix")
                    || brand.hasPrefix("mif1") { return .image }
                if brand.hasPrefix("qt") { return .video }
                return .video
            }
        }

        let ext = (fileName as NSString).pathExtension.lowercased()
        if let mapped = extensionMap[ext] { return mapped }

        // Nothing recognised: decide between text and binary by inspection.
        return FileSnapshot.looksTextual(data) ? .text : .binary
    }
}
