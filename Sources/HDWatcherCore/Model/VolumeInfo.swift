import Foundation

/// Broad classification of a mounted volume. Drives the "did data leave the
/// machine?" logic in the transfer detector and the volume-scope conditions in
/// alert rules.
public enum VolumeClass: String, Codable, Sendable, CaseIterable {
    case internalDisk    // built-in, non-removable
    case externalDisk    // USB/Thunderbolt attached physical media
    case removable       // ejectable media (SD, optical, thumb drives)
    case network         // SMB/AFP/NFS
    case diskImage       // mounted .dmg/.sparsebundle
    case unknown

    public var displayName: String {
        switch self {
        case .internalDisk: return "Internal"
        case .externalDisk: return "External"
        case .removable:    return "Removable"
        case .network:      return "Network"
        case .diskImage:    return "Disk Image"
        case .unknown:      return "Unknown"
        }
    }

    public var symbolName: String {
        switch self {
        case .internalDisk: return "internaldrive"
        case .externalDisk: return "externaldrive"
        case .removable:    return "sdcard"
        case .network:      return "network"
        case .diskImage:    return "opticaldiscdrive"
        case .unknown:      return "questionmark.circle"
        }
    }

    /// Anything that is not the machine's own internal storage is a place data
    /// can escape to.
    public var isOffMachine: Bool { self != .internalDisk }
}

public struct VolumeInfo: Codable, Sendable, Identifiable, Hashable {
    /// Volume UUID when available, otherwise the mount path.
    public var id: String
    public var name: String
    public var mountPath: String
    public var volumeClass: VolumeClass
    public var isRootVolume: Bool
    public var totalCapacity: Int64
    public var availableCapacity: Int64
    public var formatDescription: String
    public var firstSeen: Date
    public var isMounted: Bool
    /// Internal macOS plumbing — the Data/Preboot/VM volumes, cryptex mounts,
    /// devfs, simulator runtimes. Needed for path attribution, but not what a
    /// user means by "a volume", so hidden from the list by default.
    public var isSystemVolume: Bool

    public init(
        id: String,
        name: String,
        mountPath: String,
        volumeClass: VolumeClass,
        isRootVolume: Bool = false,
        totalCapacity: Int64 = 0,
        availableCapacity: Int64 = 0,
        formatDescription: String = "",
        firstSeen: Date = Date(),
        isMounted: Bool = true,
        isSystemVolume: Bool = false
    ) {
        self.id = id
        self.name = name
        self.mountPath = mountPath
        self.volumeClass = volumeClass
        self.isRootVolume = isRootVolume
        self.totalCapacity = totalCapacity
        self.availableCapacity = availableCapacity
        self.formatDescription = formatDescription
        self.firstSeen = firstSeen
        self.isMounted = isMounted
        self.isSystemVolume = isSystemVolume
    }

    public var usedCapacity: Int64 { max(0, totalCapacity - availableCapacity) }
    public var usedFraction: Double {
        totalCapacity > 0 ? Double(usedCapacity) / Double(totalCapacity) : 0
    }
}
