import SwiftUI
import HDWatcherCore

struct VolumesView: View {
    @Environment(AppModel.self) private var model
    @State private var showSystemVolumes = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .top) {
                    SectionHeader(title: "Mounted volumes",
                                  subtitle: "\(model.volumes.count) volumes · \(model.coverage.watchedPaths.count) watch root\(model.coverage.watchedPaths.count == 1 ? "" : "s") active")
                    Spacer()
                    Toggle(isOn: $showSystemVolumes) {
                        Label("System volumes", systemImage: "gearshape.2")
                    }
                    .toggleStyle(.button)
                    .controlSize(.small)
                    .help("Show the macOS system mounts: Data, Preboot, VM, cryptex images, simulator runtimes")
                }

                LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 12)], spacing: 12) {
                    ForEach(model.volumes) { volume in
                        VolumeCard(volume: volume,
                                   stat: model.engine?.stats.volumeStat(volume.id),
                                   isWatched: model.coverage.covers(mountPath: volume.mountPath))
                    }
                }

                if showSystemVolumes, !model.systemVolumes.isEmpty {
                    SectionHeader(title: "System volumes",
                                  subtitle: "macOS plumbing. Watched for path attribution, but not something you manage.")
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 12)], spacing: 12) {
                        ForEach(model.systemVolumes) { volume in
                            VolumeCard(volume: volume,
                                       stat: model.engine?.stats.volumeStat(volume.id),
                                       isWatched: model.coverage.covers(mountPath: volume.mountPath))
                                .opacity(0.7)
                        }
                    }
                }

                let departed = model.volumeHistory.filter { !$0.isMounted }
                if !departed.isEmpty {
                    SectionHeader(title: "Previously seen",
                                  subtitle: "Volumes connected during this session that are no longer mounted")
                    VStack(spacing: 6) {
                        ForEach(departed) { volume in
                            HStack(spacing: 8) {
                                Image(systemName: volume.volumeClass.symbolName)
                                    .foregroundStyle(.tertiary)
                                Text(volume.name).font(.callout)
                                Text(volume.volumeClass.displayName)
                                    .font(.caption).foregroundStyle(.secondary)
                                Spacer()
                                Text("first seen \(Format.relativeTime(volume.firstSeen))")
                                    .font(.caption).foregroundStyle(.tertiary)
                            }
                            .padding(.vertical, 5).padding(.horizontal, 10)
                            .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 7))
                        }
                    }
                }

                watchPathsCard
            }
            .padding(18)
        }
    }

    private var watchPathsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Watch roots",
                          subtitle: "Paths handed to FSEvents. Everything beneath them is covered.")
            if model.coverage.watchedPaths.isEmpty {
                Text("Monitoring is not running.").font(.caption).foregroundStyle(.secondary)
            } else {
                ForEach(model.coverage.watchedPaths, id: \.self) { path in
                    HStack(spacing: 6) {
                        Image(systemName: "folder").font(.caption).foregroundStyle(.secondary)
                        Text(path).font(.caption.monospaced()).textSelection(.enabled)
                        Spacer()
                    }
                }
            }
        }
        .card()
    }
}

struct VolumeCard: View {
    let volume: VolumeInfo
    let stat: VolumeStat?
    let isWatched: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 9) {
                Image(systemName: volume.volumeClass.symbolName)
                    .font(.title2)
                    .foregroundStyle(volume.volumeClass.tint)
                VStack(alignment: .leading, spacing: 1) {
                    Text(volume.name).font(.body.weight(.semibold)).lineLimit(1)
                    HStack(spacing: 5) {
                        Text(volume.volumeClass.displayName)
                        if volume.isRootVolume {
                            Text("· startup disk")
                        }
                    }
                    .font(.caption).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                if isWatched {
                    Image(systemName: "eye.fill")
                        .font(.caption).foregroundStyle(.green)
                        .help("Actively watched")
                } else {
                    Image(systemName: "eye.slash")
                        .font(.caption).foregroundStyle(.tertiary)
                        .help("Not covered by the current watch scope")
                }
            }

            if volume.totalCapacity > 0 {
                VStack(alignment: .leading, spacing: 3) {
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            Capsule().fill(.quaternary)
                            Capsule()
                                .fill(volume.usedFraction > 0.9 ? Color.red : volume.volumeClass.tint)
                                .frame(width: geo.size.width * CGFloat(volume.usedFraction))
                        }
                    }
                    .frame(height: 6)
                    HStack {
                        Text("\(Format.bytes(volume.usedCapacity)) used")
                        Spacer()
                        Text("\(Format.bytes(volume.availableCapacity)) free")
                    }
                    .font(.caption2).foregroundStyle(.secondary)
                }
            }

            if let stat {
                HStack(spacing: 12) {
                    counter("Writes", stat.writes, .green)
                    counter("Deletes", stat.deletes, .red)
                    counter("In", stat.transfersIn, .indigo)
                    counter("Out", stat.transfersOut, .orange)
                }
            }

            Text(volume.mountPath)
                .font(.caption2.monospaced())
                .foregroundStyle(.tertiary)
                .lineLimit(1).truncationMode(.middle)
        }
        .card(padding: 13)
    }

    private func counter(_ label: String, _ value: Int, _ color: Color) -> some View {
        VStack(spacing: 0) {
            Text(Format.count(value))
                .font(.caption.monospacedDigit().weight(.semibold))
                .foregroundStyle(color)
            Text(label).font(.system(size: 9)).foregroundStyle(.tertiary)
        }
    }
}
