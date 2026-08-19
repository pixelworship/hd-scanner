"""Turns biome_streams.json into Sources/HDWatcherCore/Formats/BiomeSchemaTable.swift."""

import json
streams = {k: v for k, v in json.load(open("biome_streams.json")).items() if v["fields"]}

def esc(s): return s.replace("\\", "\\\\").replace('"', '\\"')

lines = []
lines.append("""// Generated from the Biome parsers in iLEAPP (https://github.com/abrignoni/iLEAPP,
// MIT, Alexis Brignoni and contributors) by Scripts/extract-biome-schema.py.
// Edit that script and regenerate rather than editing this file.
//
// The wire format carries field numbers, not names. These are the names the
// forensics community has established for each stream by comparing many
// devices against known activity, which is the only way they can be known:
// Apple does not publish the .proto files.

import Foundation

extension BiomeSchema {

    static let table: [Stream] = [""")

for name in sorted(streams):
    entry = streams[name]
    fields = entry["fields"]
    lines.append('        Stream(name: "%s", title: "%s", fields: [' % (esc(name), esc(entry["title"] or name)))
    for path in sorted(fields, key=lambda p: [int(x) for x in p.split(".")]):
        spec = fields[path]
        parts = ['path: "%s"' % path, 'label: "%s"' % esc(spec["label"])]
        if spec.get("kind", "unknown") != "unknown":
            parts.append("kind: .%s" % spec["kind"])
        if spec.get("values"):
            pairs = ", ".join('%s: "%s"' % (k, esc(v)) for k, v in sorted(spec["values"].items(), key=lambda kv: int(kv[0])))
            parts.append("values: [%s]" % pairs)
        lines.append("            Field(%s)," % ", ".join(parts))
    lines.append("        ]),")

lines.append("    ]\n}")
open("BiomeSchemaTable.swift", "w").write("\n".join(lines) + "\n")
print("streams:", len(streams), "| fields:", sum(len(v['fields']) for v in streams.values()))
