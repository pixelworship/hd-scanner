"""Reads the Biome parsers in a checked-out iLEAPP tree and works out, per
stream, what each protobuf field number means.

    git clone --depth 1 https://github.com/abrignoni/iLEAPP.git
    python3 Scripts/extract-biome-schema.py      # -> biome_streams.json
    python3 Scripts/emit-biome-schema.py         # -> BiomeSchemaTable.swift

iLEAPP is MIT licensed (Alexis Brignoni and contributors). What is taken here
is the knowledge — field numbers, names, units and value meanings — which those
parsers established by comparing many devices against known activity. Apple
publishes none of it.

The extraction is deliberately conservative: a label is only accepted if it
comes from a table header, an explicit comment, or a variable in the artifact's
own function, and a value table is only attached to the exact field it
interprets. A wrong name is worse than no name.
"""

import re, json, glob, os

TIME_FNS = ("webkit_timestampsconv", "cocoa")
SKIP = {"segb state","filename","offset","segb timestamp","data","source file","record","file",
        "info","info2","info3","output","value (raw)","raw","state","data headers","data list",
        "typess","ts","protostuff","row","rows"}
STEP = r"(?:\[['\"][\w.]+['\"]\]|\.get\(['\"][\w.]+['\"][^)]*\))"

def balanced(text, start):
    depth = 0
    for i in range(start, len(text)):
        if text[i] in "([{": depth += 1
        elif text[i] in ")]}":
            depth -= 1
            if depth == 0: return text[start+1:i]
    return ""

def split_top(s):
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([{": depth += 1
        if ch in ")]}": depth -= 1
        if ch == "," and depth == 0: parts.append(cur.strip()); cur = ""
        else: cur += ch
    if cur.strip(): parts.append(cur.strip())
    return parts

def clean(label):
    label = re.sub(r"\s+", " ", label).strip().strip("'\"")
    label = re.sub(r"\s*\(.*?\)\s*$", "", label)
    # "Full URL string" -> "Full URL", but "Value" on its own is a real label.
    if " " in label:
        label = re.sub(r"\s+(string|value)$", "", label, flags=re.I)
    return label.strip()

def usable(label):
    low = label.lower()
    return (label and len(label) <= 42 and low not in SKIP
            and not any(w in low for w in ("tbd","placeholder","unknown","->","#"))
            and not re.match(r"^field \d+$", low)
            and bool(re.match(r"^[\w][\w /&.'-]*$", label)))

streams = {}

for path in sorted(glob.glob("iLEAPP/scripts/artifacts/biome*.py")):
    text = open(path, encoding="utf-8", errors="replace").read()
    roots = set(re.findall(r"(\w+)\s*,\s*\w+\s*=\s*blackboxprotobuf\.decode_message", text)) or {"protostuff"}
    ref = re.compile(r"\b(?:%s)((?:%s)+)" % ("|".join(map(re.escape, roots)), STEP))
    keyre = re.compile(r"['\"]([\w.]+)['\"]")

    def fields_in(expr):
        out = []
        for m in ref.finditer(expr):
            parts = [keyre.search(t).group(1) for t in re.findall(STEP, m.group(1)) if keyre.search(t)]
            if parts and all(p.isdigit() for p in parts): out.append(".".join(parts))
        return out

    assignments = dict(re.findall(r"^\s*(\w+)\s*=\s*(.*)$", text, re.M))
    def resolve(expr, depth=3):
        for _ in range(depth):
            if ref.search(expr): break
            grown = expr
            for var, value in assignments.items():
                if var in grown and var != value:
                    grown = re.sub(r"\b%s\b" % re.escape(var), lambda _, v=value: v, grown)
            if grown == expr: break
            expr = grown
        return expr

    # module-level value tables, e.g. ON_OFF = {0: 'Off', 1: 'On'}
    tables = {}
    for name, body in re.findall(r"^([A-Z][A-Z0-9_]*)\s*=\s*(\{[^}]*\})", text, re.M):
        pairs = dict((int(k), v) for k, v in re.findall(r"(\d+)\s*:\s*'([^']*)'", body))
        if pairs: tables[name] = pairs

    types = {}
    for m in re.finditer(r"[Tt]ypess?\s*=\s*\{", text):
        for f, k in re.findall(r"'([\d.]+)':\s*\{\s*'(?:type|name)':\s*'(\w*)'",
                               balanced(text, m.end()-1)):
            if k: types.setdefault(f, k)

    # function bodies
    funcs = {}
    defs = [(m.group(1), m.start()) for m in re.finditer(r"^def (\w+)\(", text, re.M)]
    for i, (name, start) in enumerate(defs):
        end = defs[i+1][1] if i+1 < len(defs) else len(text)
        funcs[name] = text[start:end]

    helper_fields = {name: sorted(set(fields_in(body))) for name, body in funcs.items()}

    # Which parameter of a helper is its value table, and exactly which field
    # that table interprets. Attaching a table to every field the helper touches
    # would label timestamps "On"/"Off".
    helper_tables = {}
    for name, body in funcs.items():
        signature = re.search(r"def \w+\(([^)]*)\)", body)
        params = [p.split("=")[0].strip() for p in split_top(signature.group(1))] if signature else []
        per_param = {}
        for param in params:
            for m in re.finditer(r"\b%s\.get\(\s*([^,)]+)" % re.escape(param), body):
                for field in fields_in(resolve(m.group(1))):
                    per_param.setdefault(param, set()).add(field)
        helper_tables[name] = (params, per_param)

    # artifacts: key -> paths
    artifacts = {}
    am = re.search(r"__artifacts_v2__\s*=\s*\{", text)
    if am:
        block = balanced(text, am.end()-1)
        for key_m in re.finditer(r'"(\w+)":\s*\{', block):
            entry = balanced(block, key_m.end()-1)
            paths = re.findall(r"streams/(?:restricted|public|\*)/([\w.\-]+)", entry)
            title = re.search(r'"name":\s*"([^"]+)"', entry)
            if paths:
                artifacts[key_m.group(1)] = (paths, re.sub(r"^Biome\s*-\s*", "", title.group(1) if title else ""))

    for key, (names, title) in artifacts.items():
        body = funcs.get(key, text)
        mapping = {}

        def note(field, label, transform=None, values=None):
            label = clean(label)
            if not usable(label): return
            entry = mapping.setdefault(field, {"label": label, "kind": "unknown"})
            if transform: entry["kind"] = "appleTime"
            if values: entry["values"] = {str(k): v for k, v in values.items()}
            if entry["kind"] == "unknown":
                entry["kind"] = {"str":"text","int":"integer","double":"real",
                                 "fixed64":"real","bytes":"bytes"}.get(types.get(field,""), "unknown")

        def transform_in(expr):
            return next((fn for fn in TIME_FNS if fn in expr), None)

        # An artifact that reads no fields itself is using a shared helper;
        # follow it there rather than falling back to the whole module, whose
        # other artifacts describe entirely different streams.
        scope = body
        if not fields_in(scope):
            for call in re.finditer(r"\b(_\w+)\(", body):
                candidate = funcs.get(call.group(1))
                if candidate and fields_in(candidate):
                    scope = candidate
                    break
            else:
                scope = text if "data_list.append" not in body else body
        hidx = scope.find("data_headers")
        headers = split_top(balanced(scope, scope.find("(", hidx))) if hidx >= 0 else []
        for m in re.finditer(r"data_list\.append\(", scope):
            values = split_top(balanced(scope, m.end()-1).strip().lstrip("(").rstrip(")"))
            for header, value in zip(headers, values):
                expr = resolve(value)
                label = re.match(r"""\(\s*['"]([^'"]+)['"]""", header.strip())
                for field in fields_in(expr):
                    note(field, label.group(1) if label else header, transform_in(expr))

        # Only this artifact's own assignments: a module can hold a dozen
        # artifacts, and borrowing a label from the one next door produces
        # confident nonsense like a lock state named "Celsius".
        for var, expr in re.findall(r"^\s*(\w+)\s*=\s*(.*)$", scope, re.M):
            resolved = resolve(expr)
            for field in fields_in(resolved):
                note(field, var.replace("_"," ").title(), transform_in(resolved))

        for field, comment in re.findall(r"^\s*#\s*(\d+)\s*->\s*(.+)$", text, re.M):
            note(field, comment)

        # value tables, both spellings: MAP.get(expr) and helper(..., MAP)
        for m in re.finditer(r"\b([A-Z][A-Z0-9_]*)\.get\(\s*([^,)]+)", scope):
            if m.group(1) not in tables: continue
            for field in fields_in(resolve(m.group(2))):
                note(field, mapping.get(field, {}).get("label", "Value"), values=tables[m.group(1)])
        # An inline dict: {1: 'Foreground', 0: 'Background'}.get(state, …)
        for m in re.finditer(r"\{((?:\s*\d+\s*:\s*'[^']*'\s*,?)+)\}\s*\.get\(\s*([^,)]+)", scope):
            pairs = dict((int(k), v) for k, v in re.findall(r"(\d+)\s*:\s*'([^']*)'", m.group(1)))
            for field in fields_in(resolve(m.group(2))):
                note(field, mapping.get(field, {}).get("label", "Value"), values=pairs)

        # A shared helper called with one of the module's value tables.
        for m in re.finditer(r"\b(_\w+)\(([^)]*)\)", body):
            helper, args = m.group(1), m.group(2)
            params, per_param = helper_tables.get(helper, ([], {}))
            for index, argument in enumerate(split_top(args)):
                argument = argument.strip()
                if argument not in tables or index >= len(params): continue
                for field in per_param.get(params[index], set()):
                    label = mapping.get(field, {}).get("label", "Value")
                    note(field, label if usable(label) else "Value", values=tables[argument])

        # A field whose only name is "Value" is really named by its artifact:
        # the lock-state stream's value is the lock state.
        for field, spec in mapping.items():
            if spec["label"].lower() in ("value", "status") and title:
                spec["label"] = title

        for name in names:
            entry = streams.setdefault(name, {"title": title or name, "fields": {}})
            if title and entry["title"] == name: entry["title"] = title
            for field, spec in mapping.items():
                current = entry["fields"].get(field)
                if current is None:
                    entry["fields"][field] = spec
                else:
                    if current.get("kind") == "unknown" and spec.get("kind") != "unknown":
                        current["kind"] = spec["kind"]
                    if "values" not in current and "values" in spec:
                        current["values"] = spec["values"]

streams = {k: v for k, v in streams.items() if v["fields"]}
json.dump(streams, open("biome_streams.json","w"), indent=1, sort_keys=True)
print("streams:", len(streams), "| fields:", sum(len(v["fields"]) for v in streams.values()),
      "| value tables:", sum(1 for v in streams.values() for f in v["fields"].values() if "values" in f))
