# HDWatcher

A macOS app that watches filesystem activity across every mounted volume, infers
file transfers between disks, and writes everything to an encrypted,
tamper-evident log locked behind the Secure Enclave and a password.

**Bundle identifier:** `co.pixelworship.hdwatcher`

---

## Build

Two ways, same code:

**Xcode** — open `HDWatcher.xcodeproj`. Signing is preconfigured for the
Pixel Worship team (`BM46YKWLTV`) under Signing & Capabilities. The project is
generated from `project.yml`; after adding or removing files run:

```bash
xcodegen generate
```

**Command line**

```bash
./build-app.sh
```

That compiles the package, generates the icon, assembles `build/HDWatcher.app`
and ad-hoc signs it. Then:

```bash
open build/HDWatcher.app
```

Options:

| Flag | Effect |
|------|--------|
| `--debug` | Debug build instead of release |
| `--sign "Developer ID Application: …"` | Override the signing identity |
| `--install` | Copy the result into `/Applications` |

### Signing

The Pixel Worship team is **`BM46YKWLTV`**. Its certificate is named after the
person rather than the company — `Apple Development: Matthew Mourlam
(2QHZSWALA4)` — while the certificate named `matt@pixelworship.co` belongs to a
*separate personal team* (`S8WVYZX5QM`). Picking the one that looks right by
name selects the wrong team, so both the Xcode project and `build-app.sh` pin
`BM46YKWLTV` explicitly.

`build-app.sh` prefers a Developer ID Application certificate for that team,
falls back to the Apple Development certificate, and finally to an ad-hoc
signature so the build always works on a machine without the certificates.

Only Apple Development certificates are currently installed. Those are fine for
running locally; distributing to other Macs needs a **Developer ID Application**
certificate from the Pixel Worship team, followed by notarisation.

Re-signing does not invalidate an existing vault: the Secure Enclave blob is
bound to the machine, not to the code signature. Changing the signature *does*
reset TCC, so Full Disk Access has to be granted again after switching identity.

### Full Disk Access

Grant it under **System Settings → Privacy & Security → Full Disk Access**, then
relaunch. Without it the app runs, but macOS hides protected locations (Mail,
Messages, other apps' containers) from the watcher. The Dashboard shows a banner
and Settings → Monitoring has a coverage probe listing exactly which directories
are currently visible.

---

## Always-on recording (privileged daemon)

**Install it permanently.** Settings → Background → *Install Permanently* asks
for an administrator password once and then the daemon is launchd's
responsibility: binary at `/usr/local/libexec/hdwatcherd`, plist in
`/Library/LaunchDaemons`, `RunAtLoad` and `KeepAlive`. It starts at every boot,
before anyone logs in, and survives rebuilding the app and updating macOS.

The `SMAppService` route the app offers first is the sanctioned one, but its
registration is tied to the app's code signature and to an approval in Login
Items: rebuild the app and the signature changes, update macOS and the approval
can be withdrawn. Either way the daemon quietly stops starting at boot — the one
thing it exists for — and the only sign is that nothing is being recorded. The
same installer is in the repository as `Scripts/install-daemon.sh`; the app runs
that exact file, shipped inside its own bundle so the path never moves, and
`--uninstall` removes it.

A LaunchDaemon (`hdwatcherd`) ships inside the app bundle and is registered with
`SMAppService` from **Settings → Background**. macOS requires an administrator to
approve it, and will only run it out of `/Applications`.

Running with privileges buys three things a per-user agent cannot have:

- **It records from boot**, before anyone logs in.
- **Its log lives in `/Library`, owned by root.** The logged-in user cannot
  delete or rewrite their own audit trail — which is the point of an audit trail.
- **It can inspect every process**, including root-owned daemons. This is what
  makes attribution work for things like `securityd`; an unprivileged agent is
  refused by the kernel and can only ever name same-user processes.

### How it records a log it cannot read

The daemon starts with no user present, so it cannot hold the vault key. Giving
it one would mean anything running as root could decrypt your entire history.
Instead the log key pair is split:

```
master key ──HKDF──► ingest private key   (app only, needs your password)
                          │
                          └──► ingest public key ──► ingest.pub  (daemon reads this)
```

Each segment the daemon writes gets fresh keys from an ephemeral ECDH against
that public key, with the ephemeral public half stored in the segment header. The
daemon can append events and **cannot read back a single one** — recovering them
needs the private key, which exists only while you have the vault unlocked. Its
manifest is sealed the same way.

Verified: a daemon-written segment contains no plaintext paths or contents, and a
store built from the public key alone returns nothing when asked to read.

### Who can touch the audit trail

Verified on a live install, as an ordinary (non-root) user:

| Attempt | Result |
|---------|--------|
| Modify a segment in place | denied |
| Truncate a segment | denied |
| Delete a segment | denied |
| Plant a forged segment | denied |
| Delete the log directory | denied |
| Write to any parent directory | denied |

Root owns the directory (`0755`) and every segment (`0644`). Deletion is governed
by write permission on the *directory*, not the file, so root ownership of the
directory is what actually protects the history.

Root itself cannot be locked out — nothing running on the machine can be. What
the daemon does instead is make interference impossible to hide: every 15
seconds it re-asserts ownership and permissions, and checks that no segment it
wrote has vanished or shrunk. Anything it finds is written **into the trail
itself** as a critical `Audit Trail Tampering` event and raises an alert. Growth
is normal and ignored; only shrinkage and disappearance are reported, and each
missing segment is reported once rather than every pass.

That covers the three ways history can be attacked:

- **Rewriting it** — the per-block hash chain fails verification.
- **Deleting it** — the manifest still lists the segment, and the guard notices
  it is gone.
- **Quietly opening the door first** — a widened permission or an ownership
  change is recorded and reverted.

What remains outside the app's reach: an attacker with root who stops the daemon
*before* acting (the log shows the gap, but not what happened during it), and
anything below the filesystem layer. Shipping the log off-machine is the honest
answer to both, and is not built.

### One chain per writer

Each writer keeps its own hash chain and numbers its own segments from 1, so
verification follows one *lineage* at a time — segment files are named
`<lineage>-<index>-<epoch>.hdwseg`. Chaining across lineages by index would
interleave two unrelated chains and make the first block of each fail its MAC,
reporting an intact log as altered. That is a false accusation of tampering,
which for a tool like this is a worse failure than missing something.

### Nothing readable on disk

The daemon has state of its own — where it reached in the event stream, and what
it has been told to watch. Left in the clear, that discloses which directories
are monitored and when the machine was active, which is exactly what an intruder
would want to know. So the daemon generates its **own Secure Enclave key** on
first run and publishes only the public half:

| File | Protection |
|------|-----------|
| `*.hdwseg`, `manifest*.enc` | Sealed to the ingest key |
| `agent-status.enc` | Sealed to the ingest key — the app reads it, the daemon cannot |
| `agent-config.enc` | Sealed to the daemon's enclave key — the app writes it, only the daemon reads it |
| `cursor.enc` | Sealed to the daemon's enclave key (app's own copy uses the vault key) |
| settings, rules, alerts, stats, captured contents | Sealed to the vault key |

What is left in the clear, and why:

- `ingest.pub`, `daemon.pub` — public keys. Publishing them is the point; they
  only permit *writing to* or *sealing for* their holder.
- `daemon.key` — the enclave-wrapped private half. Inert on any other machine
  and readable only by root.
- `vault.json` — salts, KDF parameters and wrapped key material, useless without
  the password.
- `agent.log` — the daemon's own diagnostics: start, stop, errors. No recorded
  activity, and it is the file you need when the daemon will not start.

### Key pinning

The daemon reads the public key the app published into your home — root can read
any file — and then pins a root-owned copy in `/Library`. Without that pin,
anyone able to write to your home could substitute their own public key and have
every subsequent event sealed to *them*. Once pinned, the daemon uses only its
own copy, reports the discrepancy, and keeps recording to the original key.

### What it costs

- **The app must live in `/Applications`.** macOS will not run root code from a
  user-writable location, and neither should you.
- **The daemon binary needs its own Full Disk Access entry**
  (`Contents/MacOS/hdwatcherd`); root does not bypass TCC for user data.
- **Content capture stays in the app**, since snapshotting file contents needs
  the master key.

While the daemon is recording, the app stops watching the filesystem itself and
tails the daemon's log instead, so nothing is counted twice.

## What it does

### Watches
FSEvents streams every create, modify, delete, rename and clone across the
volumes you select, with per-file granularity and inode data. New drives are
picked up as they mount; the watch set is rebuilt automatically.

### Infers transfers
FSEvents reports *that* a file appeared — never where it came from, and never
reads. HDWatcher correlates arrivals against departures and live files elsewhere,
and labels every finding with how strong the evidence is:

| Signal | Confidence |
|--------|-----------|
| Two rename events sharing one inode | **Certain** |
| Arrival matches a departure (same name + size, other volume) | **High** |
| Arrival's size + head/tail digest matches a live source | **High** |
| Spotlight finds a same-name, same-size file whose digest matches | **High** |
| Arrival matches a known file by name and size only | **Medium** |
| Arrival on removable media with no identifiable source | **Low** |

Copying a file *reads* the source, and FSEvents never reports reads — so a copy
from your disk to a USB stick would otherwise have no discoverable origin.
Spotlight already indexes the internal disk by name, so when no observed
candidate exists HDWatcher asks it, then confirms the match by size and content
digest. That is what turns "unidentified source" into a real path.

Transfers are framed from the machine's point of view: internal → external is
**Copied Out**, and defaults to Warning severity.

New arrivals are held for a short settle window first, because a Finder copy
lands as a create followed by a burst of writes — measuring it immediately would
read a zero-byte file.

### Alerts
A rule engine matching on event kind, path globs, file extension, volume class,
size, transfer confidence, burst thresholds and time-of-day windows. Ten rules
ship enabled by default, including data copied to external drives, credentials
leaving the machine, mass deletion, bulk copying and off-hours activity. Each has
a cooldown so one noisy operation cannot spam you, and burst rules are grouped
per-directory so a mass deletion in one folder doesn't mute the rule elsewhere.

### Hotspots
Directory heat with exponential time decay, rolled up to ancestors so a
squarified treemap can show where traffic concentrates. Drill into any directory;
rank by heat, event count, writes, deletes, transfers or bytes.

### Who did it — process attribution

macOS gives an ordinary app no supported way to learn which process changed a
file; that needs an Endpoint Security entitlement Apple issues case by case.
Three unprivileged sources get meaningfully far when combined:

| Source | What it gives | Limit |
|--------|---------------|-------|
| Open file descriptors (`libproc`) | The process holding the file *right now* | Same-user processes only; root daemons refuse |
| Rolling process table | Short-lived commands that already exited | Circumstantial — proximity in time |
| Unified log | Processes named alongside the path | Best effort; not always readable |

Every named process carries the evidence that implicated it — "Had the file
open", "Started moments before", "Named in the system log" — so nothing is
presented as more certain than it is. Alongside it: pid, user, executable,
bundle id, code-signing identity and team, start time and arguments.

Timing is the hard part. FSEvents coalesces with a latency, and a process can
close a file in that window. HDWatcher therefore runs a **second, near-zero
latency stream** over just the audited paths and attributes immediately, then
attaches the result when the event reaches the main pipeline.

Attribution is opt-in per rule (`Identify the responsible process`), because it
scans every reachable process. It ships enabled on the rules where "who?" is the
whole question: credentials touched, data copied off the machine, mass deletion,
application directory modified.

**What it cannot do:** name a root-owned daemon. A keychain rewrite is done by
`securityd` running as root, and the kernel will not show its descriptors to an
unprivileged process. The app says so explicitly rather than shrugging.

### Recovering deleted and changed files
HDWatcher keeps a copy of file contents in a single encrypted container
(`contents.hdw`), so you can review what changed and recover a file after it is
gone. The Recovery screen lists captured files, shows every stored version, and
diffs any two of them line by line; you can restore in place or save a copy.

**Every format is comparable.** The line-by-line diff was only ever available
for text, which is a small fraction of what a filesystem monitor captures. Any
two versions of anything can now be compared: images side by side, bytes as an
aligned hex diff with the changed columns picked out, and — for formats with
readable structure — a diff of that structure. Non-text versions also carry a
one-line summary (`131 KB → 131 KB · 240 bytes differ · first change at 0x1a40`),
computed in a single linear pass so it works on a video file.

**Four ways to read a binary.** *Records* decodes formats the app understands,
*Strings* pulls out readable fragments the way `strings(1)` does, *Full Text*
shows every byte as a text editor would (Latin-1, control bytes as `·`) so the
extraction cannot hide anything, and *Hex* is the ground truth underneath. Each
is diffable.

**Biome / SEGB record files.** Everything under `~/Library/Biome/streams` is a
segmented log of timestamped records wrapping protobuf payloads, and it used to
show up in Recovery as an unreadable blob. Both layouts are now parsed — v1 hides
its magic at the end of the file header with per-record headers, v2 leads with
the magic and keeps record metadata in a trailer — with CRCs verified per record
and the protobuf walked without a schema (field numbers and values are
recoverable; names are not). Reference-date doubles are rendered as dates. The
format follows [CCL Forensics' `ccl_segb`](https://github.com/cclgroupltd/ccl-segb),
against which the test fixtures are verified byte for byte.

**Field names for 89 streams.** The wire format carries field *numbers*, never
names, and Apple publishes no `.proto` files, so a decoded record reads
`6: "com.apple.mobilesafari"` — structurally correct and nearly useless. The
names, units and value meanings come from the Biome parsers in
[iLEAPP](https://github.com/abrignoni/iLEAPP) (MIT, Alexis Brignoni and
contributors), where they were established stream by stream by comparing many
devices against known activity. `Scripts/extract-biome-schema.py` reads a
checked-out iLEAPP tree and derives `BiomeSchemaTable.swift` from it: 89 streams,
364 named fields, 16 value tables. Records then read

```
In Focus (App.InFocus)
Bundle ID (6): "com.apple.mobilesafari"
Action (3): 1 · Foreground
Start Time (4): 2026-08-18 14:14:03
```

A known field also *suppresses* guessing: without a schema any number in the
plausible range is annotated as a date, and a schema saying "this is a lock
state" is better evidence than the value happening to look like a timestamp.
Extraction is deliberately conservative — a label is accepted only from a table
header, an explicit comment, or a variable in the artifact's own function, and a
value table is attached only to the exact field it interprets. A wrong name is
worse than no name.

**Open Records** opens the whole parsed file in a window of its own: every
record listed with timestamp, state and CRC result, searchable by content,
filterable to deleted or CRC-failed records, with each record's decoded fields,
hex and strings alongside. The parsed text can be saved or opened in a text
editor. The preview pane clips; this does not.

**Searching contents, not just names.** The Recovery search box has a
Names/Contents switch. Contents decrypts every captured version and reads it:
text files as text, record files as *parsed records* (so a timestamp or a
decoded field matches even though it appears nowhere in the raw bytes), and
everything else as bytes — scanned for both the plain and the UTF-16 spelling of
the query, since macOS stores a great deal of text as UTF-16 and a plain byte
search would never see it. Results stream in newest-first with the text around
each match, progress is shown, and it can be stopped. Versions that share bytes
are read once. There is deliberately no content index: a second copy of
everything would have to be encrypted, kept in step, and guarded as carefully as
the vault itself.

**Every format read the same way.** Whatever the file is, the preview opens on
a *Parsed* reading of it when one exists, and falls back to Strings / Full Text
/ Hex when it does not:

| Format | Read as |
|--------|---------|
| SQLite databases | tables, columns and rows — opened read-only and immutable from a private temp copy, since the vault holds the main file without its write-ahead log and SQLite would otherwise "recover" it by writing |
| Property lists (binary and XML) | the value tree, with plists nested inside plists opened in place |
| `NSKeyedArchiver` archives | the object graph, following `CF$UID` references back to what was archived rather than showing a table of fragments |
| SEGB / Biome | records, with field names (see above) |
| JSON | pretty-printed, keys sorted |
| gzip | inflated, then read as whatever it turns out to be |
| Protobuf blobs | the field tree, schema-less |
| Blob columns inside databases | plists and protobuf unpacked in place — an attributed message body is a plist in a BLOB |

That covers what iLEAPP's 384 modules actually open: databases and plists are
two thirds of it, the extensionless remainder is mostly Biome. The same reading
feeds everything — preview, the parsed window, content search (so a phrase in a
database row or a plist value is findable), and the ChatGPT prompt.

**Send to ChatGPT.** Recovery can say what a file is made of but not what it
means. This builds a question — path, metadata, detected format, and a bounded
slice of the decoded contents — and shows the whole thing before anything is
sent. It is the only place in the app where captured content leaves the machine,
so it is always confirmed, never automatic, and offers the clipboard as an
alternative.

Retention is yours to choose — never, 1 hour, 6 hours, **24 hours (default)**,
7 days, 30 days, or until you delete them. Shortening the window applies
immediately to what is already stored, not just to future captures.

**What can actually be recovered.** FSEvents reports a deletion only *after* the
file is gone, so its contents cannot be read at that moment. Contents are
therefore captured when a file is *written*, and what survives a deletion is the
most recent version captured while the file still existed. The app says this
plainly rather than implying full undelete.

Capture is deliberately bounded: files over the size cap (4 MB by default) are
skipped rather than stored partially, identical bytes are stored once and shared
between versions, repeated writes to one path are debounced, unchanged content is
skipped, and large or opaque formats (app bundles, video, archives) are excluded
by default. All of it is editable in Settings → Storage.

### Coverage

Two different questions, answered separately in Settings → Monitoring:

- **Disk coverage** — which mounted volumes are being recorded, which watch roots
  went to FSEvents, and whether anything is uncovered. A watch on `/` covers every
  volume mounted beneath it; nested volumes are deliberately not listed again,
  because watching a parent and a child reports every change twice (measured).
- **Protected-location spot check** — whether macOS is letting the app see into
  the folders it normally hides. This is about *permission*, not scope, and
  includes controls that are readable without Full Disk Access so a pass means
  something.

### Volumes
Mounted volumes with per-volume counters, capacity and mount history. macOS keeps
a dozen internal volumes mounted at all times — Data, Preboot, VM, Update,
cryptex images, simulator runtimes, devfs. Those are tracked for path
attribution but hidden behind a **System volumes** toggle, because they are not
what anyone means by "a volume".

The mount table is polled every three seconds rather than trusted to
notifications alone, so a drive pulled without ejecting still leaves the list.
Mount and unmount events are derived from a single diff of that table, which is
what stops one physical action producing two alerts.

### Responsiveness
Anything that decrypts, ranks or filters runs off the main thread and hands back
finished values: log queries, integrity verification, recovery grouping, version
previews and diffs, dashboard aggregation, and the live feed's own filtering.
Doing that work inside a SwiftUI `body` meant it re-ran on every redraw — with
tens of thousands of events and twenty thousand tracked directories, that is what
made switching tabs stall.

### Everything else
Live feed with filtering and an event inspector showing raw FSEvents flags;
forensic search across the whole encrypted history with CSV/JSON export; a
volumes screen with per-volume counters and mount history; and an integrity
screen that re-verifies the hash chain on demand.

---

## Security design

### Key hierarchy

```
                 ┌─────────────────────┐
  password ─────►│ PBKDF2-HMAC-SHA512  │──┐
                 │ (rounds calibrated) │  │
                 └─────────────────────┘  │
                                          ├──► HKDF ──► master key
       ┌──────────────────────────────┐   │              │
       │ Secure Enclave P-256 (ECDH)  │───┘              │
       │ private key never extractable│                  │
       └──────────────────────────────┘                  │
                                                         ▼
                              ┌──────────────┬───────────┴──────┐
                           log key      integrity key      settings key
                        (AES-256-GCM)     (HMAC chain)    (rules, stats)
```

Both inputs are required. The password alone is not enough, and neither is
physical possession of the machine — copying the vault to another Mac makes it
permanently unreadable, because the enclave half cannot be reproduced there.

Each purpose gets its own HKDF-derived subkey, so compromising one usage does not
hand over the others.

**On Secure Enclave keys:** keychain-resident enclave keys need a
`keychain-access-groups` entitlement backed by a real team identifier — an ad-hoc
signed build fails with `errSecMissingEntitlement`. HDWatcher instead uses
CryptoKit's `SecureEnclave.P256.KeyAgreement`, whose `dataRepresentation` is an
enclave-encrypted blob that is inert on any other machine. That keeps the app
buildable and hardware-bound without a paid signing identity. If no enclave is
present, the app degrades to password-only and says so plainly on the lock screen.

Optional Touch ID / device-password quick unlock stores a second copy of the
master key under an enclave key that requires user presence.

Failed unlocks back off exponentially after three attempts, up to a five-minute
ceiling.

### Log format

```
segment file:  [ 56-byte header ][ block ][ block ] …

block:         u32 length │ u32 index │ AES-256-GCM payload │ 32-byte chain MAC
payload:       LZFSE(JSON event batch), AAD = segment ID ‖ block index
chain MAC:     HMAC(integrity key, previous MAC ‖ index ‖ SHA-256(ciphertext))
```

The AAD binds each block to its position, so blocks cannot be reordered or moved
between segments. The MAC chain links each block to its predecessor, and each
segment's chain is seeded from the previous segment's final MAC — so removing a
whole file is detectable too. The manifest (itself encrypted) records expected
block counts, which catches truncation.

The Integrity screen recomputes all of it and reports per-segment results.

### The content container

Captured file contents live in one append-only encrypted file:

```
[ 64-byte header ][ sealed blob ][ sealed blob ] … [ sealed index ]
```

The header points at the most recent index, which holds all the accounting —
paths, versions, sizes, hashes and expiry. Each blob is sealed with its own
offset as additional authenticated data, so a stored version cannot be relocated
or swapped for another without detection. Nothing is ever overwritten in place:
a crash mid-write can at worst strand bytes, never corrupt the index the header
still names. Superseded regions are reclaimed by compaction.

### At rest

Everything in `~/Library/Application Support/co.pixelworship.hdwatcher/` is
encrypted except `vault.json`, which holds only salts, wrapped key material and
the enclave blob — all useless without the password. Directories are `0700`,
files `0600`. Locking the vault stops monitoring, flushes pending writes and
clears decrypted events from memory; auto-lock triggers on idle, sleep or screen
lock.

---

## Known limits

These are properties of the platform, not bugs:

- **No process attribution.** Nothing here can tell you *which app* copied a
  file. That requires an Endpoint Security entitlement, which Apple grants only
  to approved developers with a provisioning profile. Every transfer is therefore
  an inference, and the UI always shows its confidence.
- **No read visibility.** FSEvents does not report reads. A file copied *from*
  your disk is detected by its arrival elsewhere, not by observing the read.
- **FSEvents can drop.** Under extreme load the kernel coalesces and drops
  events; those arrive as a `Rescan Required` event naming the affected subtree
  rather than being silently lost.
- **Coverage over time is explicit.** The stream position is saved, so a restart
  replays what happened while nothing was watching, as far back as the system
  journal reaches. Every start and stop is written into the log as a marker
  naming the length of the gap — an audit trail with unexplained holes is worse
  than one that admits to them.
- **Spotlight has to have seen the source.** A copy of a file Spotlight has not
  indexed cannot have its origin identified, and is reported as leaving the
  machine with Low confidence and no source rather than being dropped.
- **Events are kept forever, by design.** There is no retention policy, no
  pruning and no delete: the event log is an append-only audit trail. The only
  cleanup offered is *archiving* a copy elsewhere, which removes nothing.
  Captured file *contents* are the separate, expiring thing. The Live Feed shows
  a rolling in-memory window and says so — Search reads the whole history.
- **Process attribution depends on privileges.** The app alone can name
  same-user processes; root-owned daemons refuse inspection. With the privileged
  daemon running, every process becomes inspectable. Neither can name the
  process behind a change after it has exited without trace — that would need an
  Endpoint Security entitlement.
- **Default filters hide system churn.** Caches, Spotlight, `node_modules` and
  similar are excluded so the log stays meaningful. Settings → Filters has the
  full editable list and a Raw Mode that logs everything.

---

## Layout

```
project.yml                  XcodeGen spec -> HDWatcher.xcodeproj
build-app.sh                 command-line build, bundle and sign
Sources/HDWatcherAgent/      hdwatcherd — the privileged recording daemon
Sources/HDWatcherCore/       engine, usable without the UI
  Crypto/                    vault, Secure Enclave binding, primitives
  Storage/                   segment format, writer, reader, event store,
                             encrypted content container
  Monitor/                   FSEvents, volume registry, normalizer, transfers,
                             Spotlight source lookup, process attribution
  Rules/                     rule model, evaluation engine, notifications
  Analytics/                 hotspot heat, activity statistics
  Service/                   engine wiring, settings, permissions
Sources/HDWatcher/           SwiftUI app
Tests/HDWatcherCoreTests/    unit + live filesystem integration tests
```

## Tests

```bash
swift test
```

306 tests, runnable with `swift test` or through the Xcode scheme. Unit tests cover the vault, log round-trips, tamper detection, rule
matching, burst and cooldown behaviour, hotspot rollup, filtering, the content
container (capture, dedup, retention, restore, compaction, encryption at rest)
the diff engine, and volume classification. Integration tests mount a real disk
image to prove cross-volume transfer detection, and spawn real processes to prove
attribution names the one holding a file open. The agent contract is covered
end to end: the app publishes a public key, a write-only store records with it,
and only the app can read the result back, including that a substituted ingest
key is refused. The integration
suite mounts a real disk image, copies files onto it and asserts that the
transfer is detected with the right direction and confidence, that the built-in
exfiltration rule fires, and that filenames never appear in cleartext inside the
segment files.
