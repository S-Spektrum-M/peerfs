# Roadmap

What needs to be built for PeerFS, in order. See the [README](README.md) for the design and [`main.tex`](main.tex) for the formal control plane.

There is no kernel driver. On Linux the mount binding is a userspace FUSE daemon.

**Current milestone:** experimental Linux read-only v1 is implemented, locally
integration-tested, and verified across two real Tailscale machines. See
[docs/v1.md](docs/v1.md) for setup, trust assumptions, and runtime limits.
A production security audit, broader acceptance and load testing remain outstanding.
V1 uses system tailscaled, not tsnet, and synchronous authority authorization on
every request instead of pushed/cached grants.

## Components

| Component | Role |
|---|---|
| **core** | Shared library: path model, config schemas, plan types, pre-flight. |
| **authority** | Control plane server: holds the rules, compiles plans, runs pre-flight, admits devices, pushes grants to owners. |
| **peerfsd** | Node agent on every device. Has two roles: *exporter* (serves its own files) and *mounter* (mounts other nodes' exports). |
| **data plane** | Wire protocol between a mounter and an owner, plus caching and locking. |
| **peerfs-cli** | Device commands (`status`, `plan`, `mount`) and admin commands (rules, authenticated with the admin key). |
| **console** | Admin web UI over the authority. |
| **mobile** | iOS File Provider and Android `DocumentsProvider` mounters. |

## Decisions to make first

These block parts of the build. Each one should end up in the README, and in `main.tex` if it is formal.

1. **Consistency contract.** What happens on concurrent writes and when a lock holder drops. Blocks write support (Phase 4).
2. **Identity and permission mapping — decided for v1.** Enrolled Tailscale StableIDs; one non-root serving UID per exporter; its Unix permissions apply underneath grants. FUSE presents local UID/GID, 0444 files and 0555 directories.
3. **Overlapping exports — decided.** PF5 forbids equal/nested same-owner roots, comparing declared paths and owner-approved canonical roots. See README for unavailable/refused owner results.
4. **Live-mount behaviour — decided for v1.** Fail closed on owner/authority loss; online authorization on every request. Valid rule-text changes invalidate all sessions; recovery, restart and one-hour expiry require fresh admission/remount. The optional user-service helper reconciles default-root mounts; transparent lease renewal remains unimplemented.
5. **Exporter privileges — decided for v1.** Root is refused. Start directly as the dedicated account; per-export UID switching is deferred.
6. **Authority availability — accepted for v1.** No admission or further file requests while the single authority is down. This is intentionally stricter than admission-only availability.

## Phase 1: Core

Pure logic, no network.

- [x] Path type: component lists, component-wise `⪯`, normalization, explicit-device-home `~` expansion.
- [x] Strict parsers and validation for `node.yaml`, `topology.yaml`, `DISK-RULES.yaml`.
- [x] Pkl adapter via `pkl eval` → YAML (subprocess tested with a fake executable; real Pkl not installed in the bootstrap environment).
- [x] Plan compiler: rules + topology (or the default topology, flagged stale) → plan.
- [x] Pre-flight checks PF1, PF3, PF4 and PF5; fail-closed PF2 owner callback and local canonical-directory helper.
- [x] Deterministic property tests that mirror the theorems: grant faithfulness, unambiguous resolution, isolation.
- [x] Offline `peerfs plan` inspection CLI, examples, Catalyst profiles and sanitizer tests.

This is not mount admission or contained file serving. `--preview` is explicitly
lexical-only. See README for contracts, bootstrap toolchain deviations and limits.
The first version is a single C++ project with separate core, CLI and test profiles.

**Done when:** the README's homelab / laptop / phone example compiles to the plans and views shown there, and every pre-flight error case has a test.

## Phase 2: Read-only MVP

One authority, exporters and Linux mounters, read-only.

**Authority**
- [x] Rules store with atomically persisted numbered versions.
- [x] Node identity from system tailscaled `WhoIs`, enrolled StableIDs and numeric tailnet IPv4 addresses.
- [ ] Proactive topology pull from devices (v1 receives topology with admission; stale fallback remains in the offline compiler).
- [x] Ask each owner to evaluate PF2 and collect its refusals and canonical root proofs.
- [x] Admission API: device-local topology in, freshly validated plan or refusal reasons out. No cached admission.

**Exporter (`peerfsd`)**
- [x] Pin owner-local ceilings; evaluate PF2 and securely pin approved roots when asked by the authority.
- [x] Contained serving via `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)` and pinned handles. Special files rejected before read-open.
- [ ] Per-export UID switching (v1 refuses root and uses a dedicated, already-unprivileged process).

**Data plane**
- [x] Read-only protocol over Tailscale TCP: bounded `PFS1`-framed JSON RPC for `stat`, `readdir`, `open`, `read`.
- [x] Explicit no-cache v1 policy: zero attribute/entry timeouts, direct I/O for prompt request-level revocation. Performance caching is deferred.

**Mounter (`peerfsd`)**
- [x] Load device-local topology and require fresh online admission; fail closed while authority is unreachable.
- [x] Read-only FUSE mount at its plan target, one selected export per foreground process.
- [x] Optional systemd-user helper discovers granted default-root exports, manages instances, and recovers invalid sessions. Explicit 45-minute remounts interrupt open descriptors; this is not transparent renewal.

**CLI**
- [ ] Complete device-command surface: v1 has offline `plan`, live `status`, `admit`, `mount`, `authority`, `export`; unmount uses `fusermount3 -u`.

**Done when:** the README example runs on three real machines, and symlink-escape tests fail closed.

## Phase 3: Revocation and live behaviour

Closes the gap described in `main.tex` ("Revocation of live mounts").

- [ ] Authority pushes the current grants (with rule version) to each owner whenever the rules change.
- [ ] Owners verify that pushes come from the authority.
- [x] Owners check the grant on every request (v1 asks the authenticated authority synchronously; no grant cache).
- [x] V1 returns errors on later operations after revocation, owner/authority loss or invalidated sessions, including reads on open files. An optional user-service helper performs fresh admission/remounts on its minute-scale poll.
- [ ] Re-plan and notify live mounters when the rules or their topology change.

**Done when:** after a grant is lowered, no request exceeds the new grant once the owner has received the push. Covered by an integration test.

## Phase 4: Writes

Needs decision 1 (consistency contract).

- [ ] Write operations: `write`, `create`, `mkdir`, `rename`, `unlink`, `setattr`, `fsync`.
- [ ] Locking or leases, according to the chosen contract. Suggested order: read-only plus single writer per export first, then leased locks.
- [ ] Cache invalidation that matches the contract.
- [ ] Mount `rw` entries read-write; the owner still enforces the mode on every request.
- [ ] Formalize the data plane in `main.tex`.

**Done when:** the consistency contract holds under concurrent writers and peers dropping mid-write, in the test harness.

## Phase 5: Admin surface

- [ ] Admin key authentication on the authority.
- [ ] `peerfs-cli` admin commands: edit, validate and apply rules; show plans per device.
- [ ] Console web UI: rules, devices, plans, pre-flight errors, ceiling refusals.
- [ ] Access-control primitives: groups and `extends`, expanded to nodes before compiling.

## Phase 6: Mobile

- [ ] iOS File Provider extension (`NSFileProviderReplicatedExtension`).
- [ ] Android `DocumentsProvider`.

Both are mounter implementations: same admission flow, same data plane.

## Ongoing

- [ ] Integration harness: several nodes in containers on a test tailnet (Headscale). Adversarial cases: symlink and hard-link escapes, revocation while mounted, authority loss mid-session.
- [ ] Packaging: systemd units, FUSE dependency, `/etc/peerfs` layout, logging.

## Later

- Opt-in sync for selected directories via LZFS.
