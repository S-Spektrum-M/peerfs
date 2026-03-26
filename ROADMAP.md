# Roadmap

What needs to be built for PeerFS, in order. See the [README](README.md) for the design and [`main.tex`](main.tex) for the formal control plane.

There is no kernel driver. On Linux the mount binding is a userspace FUSE daemon.

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
2. **Identity and permission mapping.** How tailnet peers map to local Unix accounts and mount ownership.
3. **Overlapping exports — decided.** PF5 forbids equal/nested same-owner roots, comparing declared paths and owner-approved canonical roots.
4. **Live-mount behaviour.** Behaviour on owner/authority loss and live grant revocation.
5. **Exporter privileges.** Dedicated unprivileged account vs. per-export UID switching.
6. **Authority availability.** Behaviour when the single authority is unreachable.

## Phase 1: Core

Pure logic, no network.

- [x] Path type: component lists, component-wise `⪯`, normalization, explicit-device-home `~` expansion.
- [x] Strict parsers and validation for `node.yaml`, `topology.yaml`, `DISK-RULES.yaml`.
- [x] Pkl adapter via `pkl eval` → YAML.
- [x] Plan compiler: rules + topology (or the default topology, flagged stale) → plan.
- [x] Pre-flight checks PF1, PF3, PF4 and PF5; fail-closed PF2 owner callback and local canonical-directory helper.
- [x] Deterministic property tests that mirror the theorems: grant faithfulness, unambiguous resolution, isolation.
- [x] Offline `peerfs plan` inspection CLI, examples, Catalyst profiles and sanitizer tests.

**Done when:** the README's homelab / laptop / phone example compiles to the plans and views shown there, and every pre-flight error case has a test.

## Phase 2: Read-only MVP

One authority, exporters and Linux mounters, read-only.

- [ ] Rules store with atomically persisted numbered versions and tailnet peer identity.
- [ ] Owner PF2 evaluation and contained file serving via `openat2`.
- [ ] Read-only RPC data plane and Linux FUSE mounter requiring fresh admission.

## Phase 3: Revocation and live behaviour

- [ ] Enforce live grant revocation on mounted exports and handle session recovery.

## Phase 4: Writes

- [ ] Write operations, locking/leases matching the consistency contract, and data-plane formalization.

## Phase 5: Admin surface

- [ ] Admin key authentication, CLI admin commands, web console, and `groups` / `extends` primitives.

## Phase 6: Mobile

- [ ] iOS File Provider extension (`NSFileProviderReplicatedExtension`) and Android `DocumentsProvider`.
