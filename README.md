# PeerFS

A peer group is an overlay network — a tailnet. PeerFS mounts directories across a peer group's drives into a controlled local view on each device.

The central idea is the **mount tree**: it decouples *where* a file comes from on the network from *what* it is. Peers mount exports by logical name rather than by host, while file owners retain hard local boundaries over what they are willing to expose.

A **mount** is a binding of a peer's export into the local namespace with a defined consistency contract. On Linux desktops and servers, the binding is a userspace FUSE filesystem; on mobile, it is planned to map to the OS file-provider API.

> **Current status:** PeerFS implements the verified C++23 control-plane compiler alongside an **experimental Linux read-only v1** runtime over system Tailscale — including mutual `StableID` authentication, fresh plan admission, `openat2`-contained file serving, read-only FUSE mounts, and synchronous per-request revocation. It has passed integration and real two-machine Tailscale acceptance checks, though it is not yet production-audited and does not yet implement writes.
>
> - **[Linux v1 Guide (`docs/v1.md`)](docs/v1.md)** — live setup, Tailscale policy, service commands, and protocol limits
> - **[Formalization (`main.tex`)](main.tex)** — control-plane definitions, pre-flight invariants (`PF1`–`PF5`), and proofs
> - **[Roadmap (`ROADMAP.md`)](ROADMAP.md)** — completed milestones and remaining phases (writes, pushed leases, admin UI, mobile)

---

## How It Works

```text
DISK-RULES.yaml ─┐
node ceilings ───┼─▶ authority ─▶ mount plan per device ─▶ pre-flight (PF1–PF5)
mount topologies ┘
```

Consider a three-peer group on a tailnet:

```text
     [homelab]
     /       \
[laptop] — [phone]
```

Suppose `homelab` has two directories on disk (`/share` and `/home/user/share`) that it wants to share selectively with `laptop` and `phone`. PeerFS separates configuration across three roles so no single file mixes global policy with device-local layout or host-local safety:

- **Ceiling** (`node.yaml`, local to each exporter): the maximum filesystem subtrees a node is willing to export.
- **Group rules** (`DISK-RULES.yaml` or `.pkl`, central on the authority): named exports, their source paths, and per-device access grants.
- **Topology** (`topology.yaml`, local to each mounter): where granted exports should appear in that device's local namespace.

The **authority** compiles the group rules, owner ceilings, and mounter topologies into a per-device **mount plan** and runs pre-flight checks before admitting any mount.

### 1. Node ceiling (exporter)

Each exporting node declares the outer boundary of paths it is willing to serve. The default ceiling is empty: a node exports nothing until it explicitly lists paths.

```yaml
# /etc/peerfs/node.yaml on homelab (examples/node.yaml)
ceiling:
  - /share
  - /home/user/share
```

Every export must resolve inside its owner's ceiling. The owner enforces this itself rather than trusting the central authority: any export outside the ceiling (including via symlinks) is refused locally.

### 2. Group rules (central admin)

An administrator defines named exports across the group and grants devices `r` or `rw` access in `DISK-RULES.yaml`:

```yaml
# DISK-RULES.yaml on the authority (examples/DISK-RULES.yaml)
homelab:
  exports:
    - name: media
      path: /share
      grant: { laptop: rw, phone: r }
    - name: notes
      path: /home/user/share
      grant: { laptop: rw }
```

Export names are unique across the peer group.

<details>
<summary><strong>Authoring rules in Pkl (optional)</strong></summary>

YAML gets repetitive once rules span groups of peers. Trusted [Pkl](https://pkl-lang.org) modules (`.pkl`) can be used as an authoring layer that evaluates down to the exact same YAML schema via `pkl eval --format yaml`:

```pkl
class Export {
  name: String
  path: String(startsWith("/"))
  grant: Mapping<String, "r" | "rw">
}

local laptops = List("laptop", "work-laptop")

homelab {
  exports {
    new Export {
      name = "media"; path = "/share"
      grant { for (p in laptops) { [p] = "rw" }; ["phone"] = "r" }
    }
  }
}
```

</details>

### 3. Mount topology (mounter)

Each mounting device declares where its granted exports should appear locally. Any granted export not explicitly listed in `mounts` is placed under `<root>/<name>` (`/mnt/peerfs/<name>` by default).

```yaml
# /etc/peerfs/topology.yaml on laptop (examples/laptop.yaml)
root: /mnt/peerfs        # default
mounts:
  media: ~/Media
```

A topology can **only place** exports — it can never add ungranted exports or widen `r` to `rw`.

Nothing mounts without a freshly validated plan from the authority. Plans are never cached across admissions: if the authority is unreachable, the device waits rather than reusing an old plan that might hold revoked grants. (In offline compilation, if a device's topology is omitted, the compiler falls back to default placement under `/mnt/peerfs` and flags the resulting plan `stale: true` so it cannot be mistaken for an admissible plan.)

### 4. Compiled mount plan & resulting views

For `laptop`, the compiler produces:

```yaml
# mount plan: laptop
- export: media
  source: homelab:/share
  target: /home/alice/Media   # ~/Media expanded with laptop's explicit home
  mode: rw
- export: notes
  source: homelab:/home/user/share
  target: /mnt/peerfs/notes
  mode: rw
```

`source` is internal to the plan; applications on the device only interact with `target`:

| Device | Resulting local paths | Control-plane grant | Linux v1 runtime mode |
|---|---|---|---|
| **laptop** | `~/Media` (`media`), `/mnt/peerfs/notes` (`notes`) | `rw`, `rw` | `ro` (v1 is read-only) |
| **phone** | `/mnt/peerfs/media` (`media`, default topology) | `r` | `ro` |

### 5. Pre-flight invariants & failure isolation

Every compiled plan is checked against five pre-flight invariants (formalized in [`main.tex`](main.tex)) before admission:

- **`PF1` (Unique export names):** Every export granted to the device has a globally unique name across all rules, even if a conflicting duplicate is not granted to this device.
- **`PF2` (Owner ceiling containment):** Every granted export exists as a directory on its owner and its canonical path resolves within that owner's configured ceiling.
- **`PF3` (Placement-only topology):** The device's topology does not reference unknown exports or exports not granted to that device.
- **`PF4` (Disjoint mount targets):** Resolved local target paths (including defaults under `root`) neither collide nor nest inside one another.
- **`PF5` (Disjoint same-owner exports):** On any single owner, a granted export's root is neither equal to nor nested within another export on that same owner. Checks compare both normalized declared paths and (when both `PF2` owner checks succeed) canonical roots so symlink aliases cannot disguise an overlap. Refused exports have no canonical root and cannot appear in valid plans, though their declared paths still participate in `PF5`; different owners may freely export identical path strings.

**Failure isolation:** A failed check rejects only the affected device's plan. A broken topology on one mounter never affects another device's mounts, and an invalid export fails only devices granted an implicated export.

---

## Linux Read-Only v1 Architecture

On top of the pure control-plane library, PeerFS includes a live Linux runtime (`authority`, `exporter`, and FUSE `mounter`) operating over system Tailscale:

- **Authenticated peer identity:** Endpoints communicate over Tailscale IPv4 (`100.64.0.0/10`) and verify the actual TCP peer socket against the local `tailscaled` Unix-socket `WhoIs` API. Both `Node.StableID` and peer IP must match an explicit enrollment file (`network.json`). Hostnames and payload claims are never trusted, and no public listeners or proxies are used.
- **Fresh admission & synchronous revocation:** `peerfs authority` maintains atomically persisted, monotonically versioned rule snapshots and issues ephemeral (max 1-hour) device-bound sessions on admission. Although the control plane preserves `r`/`rw` modes, **v1 enforces read-only operations throughout**. Every `stat`, `readdir`, `open`, and `read` synchronously verifies the session and current grant with the authority, and FUSE mounts use `direct_io` with zero entry/attribute cache timeouts. Editing `DISK-RULES.yaml` bumps the rule version and revokes access on the very next operation — even on already-open file descriptors.
- **Race-safe filesystem containment:** `peerfs export` runs strictly as an unprivileged user (root is refused). It pins ceiling directories at startup, pins approved export roots during `PF2` verification, and opens all requested paths beneath those descriptors using Linux `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`). Absolute symlinks, `..` escapes, mount crossings, and special files (FIFOs, sockets, device nodes) are rejected.

See [`docs/v1.md`](docs/v1.md) for full operational details, protocol framing (`PFS1`), and `systemd` service/reconciler units.

---

## Quick Start

### Prerequisites (Linux)

- **Core build & test:** Catalyst 2.1.0+, Clang 21.1.8 (`clang++-21`), `llvm-ar-21`, `mold`, `pkg-config`, system `yaml-cpp` 0.9.0, and Python 3.
- **Live CLI & FUSE runtime:** Linux 5.6+ (`openat2`), `/proc`, `libfuse3-dev` + `fusermount3`, `libcurl` (`libcurl4-openssl-dev` or equivalent), `nlohmann-json3-dev`, and system `tailscaled` (for live deployment).
- **Optional:** `pkl` (to evaluate `.pkl` configs) and `pdflatex` (to build `main.tex`).

### Build and test

```sh
# Build static core library (build/common/libpeerfs.a) and CLI (build/common-cli/peerfs)
make build

# Run full verification suite: core unit/property tests, offline CLI, live TCP/FUSE, and mount sync
make check

# Run everything under AddressSanitizer + UndefinedBehaviorSanitizer
make sanitized-check
```

Individual Catalyst profiles and Make targets are also available:

```sh
catalyst build -p cli release      # Optimized release binary (build/common-cli-release/peerfs)
catalyst build -p live             # Static library with both core and live APIs
catalyst test -r                   # Core unit + 1,000 deterministic property tests
make live-check                    # Live authority/exporter/FUSE suite (mock LocalAPI over loopback)
make mount-sync-check              # Systemd user-mount reconciler tests
make docs                          # Compile main.tex -> main.pdf
```

### Offline plan inspection (`peerfs plan`)

You can compile and inspect the example configurations right away without Tailscale or `/share` directories on disk:

```sh
build/common-cli/peerfs plan \
  --rules examples/DISK-RULES.yaml --device laptop \
  --node homelab=examples/node.yaml --preview \
  --topology examples/laptop.yaml --home /home/alice

build/common-cli/peerfs plan \
  --rules examples/DISK-RULES.yaml --device phone \
  --node homelab=examples/node.yaml --preview \
  --topology examples/phone.yaml
```

- `--preview` runs **lexical-only** ceiling checks (`admission: false`, `validation: lexical-preview`); it cannot detect symlink aliases or authorize a mount.
- `--local-owner <owner>` replaces `--preview` on an exporting host to run real canonical filesystem checks against that owner's `node.yaml` (any remote owners fail `PF2` closed).
- `--home <path>` is required whenever a topology uses `~` — PeerFS never reads `$HOME` from the inspecting machine's environment.
- **Exit codes:** `0` valid inspection result, `1` pre-flight refusal (structured `PF1`–`PF5` reasons in YAML), `2` usage/input/Pkl error.

### Running live over Tailscale

Enroll your nodes' Tailscale IPv4 addresses (`100.64.0.0/10`) and `StableID`s in a `network.json` file (modeled on [`examples/network.json`](examples/network.json)), then run the foreground services:

```sh
# 1. On the authority node
peerfs authority --network /etc/peerfs/network.json \
  --rules /etc/peerfs/DISK-RULES.yaml --state ~/.local/state/peerfs-authority

# 2. On each exporting node (unprivileged account)
peerfs export --network /etc/peerfs/network.json --node /etc/peerfs/node.yaml

# 3. On a mounting node: check status, inspect live admission, and mount an export
peerfs status --network /etc/peerfs/network.json
peerfs admit  --network /etc/peerfs/network.json --topology /etc/peerfs/topology.yaml --home "$HOME"
peerfs mount  --network /etc/peerfs/network.json --topology /etc/peerfs/topology.yaml --home "$HOME" --export media

# Unmount when finished
fusermount3 -u "$HOME/Media"
```

Follow **[`docs/v1.md`](docs/v1.md)** for complete enrollment instructions, Tailscale ACL/WhoIs verification, mount-target ownership rules, and `systemd` user services.

---

## Repository Layout

| Path | Description |
|---|---|
| [`include/peerfs/core.hpp`](include/peerfs/core.hpp) | Pure control-plane C++23 API (`Path`, schemas, `compilePlan`, `checkLocalExport`) |
| [`include/peerfs/live.hpp`](include/peerfs/live.hpp) | Live Linux v1 service and client APIs (`serveAuthority`, `serveExporter`, `mountExport`) |
| [`src/core/`](src/core/) | Lexical path model, strict YAML validation, Pkl adapter, plan compiler, `PF1`–`PF5` |
| [`src/live/`](src/live/) | `PFS1` TCP RPC, Tailscale `WhoIs` client, versioned authority, `openat2` exporter, FUSE mounter |
| [`src/cli/peerfs.cpp`](src/cli/peerfs.cpp) | `peerfs` CLI (`plan`, `authority`, `export`, `status`, `admit`, `mount`) |
| [`examples/`](examples/) | Sample `DISK-RULES.yaml`, `node.yaml`, `laptop.yaml`, `phone.yaml`, and `network.json` |
| [`packaging/systemd/`](packaging/systemd/) | System and per-user `systemd` service/timer templates |
| [`scripts/sync_user_mounts.py`](scripts/sync_user_mounts.py) | Optional `systemd --user` mount reconciler for default-root exports |
| [`test/`](test/) | C++ core/property tests, black-box CLI tests, live loopback/FUSE tests, reconciler tests |
| [`main.tex`](main.tex) | LaTeX control-plane formalization and proofs |
| [`docs/v1.md`](docs/v1.md) | Live Linux v1 setup, Tailscale policy, protocol limits, and service recipes |

---

## Library Contracts, Input Limits & Toolchain Notes

- **Pure plan compilation (`compilePlan`):** Performs no intrinsic filesystem or network I/O. Grant modes are copied verbatim; topologies only influence target paths. The `OwnerCheck` callback is invoked once per export per compilation (including ungranted exports required for `PF5`) and must return an owner-verified canonical path or refusal; an absent callback fails `PF2` closed.
- **Offline vs. live containment (`checkLocalExport`):** `checkLocalExport` resolves local export and ceiling directories at a point in time, rejecting missing/non-directory roots, symlink loops, and out-of-ceiling canonical paths (unresolvable ceiling entries grant nothing). It is an offline pre-flight helper, **not** a race-safe file server — live serving always uses `src/live/exporter.cpp` with pinned directory descriptors and `openat2`.
- **Strict input bounds:** Configuration inputs must be a single YAML document `<= 1 MiB` within a traversal budget of `20,000` value nodes and nesting depth `<= 32`. Unknown keys, duplicate map keys, merge keys, relative paths, and above-root `..` traversals are rejected; bounded non-cyclic aliases are permitted. Export, owner, and device identifiers match `[A-Za-z0-9][A-Za-z0-9_.-]*`. Duplicate export *names* are deferred to `PF1` rather than failing the YAML parser so unrelated device plans preserve failure isolation.
- **Pkl evaluation (`loadConfig`):** Invokes `pkl eval --format yaml` directly via `posix_spawnp` (no shell interpolation) with a 30-second timeout and 1 MiB output cap. Only evaluate trusted `.pkl` modules: the adapter inherits the current environment and relies on Pkl for import/resource policy.
- **Bootstrap toolchain exceptions:** The codebase follows Prescription C++ layout and naming conventions, with explicit bootstrap exceptions verified by [`scripts/verify-toolchain.sh`](scripts/verify-toolchain.sh):
  - Uses **libstdc++** rather than `libc++` to match the installed system `yaml-cpp 0.9.0` ABI without mixing C++ standard libraries.
  - Uses C++23 `std::expected<T, std::string>` (`pq::expected` is not integrated) and suppresses unknown-attribute warnings for Jocasta-style `[[doc::brief(...)]]` annotations while Jocasta extraction is unintegrated.
  - Uses `clang-format-22` / `clang-tidy-22` alongside `clang++-21` (21.1.8) in a single-repository Catalyst project; `catalyst.lock` records system dependencies without claiming a hermetic container image.

---

## Roadmap & Open Questions

See **[`ROADMAP.md`](ROADMAP.md)** for detailed phase tracking. Key open design areas before Phase 4+ include:

1. **Write consistency & locking contract:** Defining concurrent-write semantics (single writer per export vs. advisory/mandatory leased locks) and recovery behavior when a peer disconnects while holding a lock.
2. **Pushed grant leases & transparent renewal:** Replacing synchronous per-request authority checks and periodic remounts with authority-pushed versioned grants and seamless session renewal.
3. **Data representation & caching:** Safe client-side caching/invalidation aligned with the consistency contract, plus evaluating whole-file vs. diff/CoW transfers (and potential opt-in offline directory sync).
4. **Access-control ergonomics & mobile:** Group/`extends` primitives in `DISK-RULES`, an authenticated admin CLI/console, and iOS `NSFileProviderReplicatedExtension` / Android `DocumentsProvider` mounters.
