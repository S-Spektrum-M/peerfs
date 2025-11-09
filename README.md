# Peer FS

*Friday, November 7, 2025 — 10:49 AM*

A peer group is an overlay — a tailnet.

PeerFS is a way to mount the contents of a group's drives in a controlled view.

The point is the mount tree: it decouples *where* a file on the network comes from from *what* it is. Peers mount exports by name, not by host.

A **mount** is a binding of a peer's export into the local namespace with a defined consistency contract. On desktop the binding is FUSE. On mobile it's the OS's file-provider API.

## A simple example

```
     [homelab]
     /       \
[laptop] — [phone]
```

Say the homelab's fs is:

```
/
...
home/user/...
          share
...
share
```

`share` is not special. It's just a clarifying aid.

## How it works

```
DISK-RULES.yaml ─┐
node ceilings ───┼─▶ server ─▶ mount plan per device ─▶ pre-flight
mount topologies ┘
```

The server compiles the group rules, each node's ceiling, and each mounter's topology into a **mount plan** per device, then runs a pre-flight check on each plan.

Two files are local to a device, one per side:

- **Ceiling**: what a node is willing to *export*.
- **Topology**: where a mounter wants exports to *appear*.

### Node ceiling (exporter)

Each node declares the most it is willing to export. The default is empty: a node exports nothing until it lists paths.

```yaml
# /etc/peerfs/node.yaml on homelab
ceiling:
  - /share
  - /home/user/share
```

### Group rules (central, admin)

An admin configures `DISK-RULES.yaml` (or `.pkl`) through a console (or, later, `peerfs-cli` authenticated with the admin's key):

```yaml
homelab:
  exports:
    - name: media
      path: /share
      grant: { laptop: rw, phone: r }
    - name: notes
      path: /home/user/share
      grant: { laptop: rw }
```

Export names are unique across the group.

Every export must fall within the node's ceiling. The node enforces this itself rather than trusting the central config: an export outside the ceiling is refused and reported back to the console.

> **Note:** YAML gets repetitive once there are groups of peers. [Pkl](https://pkl-lang.org) is a candidate authoring layer that evaluates down to the same YAML:
>
> ```pkl
> class Export {
>   name: String
>   path: String(startsWith("/"))
>   grant: Mapping<String, "r" | "rw">
> }
>
> local laptops = List("laptop", "work-laptop")
>
> homelab {
>   exports {
>     new Export {
>       name = "media"; path = "/share"
>       grant { for (p in laptops) { [p] = "rw" }; ["phone"] = "r" }
>     }
>   }
> }
> ```

### Mount topology (mounter)

Each mounter declares where granted exports should appear. Any granted export it doesn't list goes under `root/<name>`.

```yaml
# /etc/peerfs/topology.yaml on laptop
root: /mnt/peerfs        # default
mounts:
  media: ~/Media
```

A topology can only place exports. It can't widen what a device was granted.

The topology is authored on the device. The server reaches out to consult it when compiling the plan. If the device is unreachable, that's fine: the server compiles the plan with default placement and sets an internal flag. When the device next mounts, it sends its topology and the server recompiles the plan and runs pre-flight on it.

Nothing mounts without a mount plan the server has validated. Plans are not cached: if the server is unreachable, the device waits. Otherwise a device could keep write access from an old plan after its grants changed, and staying off the server on purpose would become a way to hold on to revoked access.

### Mount plan (generated)

The server's output for laptop:

```yaml
# mount plan: laptop
- export: media
  source: homelab:/share
  target: ~/Media
  mode: rw
- export: notes
  source: homelab:/home/user/share
  target: /mnt/peerfs/notes
  mode: rw
```

`source` lives in the plan. The user only ever sees `target`.

### Pre-flight

Each plan is checked before it ships. A failed check is an error, and it only affects the device whose plan failed. Every other device's plan goes out as normal.

Errors:

- duplicate export names (fails every plan that includes either export)
- exports outside a node's ceiling (fails every plan that includes the export)
- topology entries for exports the device wasn't granted
- colliding or nested topology targets

## Resulting views

**laptop:**

```
~/Media              (rw)   ← media
/mnt/peerfs/notes    (rw)
```

**phone** (no topology, so defaults):

```
/mnt/peerfs/media    (r)
```

## Future Ideas

1. More primitives for access-control definition
   1. Groups
   2. Extends
2. Opt-in sync for selected dirs via LZFS (separate pet project, not started).

## Open Questions

1. What is the consistency contract? Contention model: write locks? Advisory or mandatory? Held by whom, and what happens when a peer drops while holding one?
2. CoW? Diffs? Binary?
3. Will enterprises actually want this? They're moving to cloud first anyway.
