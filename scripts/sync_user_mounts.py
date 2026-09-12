#!/usr/bin/env python3
"""Reconcile all granted default-root mounts with non-root systemd user services.

No cached plan is used to authorize a mount. Each peerfs mount process performs
its own admission. Only export names, a config digest and a rules version are
cached, never a session token. Failed admission leaves existing mounts alone.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
UNIT = re.compile(r"peerfs-mount@([A-Za-z0-9][A-Za-z0-9_.-]*)\.service\Z")
MAX_EXPORTS = 64


def command(arguments, timeout=35):
    try:
        result = subprocess.run(list(map(str, arguments)), capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"{arguments[0]} failed or timed out") from error
    if result.returncode:
        # Never include successful admission stdout: it contains a session token.
        raise RuntimeError(f"{arguments[0]} failed: {result.stderr.strip()[:500]}")
    return result.stdout


def unit_name(name):
    if not NAME.fullmatch(name):
        raise RuntimeError("invalid export name")
    return f"peerfs-mount@{name}.service"


def active(name):
    try:
        command(["systemctl", "--user", "is-active", "--quiet", unit_name(name)], timeout=5)
        return True
    except RuntimeError:
        return False


def filesystem_type(target):
    try:
        return command(["findmnt", "--nocanonicalize", "--noheadings", "--raw", "--output", "FSTYPE", "--mountpoint", target], timeout=5).strip()
    except RuntimeError:
        return ""


def healthy(name, root):
    if not active(name) or filesystem_type(root / name) != "fuse.peerfs":
        return False
    try:
        # A separate bounded process avoids blocking Python indefinitely on FUSE.
        command(["stat", "--format=%F", "--", root / name], timeout=12)
        return True
    except RuntimeError:
        return False


def save_cache(path, value):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".cache-", delete=False) as output:
            temporary = Path(output.name)
            json.dump(value, output)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def synchronize(binary, network, topology, root, state):
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        raise RuntimeError("run mount synchronization as the unprivileged mounter user")
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise RuntimeError("mount root must exist and have no symlink aliases")
    metadata = root.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022 or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("mount root must be owned by you and not group/other-writable")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = state.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise RuntimeError("mount state must be a private directory owned by you")
    with (state / "lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        status = json.loads(command([binary, "status", "--network", network]))
        version = status.get("version")
        if status.get("ok") is not True or status.get("read_only") is not True or type(version) is not int or version < 1:
            raise RuntimeError("invalid authority status")
        digest = hashlib.sha256(network.read_bytes() + b"\0" + topology.read_bytes() + b"\0" + binary.read_bytes()).hexdigest()
        cache_file = state / "cache.json"
        try:
            cache = json.loads(cache_file.read_text())
            cached_names = set(cache["exports"])
            if len(cached_names) > MAX_EXPORTS or any(not isinstance(name, str) or not NAME.fullmatch(name) for name in cached_names):
                raise ValueError("bad cache")
        except (OSError, ValueError, KeyError, TypeError):
            cache = {}
            cached_names = set()
        # list-unit-files reports the template, not enabled instances, on some
        # systemd versions. Discover loaded instances and confirm each explicitly.
        candidates = set(cached_names)
        listing = command(["systemctl", "--user", "list-units", "--all", "--plain", "--no-legend", "--no-pager", "peerfs-mount@*.service"], timeout=10)
        for line in listing.splitlines():
            columns = line.split()
            match = UNIT.fullmatch(columns[0]) if columns else None
            if match:
                candidates.add(match[1])
        managed = set()
        for name in candidates:
            try:
                command(["systemctl", "--user", "is-enabled", "--quiet", unit_name(name)], timeout=5)
                managed.add(name)
            except RuntimeError:
                pass
        health = {name: healthy(name, root) for name in cached_names}
        if cache.get("version") == version and cache.get("digest") == digest and managed == cached_names and all(health.values()):
            return

        admission = json.loads(command([binary, "admit", "--network", network, "--topology", topology, "--home", Path.home()]))
        enrollment = json.loads(network.read_text())
        entries = admission.get("entries")
        if admission.get("admitted") is not True or admission.get("read_only") is not True or admission.get("device") != enrollment["self"]:
            raise RuntimeError("fresh read-only admission required")
        if not isinstance(entries, list) or len(entries) > MAX_EXPORTS:
            raise RuntimeError("invalid admission entries")
        desired = set()
        for entry in entries:
            name = entry.get("export")
            if not isinstance(name, str) or not NAME.fullmatch(name) or name in desired or entry.get("mode") != "r":
                raise RuntimeError("invalid or duplicate read-only export")
            if entry.get("target") != str(root / name):
                raise RuntimeError("mount synchronization requires default placement under its configured root")
            desired.add(name)
        # Validate every target before changing any managed unit.
        for name in sorted(desired):
            target = root / name
            # Consult mountinfo first: stat/lstat of a revoked FUSE root is
            # expected to fail, and must not prevent replacing our managed mount.
            mounted = filesystem_type(target)
            if mounted and (mounted != "fuse.peerfs" or not active(name)):
                raise RuntimeError(f"refusing an unrelated existing mount: {target}")
            if not mounted:
                if target.is_symlink():
                    raise RuntimeError(f"refusing symlink target: {target}")
                target.mkdir(mode=0o700, exist_ok=True)
                metadata = target.lstat()
                if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o022 or any(target.iterdir()):
                    raise RuntimeError(f"refusing unsafe or nonempty target: {target}")
        changed = cache.get("version") != admission.get("version") or cache.get("digest") != digest
        for name in sorted((managed | cached_names) - desired):
            command(["systemctl", "--user", "disable", "--now", unit_name(name)])
        for name in sorted(desired):
            was_active = active(name)
            command(["systemctl", "--user", "enable", "--now", unit_name(name)])
            if was_active and (changed or not health.get(name, False)):
                command(["systemctl", "--user", "restart", unit_name(name)])
        save_cache(cache_file, {"version": admission["version"], "digest": digest, "exports": sorted(desired)})
        print("PeerFS mounts synchronized: " + (", ".join(sorted(desired)) or "none"))


def main():
    home = Path.home()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=home / ".local/bin/peerfs")
    parser.add_argument("--network", type=Path, default=home / ".config/peerfs/network.json")
    parser.add_argument("--topology", type=Path, default=home / ".config/peerfs/topology.yaml")
    parser.add_argument("--root", type=Path, default=Path("/mnt/peerfs"))
    parser.add_argument("--state", type=Path, default=home / ".local/state/peerfs-mounts")
    options = parser.parse_args()
    try:
        synchronize(options.binary, options.network, options.topology, options.root, options.state)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"PeerFS mount synchronization failed: {error}\n")


if __name__ == "__main__":
    main()
