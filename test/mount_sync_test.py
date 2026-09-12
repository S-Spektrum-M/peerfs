#!/usr/bin/env python3
"""Test mount reconciliation without modifying actual systemd units or mounts."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("mount_sync", Path(__file__).resolve().parents[1] / "scripts/sync_user_mounts.py")
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


@unittest.skipIf(os.getuid() == 0, "mount reconciliation intentionally refuses root")
class MountSyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.root = self.home / "mounts"
        self.root.mkdir(mode=0o700)
        self.state = self.home / "state"
        self.network = self.home / "network.json"
        self.network.write_text('{"self":"laptop"}')
        self.topology = self.home / "topology.yaml"
        self.topology.write_text("root: " + str(self.root))
        self.binary = self.home / "peerfs"
        self.binary.write_text("fake test binary")
        self.names = {"share", "notes"}
        self.enabled = set()
        self.active = set()
        self.unhealthy = set()
        self.version = 1
        self.calls = []
        self.offline = False
        self.refused = False
        self.bad_target = False
        self.wrong_device = False
        self.foreign = set()
        self.patcher = patch.object(SYNC, "command", self.command)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def command(self, arguments, timeout=35):
        arguments = list(map(str, arguments))
        self.calls.append(arguments)
        if arguments[0] == str(self.binary):
            if self.offline:
                raise RuntimeError("authority unavailable")
            if arguments[1] == "status":
                return json.dumps({"ok": True, "read_only": True, "version": self.version})
            if self.refused:
                raise RuntimeError("admission refused")
            return json.dumps({"admitted": True, "read_only": True, "version": self.version,
                               "device": "wrong" if self.wrong_device else "laptop", "session": "SECRET-TOKEN",
                               "entries": [{"export": name, "mode": "r", "target": str((self.home if self.bad_target else self.root) / name)} for name in sorted(self.names)]})
        if arguments[0] == "findmnt":
            name = Path(arguments[-1]).name
            if name in self.foreign:
                return "ext4\n"
            if name in self.active:
                return "fuse.peerfs\n"
            raise RuntimeError("not mounted")
        if arguments[0] == "stat":
            if Path(arguments[-1]).name in self.unhealthy:
                raise RuntimeError("permission revoked")
            return "directory\n"
        if arguments[:2] == ["systemctl", "--user"]:
            operation = arguments[2]
            if operation == "list-units":
                return "\n".join(f"peerfs-mount@{name}.service loaded active running PeerFS export" for name in sorted(self.active))
            name = SYNC.UNIT.fullmatch(arguments[-1])[1]
            if operation == "is-enabled":
                if name not in self.enabled:
                    raise RuntimeError("disabled")
            elif operation == "is-active":
                if name not in self.active:
                    raise RuntimeError("inactive")
            elif operation == "enable":
                self.enabled.add(name)
                self.active.add(name)
            elif operation == "disable":
                self.enabled.discard(name)
                self.active.discard(name)
            elif operation == "restart":
                self.active.add(name)
                self.unhealthy.discard(name)
            else:
                self.fail("unexpected systemctl operation: " + operation)
            return ""
        self.fail("unexpected command: " + repr(arguments))

    def synchronize(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            SYNC.synchronize(self.binary, self.network, self.topology, self.root, self.state)
        self.assertNotIn("SECRET-TOKEN", output.getvalue())

    def operations(self, name):
        return [call for call in self.calls if call[:3] == ["systemctl", "--user", name]]

    def test_discovers_all_grants_and_caches_no_credentials(self):
        self.synchronize()
        self.assertEqual(self.enabled, self.names)
        self.assertTrue(all((self.root / name).is_dir() for name in self.names))
        cache = (self.state / "cache.json").read_text()
        self.assertNotIn("SECRET-TOKEN", cache)
        self.assertEqual(json.loads(cache)["exports"], sorted(self.names))
        self.assertEqual((self.state.stat().st_mode & 0o777), 0o700)

    def test_healthy_unchanged_mounts_do_not_readmit_or_restart(self):
        self.synchronize()
        self.calls.clear()
        self.synchronize()
        self.assertFalse(self.operations("restart"))
        self.assertFalse(self.operations("enable"))
        self.assertFalse(any(call[:2] == [str(self.binary), "admit"] for call in self.calls))

    def test_rule_change_removes_revoked_mount_and_refreshes_retained(self):
        self.synchronize()
        self.calls.clear()
        self.version += 1
        self.names.remove("share")
        self.synchronize()
        self.assertEqual(self.enabled, {"notes"})
        self.assertEqual(self.operations("disable")[0][-1], "peerfs-mount@share.service")
        self.assertEqual(self.operations("restart")[0][-1], "peerfs-mount@notes.service")
        self.assertTrue((self.root / "share").exists(), "do not delete user directories")

    def test_authority_outage_leaves_existing_mounts_and_cache_untouched(self):
        self.synchronize()
        cache = (self.state / "cache.json").read_bytes()
        self.calls.clear()
        self.offline = True
        with self.assertRaises(RuntimeError):
            self.synchronize()
        self.assertEqual(self.active, self.names)
        self.assertEqual((self.state / "cache.json").read_bytes(), cache)
        self.assertFalse(self.operations("disable"))

    def test_refused_admission_does_not_install_cached_plan(self):
        self.synchronize()
        self.calls.clear()
        self.version += 1
        self.refused = True
        with self.assertRaises(RuntimeError):
            self.synchronize()
        self.assertFalse(self.operations("restart"))
        self.assertFalse(self.operations("disable"))

    def test_invalid_target_and_wrong_identity_are_refused(self):
        for field in ["bad_target", "wrong_device"]:
            setattr(self, field, True)
            with self.assertRaises(RuntimeError):
                self.synchronize()
            setattr(self, field, False)
        self.assertFalse(self.operations("enable"))

    def test_nonempty_or_symlink_target_is_not_overwritten(self):
        target = self.root / "share"
        target.mkdir()
        (target / "keep").write_text("user data")
        with self.assertRaises(RuntimeError):
            self.synchronize()
        self.assertEqual((target / "keep").read_text(), "user data")
        (target / "keep").unlink()
        target.rmdir()
        target.symlink_to(self.home, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            self.synchronize()
        self.assertFalse(self.operations("enable"))

    def test_foreign_mount_is_not_touched(self):
        self.foreign.add("share")
        with self.assertRaises(RuntimeError):
            self.synchronize()
        self.assertFalse(self.operations("enable"))
        self.assertFalse(self.operations("disable"))

    def test_revoked_root_lstat_does_not_prevent_managed_recovery(self):
        self.synchronize()
        self.calls.clear()
        self.unhealthy.add("share")
        with patch.object(SYNC.Path, "is_symlink", side_effect=PermissionError("revoked root")):
            self.synchronize()
        self.assertEqual(self.operations("restart")[0][-1], "peerfs-mount@share.service")

    def test_invalidated_session_triggers_fresh_admission_and_restart(self):
        self.synchronize()
        self.calls.clear()
        self.unhealthy.add("share")
        self.synchronize()
        self.assertTrue(any(call[:2] == [str(self.binary), "admit"] for call in self.calls))
        self.assertEqual(self.operations("restart")[0][-1], "peerfs-mount@share.service")


if __name__ == "__main__":
    unittest.main()
