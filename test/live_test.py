#!/usr/bin/env python3
"""Real TCP + Linux openat2 tests with mock tailscaled; no tailnet mutation.

Requires a cli+integration binary. Production binaries reject loopback mode.
FUSE is exercised when this host permits mounting; a denial is reported as a skip.
"""
import concurrent.futures
import errno
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build/common-cli-integration/peerfs"
if len(sys.argv) > 1 and ("/" in sys.argv[1] or Path(sys.argv[1]).is_file()):
    BINARY = Path(sys.argv.pop(1)).resolve()
PRODUCTION = ROOT / "build/common-cli/peerfs"
IPS = {"control": "127.0.0.2", "homelab": "127.0.0.3", "laptop": "127.0.0.4", "phone": "127.0.0.5"}
IDS = {name: "node-" + name for name in IPS}


def free_port(ip):
    with socket.socket() as connection:
        connection.bind((ip, 0))
        return connection.getsockname()[1]


class LocalAPI(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 128


class WhoIs(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        address = query.get("addr", [""])[0].split(":")[0]
        identity = self.server.identities.get(address)
        if not self.path.startswith("/localapi/v0/whois?") or not identity:
            self.send_error(404)
            return
        wire = json.dumps({"Node": {"StableID": identity}}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(wire)))
        self.end_headers()
        self.wfile.write(wire)

    def log_message(self, *args):
        pass


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="peerfs-live-")
        self.root = Path(self.temporary.name)
        self.processes = []
        self.logs = []
        self.api = LocalAPI(str(self.root / "tailscaled.sock"), WhoIs)
        self.api.identities = {IPS[name]: IDS[name] for name in IPS}
        self.api_thread = threading.Thread(target=self.api.serve_forever, daemon=True)
        self.api_thread.start()
        self.addCleanup(self.cleanup)
        self.authority_port = free_port(IPS["control"])
        self.export_port = free_port(IPS["homelab"])
        self.configs = {}
        for name in IPS:
            path = self.root / (name + ".json")
            path.write_text(json.dumps({
                "self": name, "authority": "control", "authority_port": self.authority_port,
                "test_loopback": True, "tailscale_socket": str(self.root / "tailscaled.sock"),
                "peers": {peer: {"id": IDS[peer], "address": IPS[peer], "port": self.export_port} for peer in IPS},
            }))
            self.configs[name] = path
        self.share = self.root / "share"
        self.share.mkdir()
        (self.share / "hello.txt").write_bytes(b"hello from owner\n\x00\xff")
        (self.share / "big.bin").write_bytes(bytes(range(256)) * 1024)
        (self.share / "inside").symlink_to("hello.txt")
        self.outside = self.root / "outside"
        self.outside.mkdir()
        (self.outside / "secret").write_text("MUST NOT ESCAPE")
        (self.share / "escape").symlink_to(self.outside, target_is_directory=True)
        (self.share / "magic").symlink_to("/proc/self/environ")
        (self.share / "absolute-inside").symlink_to(self.share / "hello.txt")
        os.mkfifo(self.share / "fifo")
        self.node = self.root / "node.yaml"
        self.node.write_text(json.dumps({"ceiling": [str(self.share)]}))
        self.rules = self.root / "rules.yaml"
        self.rule_value = {"homelab": {"exports": [
            {"name": "media", "path": str(self.share), "grant": {"laptop": "rw", "phone": "r"}},
        ]}}
        self.write_rules()
        self.topology = self.root / "topology.yaml"
        self.target = self.root / "mount"
        self.target.mkdir(mode=0o700)
        self.topology.write_text(json.dumps({"mounts": {"media": str(self.target)}}))
        self.state = self.root / "state"
        self.authority = self.start("authority", "--network", self.configs["control"], "--rules", self.rules, "--state", self.state)
        self.exporter = self.start("export", "--network", self.configs["homelab"], "--node", self.node)
        self.wait_listen("control", self.authority_port, self.authority)
        self.wait_listen("homelab", self.export_port, self.exporter)

    def cleanup(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(self.processes):
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        self.api.shutdown()
        self.api.server_close()
        self.api_thread.join()
        for log in self.logs:
            log.close()
        self.temporary.cleanup()

    def write_rules(self):
        temporary = self.rules.with_suffix(".new")
        temporary.write_text(json.dumps(self.rule_value))
        temporary.replace(self.rules)

    def start(self, *args):
        log = open(self.root / f"process-{len(self.processes)}.log", "w+")
        self.logs.append(log)
        process = subprocess.Popen([str(BINARY), *map(str, args)], stdout=log, stderr=log, cwd=ROOT)
        self.processes.append(process)
        return process

    def wait_listen(self, name, port, process):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail("server exited: " + "\n".join(Path(log.name).read_text() for log in self.logs))
            try:
                with socket.create_connection((IPS[name], port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.05)
        self.fail("server failed to listen")

    def rpc(self, caller, server, body, control=False, wire=None):
        port = self.authority_port if control else self.export_port
        with socket.socket() as connection:
            connection.settimeout(35)
            connection.bind((IPS.get(caller, caller), 0))
            connection.connect((IPS[server], port))
            data = json.dumps(body).encode() if wire is None else wire
            connection.sendall(b"PFS1" + struct.pack("!I", len(data)) + data)
            def exact(size):
                result = b""
                while len(result) < size:
                    chunk = connection.recv(size - len(result))
                    if not chunk:
                        raise RuntimeError("unexpected EOF")
                    result += chunk
                return result
            self.assertEqual(exact(4), b"PFS1")
            size = struct.unpack("!I", exact(4))[0]
            self.assertLessEqual(size, 1024 * 1024)
            return json.loads(exact(size))

    def admit(self, caller="laptop", topology=None):
        response = self.rpc(caller, "control", {"op": "admit", "topology": topology or self.topology.read_text(), "home": ""}, control=True)
        self.assertTrue(response["ok"], response)
        self.assertTrue(response["admitted"], response)
        self.assertEqual(response["device"], caller)
        self.assertTrue(response["read_only"])
        self.assertEqual(response["entries"][0]["mode"], "r")
        return response

    def data(self, session, operation="read", path="hello.txt", caller="laptop", **kwargs):
        body = {"op": operation, "session": session, "export": "media", "path": path}
        if operation == "read":
            body.update(offset=0, size=65536)
        if operation == "readdir":
            body.update(offset=0)
        body.update(kwargs)
        return self.rpc(caller, "homelab", body)

    def test_admission_and_binary_reads(self):
        admitted = self.admit()
        session = admitted["session"]
        response = self.data(session)
        self.assertTrue(response["ok"], response)
        self.assertEqual(bytes.fromhex(response["data"]), b"hello from owner\n\x00\xff")
        self.assertEqual(bytes.fromhex(self.data(session, size=5, offset=6)["data"]), b"from ")
        self.assertEqual(self.data(session, offset=100000)["data"], "")
        self.assertEqual(bytes.fromhex(self.data(session, path="big.bin", size=65536, offset=65536)["data"]), bytes(range(256)) * 256)
        self.assertTrue(self.data(session, size=262144)["ok"])
        self.assertFalse(self.data(session, size=262145)["ok"])
        self.assertFalse(self.data(session, offset=-1)["ok"])
        self.assertTrue(self.data(session, operation="open")["ok"])
        self.assertEqual(self.data(session, operation="stat")["size"], len(b"hello from owner\n\x00\xff"))
        self.assertEqual(bytes.fromhex(self.data(session, path="inside")["data"]), b"hello from owner\n\x00\xff")
        phone_session = self.admit("phone")["session"]
        self.assertTrue(self.data(phone_session, caller="phone")["ok"])
        command = subprocess.run([str(BINARY), "admit", "--network", str(self.configs["laptop"]), "--topology", str(self.topology)], capture_output=True, text=True)
        self.assertEqual(command.returncode, 0, command.stderr)
        self.assertTrue(json.loads(command.stdout)["admitted"])
        status = subprocess.run([str(BINARY), "status", "--network", str(self.configs["laptop"])], capture_output=True, text=True)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout)["version"], admitted["version"])

    def test_escape_and_special_file_refusals(self):
        session = self.admit()["session"]
        for path in ["../outside/secret", "/etc/passwd", "escape/secret", "magic", "absolute-inside"]:
            response = self.data(session, path=path)
            self.assertFalse(response["ok"], (path, response))
            self.assertEqual(response["errno"], errno.EACCES, response)
        self.assertFalse(self.data(session, path="fifo")["ok"])
        self.assertFalse(self.data(session, operation="write")["ok"])
        self.assertFalse(self.data(session, operation="read", device="phone")["ok"])
        self.assertFalse(self.data(session, path="not-found")["ok"])

    def test_identity_session_binding_and_authority_only_verification(self):
        session = self.admit()["session"]
        self.assertFalse(self.data(session, caller="phone")["ok"], "stolen token must not substitute identity")
        self.assertFalse(self.data("made-up")["ok"])
        response = self.rpc("laptop", "homelab", {"op": "verify", "export": "media", "path": str(self.share)})
        self.assertEqual(response["errno"], errno.EACCES)
        response = self.rpc("laptop", "control", {"op": "authorize", "session": session, "export": "media", "device": "laptop"}, control=True)
        self.assertFalse(response["ok"])
        # A valid node response for the wrong enrolled address is still refused.
        self.api.identities[IPS["laptop"]] = IDS["phone"]
        response = self.data(session)
        self.assertFalse(response["ok"])
        self.api.identities[IPS["laptop"]] = IDS["laptop"]
        response = self.rpc("127.0.0.9", "control", {"op": "status"}, control=True)
        self.assertFalse(response["ok"])

    def test_live_revocation_and_version_persistence(self):
        admitted = self.admit()
        version = admitted["version"]
        session = admitted["session"]
        self.rule_value["homelab"]["exports"][0]["grant"].pop("laptop")
        self.write_rules()
        self.assertFalse(self.data(session)["ok"])
        response = self.rpc("laptop", "control", {"op": "admit", "topology": "{}", "home": ""}, control=True)
        self.assertTrue(response["admitted"])
        self.assertEqual(response["entries"], [])
        self.assertGreater(response["version"], version)
        self.authority.terminate()
        self.authority.wait(timeout=20)
        self.authority = self.start("authority", "--network", self.configs["control"], "--rules", self.rules, "--state", self.state)
        self.wait_listen("control", self.authority_port, self.authority)
        status = self.rpc("laptop", "control", {"op": "status"}, control=True)
        self.assertEqual(status["version"], response["version"])
        self.rule_value["homelab"]["exports"][0]["grant"]["laptop"] = "r"
        self.write_rules()
        new_session = self.admit()
        self.assertGreater(new_session["version"], status["version"])
        self.assertTrue(self.data(new_session["session"])["ok"])
        self.assertFalse(self.data(session)["ok"])

    def test_authority_loss_invalid_rules_and_owner_restart_fail_closed(self):
        session = self.admit()["session"]
        self.rules.write_text("invalid: [")
        self.assertFalse(self.data(session)["ok"])
        self.write_rules()
        self.assertTrue(self.data(session)["ok"])
        self.exporter.terminate()
        self.exporter.wait(timeout=20)
        self.exporter = self.start("export", "--network", self.configs["homelab"], "--node", self.node)
        self.wait_listen("homelab", self.export_port, self.exporter)
        self.assertFalse(self.data(session)["ok"], "lost pinned handles require fresh admission")
        session = self.admit()["session"]
        self.authority.terminate()
        self.authority.wait(timeout=20)
        self.assertFalse(self.data(session)["ok"], "authority outage must stop new reads")
        command = subprocess.run([str(BINARY), "admit", "--network", str(self.configs["laptop"]), "--topology", str(self.topology)], capture_output=True, text=True)
        self.assertNotEqual(command.returncode, 0)

    def test_pf_checks_and_root_pinning(self):
        bad = self.rpc("laptop", "control", {"op": "admit", "topology": "mounts: {unknown: /bad}", "home": ""}, control=True)
        self.assertFalse(bad["admitted"])
        self.assertIn("PF3", [issue["check"] for issue in bad["issues"]])
        session = self.admit()["session"]
        old_root = self.root / "old-share"
        self.share.rename(old_root)
        self.share.symlink_to(self.outside, target_is_directory=True)
        # A changed pathname cannot redirect a previously pinned directory handle.
        self.assertEqual(bytes.fromhex(self.data(session)["data"]), b"hello from owner\n\x00\xff")
        bad = self.rpc("laptop", "control", {"op": "admit", "topology": self.topology.read_text(), "home": ""}, control=True)
        self.assertFalse(bad["admitted"])
        self.assertIn("PF2", [issue["check"] for issue in bad["issues"]])

    def test_directory_paging_concurrent_reads_and_admission(self):
        for index in range(300):
            (self.share / f"file-{index}").touch()
        session = self.admit()["session"]
        offset = 0
        names = []
        while True:
            response = self.data(session, operation="readdir", path="", offset=offset)
            self.assertTrue(response["ok"], response)
            names.extend(response["names"])
            offset = response["next"]
            if response["end"]:
                break
        self.assertIn("hello.txt", names)
        self.assertEqual(len([name for name in names if name.startswith("file-")]), 300)
        def task(index):
            if index % 3 == 0:
                return self.admit()["admitted"]
            response = self.data(session)
            self.assertTrue(response["ok"], response)
            return response["ok"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            self.assertTrue(all(pool.map(task, range(24))))

    def test_authority_and_exporter_can_share_a_node(self):
        self.authority.terminate()
        self.exporter.terminate()
        self.authority.wait(timeout=20)
        self.exporter.wait(timeout=20)
        for path in self.configs.values():
            config = json.loads(path.read_text())
            config["authority"] = "homelab"
            path.write_text(json.dumps(config))
        self.authority = self.start("authority", "--network", self.configs["homelab"], "--rules", self.rules, "--state", self.state)
        self.exporter = self.start("export", "--network", self.configs["homelab"], "--node", self.node)
        self.wait_listen("homelab", self.authority_port, self.authority)
        self.wait_listen("homelab", self.export_port, self.exporter)
        command = subprocess.run([str(BINARY), "admit", "--network", str(self.configs["laptop"]), "--topology", str(self.topology)], capture_output=True, text=True)
        self.assertEqual(command.returncode, 0, command.stderr)
        admitted = json.loads(command.stdout)
        self.assertTrue(admitted["admitted"], admitted)
        self.assertTrue(self.data(admitted["session"])["ok"])

    def test_unrelated_offline_owner_is_not_contacted(self):
        self.rule_value["phone"] = {"exports": [{"name": "unrelated", "path": "/not-serving", "grant": {"phone": "r"}}]}
        self.write_rules()
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((IPS["phone"], self.export_port))
            listener.listen()
            listener.settimeout(0.1)
            started = time.monotonic()
            self.admit("laptop")
            self.assertLess(time.monotonic() - started, 3)
            with self.assertRaises(socket.timeout):
                listener.accept()

    def test_canonical_aliases_are_rejected_by_live_pf5(self):
        alias = self.root / "alias"
        alias.symlink_to(self.share, target_is_directory=True)
        self.rule_value["homelab"]["exports"].append({"name": "alias", "path": str(alias), "grant": {"phone": "r"}})
        self.write_rules()
        response = self.rpc("laptop", "control", {"op": "admit", "topology": self.topology.read_text(), "home": ""}, control=True)
        self.assertTrue(response["ok"], response)
        self.assertFalse(response["admitted"])
        self.assertIn("PF5", [issue["check"] for issue in response["issues"]])

    def test_symlink_swap_race_never_returns_outside_bytes(self):
        session = self.admit()["session"]
        candidate = self.share / "race"
        candidate.symlink_to("hello.txt")
        stop = threading.Event()
        def swap():
            temporary = self.share / "race-replacement"
            while not stop.is_set():
                for destination in ["../outside/secret", "hello.txt"]:
                    temporary.symlink_to(destination)
                    temporary.replace(candidate)
        thread = threading.Thread(target=swap)
        thread.start()
        try:
            for _ in range(100):
                response = self.data(session, path="race")
                if response["ok"]:
                    self.assertEqual(bytes.fromhex(response["data"]), b"hello from owner\n\x00\xff")
        finally:
            stop.set()
            thread.join()

    def test_protocol_bounds_duplicate_keys_and_production_transport(self):
        duplicate = self.rpc("laptop", "control", {}, control=True, wire=b'{"op":"status","op":"admit"}')
        self.assertFalse(duplicate["ok"])
        nested = b'{"op":"status","x":' + b'[' * 40 + b'0' + b']' * 40 + b'}'
        self.assertFalse(self.rpc("laptop", "control", {}, control=True, wire=nested)["ok"])
        self.assertFalse(self.rpc("laptop", "control", {"op": "admit", "device": "phone", "topology": "{}", "home": ""}, control=True)["ok"])
        with socket.socket() as connection:
            connection.settimeout(10)
            connection.bind((IPS["laptop"], 0))
            connection.connect((IPS["control"], self.authority_port))
            connection.sendall(b"PFS1" + struct.pack("!I", 1024 * 1024 + 1))
            def exact(size):
                result = b""
                while len(result) < size:
                    chunk = connection.recv(size - len(result))
                    self.assertTrue(chunk, "unexpected EOF")
                    result += chunk
                return result
            self.assertEqual(exact(4), b"PFS1")
            size = struct.unpack("!I", exact(4))[0]
            response = json.loads(exact(size))
            self.assertFalse(response["ok"])
        if PRODUCTION.exists():
            command = subprocess.run([str(PRODUCTION), "admit", "--network", str(self.configs["laptop"]), "--topology", str(self.topology)], capture_output=True, text=True)
            self.assertNotEqual(command.returncode, 0)
            self.assertIn("loopback transport is disabled", command.stderr)

    def test_fuse_mount_read_and_revocation(self):
        if not shutil.which("fusermount3") or not Path("/dev/fuse").exists():
            self.skipTest("FUSE unavailable")
        mount = self.start("mount", "--network", self.configs["laptop"], "--topology", self.topology, "--export", "media")
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline and not os.path.ismount(self.target) and mount.poll() is None:
            time.sleep(0.05)
        if not os.path.ismount(self.target):
            output = Path(self.logs[-1].name).read_text()
            if "Operation not permitted" in output or "Permission denied" in output or "failed to open /dev/fuse" in output:
                self.skipTest("host denies FUSE mounts: " + output.strip())
            self.fail("FUSE mount failed: " + output)
        try:
            self.assertEqual((self.target / "hello.txt").read_bytes(), b"hello from owner\n\x00\xff")
            self.assertEqual((self.target / "big.bin").read_bytes(), bytes(range(256)) * 1024)
            self.assertIn("hello.txt", os.listdir(self.target))
            with self.assertRaises(OSError):
                (self.target / "escape" / "secret").read_bytes()
            with self.assertRaises(OSError):
                (self.target / "new-file").write_text("no writes")
            with open(self.target / "hello.txt", "rb", buffering=0) as opened:
                self.assertEqual(opened.read(5), b"hello")
                self.rule_value["homelab"]["exports"][0]["grant"].pop("laptop")
                self.write_rules()
                with self.assertRaises(OSError):
                    opened.read(5)
        finally:
            subprocess.run(["fusermount3", "-u", str(self.target)], check=True)
            mount.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
