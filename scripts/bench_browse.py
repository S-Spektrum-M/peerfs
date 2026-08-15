#!/usr/bin/env python3
"""File-browsing latency benchmark over a real FUSE mount (loopback, mock tailscaled).

Usage: bench_browse.py [BINARY] [--rtt-ms N] [--rounds N]

Mounter traffic to the exporter passes through a proxy that adds a simulated
tailnet round-trip time (default 17 ms, representative tailnet peer RTT). The proxy
binds the mounter's loopback address upstream, so exporter WhoIs identity is
unchanged. The authority and exporter talk directly, as when co-located.
Requires a cli+integration build; touches no real tailnet or deployed service.
"""
import argparse
import asyncio
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
IPS = {"control": "127.0.0.2", "homelab": "127.0.0.3", "laptop": "127.0.0.4"}
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
        self.server.calls += 1
        address = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("addr", [""])[0].split(":")[0]
        identity = self.server.identities.get(address)
        if not identity:
            self.send_error(404)
            return
        wire = json.dumps({"Node": {"StableID": identity}}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(wire)))
        self.end_headers()
        self.wfile.write(wire)

    def log_message(self, *args):
        pass


class LatencyProxy:
    """Delays every chunk by RTT/2 each way and each new connection by one RTT."""

    def __init__(self, listen, upstream, source, rtt):
        self.listen, self.upstream, self.source, self.half = listen, upstream, source, rtt / 2
        self.connections = 0
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        threading.Thread(target=self.run, daemon=True).start()
        self.ready.wait()

    def run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.start())
        self.ready.set()
        self.loop.run_forever()

    async def start(self):
        self.server = await asyncio.start_server(self.accept, *self.listen)

    async def pump(self, reader, writer):
        queue = asyncio.Queue()

        async def deliver():
            while True:
                due, chunk = await queue.get()
                if chunk is None:
                    break
                await asyncio.sleep(max(0, due - self.loop.time()))
                writer.write(chunk)
                await writer.drain()
            writer.close()

        task = asyncio.ensure_future(deliver())
        try:
            while chunk := await reader.read(1 << 20):
                queue.put_nowait((self.loop.time() + self.half, chunk))
        except ConnectionError:
            pass
        queue.put_nowait((0, None))
        await task

    async def accept(self, reader, writer):
        self.connections += 1
        await asyncio.sleep(self.half * 2)  # TCP handshake
        try:
            up_reader, up_writer = await asyncio.open_connection(*self.upstream, local_addr=(self.source, 0))
        except OSError:
            writer.close()
            return
        await asyncio.gather(self.pump(reader, up_writer), self.pump(up_reader, writer), return_exceptions=True)


def build_tree(share):
    flat = share / "flat"
    flat.mkdir()
    for index in range(200):
        (flat / f"file-{index:04}.txt").write_text(f"file {index}\n" * 8)
    tree = share / "tree"
    for branch in range(8):
        for leaf in range(4):
            directory = tree / f"b{branch}" / f"l{leaf}"
            directory.mkdir(parents=True)
            for index in range(12):
                (directory / f"n{index}.dat").write_bytes(os.urandom(256))
    (share / "big.bin").write_bytes(os.urandom(4 << 20))


def workloads(mount):
    def ls_l():
        with os.scandir(mount / "flat") as entries:
            for entry in entries:
                entry.stat(follow_symlinks=False)

    def walk():
        for directory, _, files in os.walk(mount / "tree"):
            for name in files:
                os.lstat(os.path.join(directory, name))

    def previews():
        for index in range(0, 200, 10):
            (mount / "flat" / f"file-{index:04}.txt").read_bytes()

    def big_read():
        with open(mount / "big.bin", "rb") as handle:
            while handle.read(1 << 20):
                pass

    return {"ls -l flat(200)": ls_l, "walk tree(32x12)": walk, "open+read 20 small": previews, "read 4MiB": big_read}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default=str(ROOT / "build/common-cli-integration/peerfs"))
    parser.add_argument("--rtt-ms", type=float, default=17.0)
    parser.add_argument("--rounds", type=int, default=3)
    options = parser.parse_args()
    temporary = tempfile.TemporaryDirectory(prefix="peerfs-bench-")
    root = Path(temporary.name)
    processes = []
    api = LocalAPI(str(root / "tailscaled.sock"), WhoIs)
    api.identities = {IPS[name]: IDS[name] for name in IPS}
    api.calls = 0
    threading.Thread(target=api.serve_forever, daemon=True).start()
    authority_port, export_port = free_port(IPS["control"]), free_port(IPS["homelab"])
    proxy_port = free_port(IPS["homelab"])
    configs = {}
    for name in IPS:
        port = proxy_port if name == "laptop" else export_port
        path = root / (name + ".json")
        path.write_text(json.dumps({
            "self": name, "authority": "control", "authority_port": authority_port, "test_loopback": True,
            "tailscale_socket": str(root / "tailscaled.sock"),
            "peers": {peer: {"id": IDS[peer], "address": IPS[peer], "port": port} for peer in IPS},
        }))
        configs[name] = path
    share = root / "share"
    share.mkdir()
    build_tree(share)
    (root / "node.yaml").write_text(json.dumps({"ceiling": [str(share)]}))
    (root / "rules.yaml").write_text(json.dumps({"homelab": {"exports": [
        {"name": "media", "path": str(share), "grant": {"laptop": "r"}}]}}))
    target = root / "mount"
    target.mkdir(mode=0o700)
    (root / "topology.yaml").write_text(json.dumps({"mounts": {"media": str(target)}}))
    log = open(root / "log", "w+")

    def start(*args):
        process = subprocess.Popen([options.binary, *map(str, args)], stdout=log, stderr=log)
        processes.append(process)
        return process

    proxy = LatencyProxy((IPS["homelab"], proxy_port), (IPS["homelab"], export_port), IPS["laptop"],
                         options.rtt_ms / 1000)
    try:
        start("authority", "--network", configs["control"], "--rules", root / "rules.yaml", "--state", root / "state")
        start("export", "--network", configs["homelab"], "--node", root / "node.yaml")
        for ip, port in ((IPS["control"], authority_port), (IPS["homelab"], export_port)):
            for _ in range(200):
                try:
                    socket.create_connection((ip, port), timeout=0.1).close()
                    break
                except OSError:
                    time.sleep(0.05)
        start("mount", "--network", configs["laptop"], "--topology", root / "topology.yaml", "--export", "media")
        deadline = time.monotonic() + 15
        while not os.path.ismount(target) and time.monotonic() < deadline:
            time.sleep(0.05)
        if not os.path.ismount(target):
            log.seek(0)
            sys.exit("mount failed:\n" + log.read())
        print(f"binary={options.binary} rtt={options.rtt_ms}ms rounds={options.rounds}")
        for name, function in workloads(target).items():
            times, whois, connections = [], api.calls, proxy.connections
            for _ in range(options.rounds):
                began = time.perf_counter()
                function()
                times.append(time.perf_counter() - began)
            whois = (api.calls - whois) / options.rounds
            connections = (proxy.connections - connections) / options.rounds
            print(f"  {name:22} median {statistics.median(times) * 1000:9.1f} ms   "
                  f"min {min(times) * 1000:9.1f} ms   conns/run {connections:6.0f}   whois/run {whois:6.0f}")
    finally:
        if os.path.ismount(target):
            subprocess.run(["fusermount3", "-u", str(target)], check=False)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        api.shutdown()
        temporary.cleanup()


if __name__ == "__main__":
    main()
