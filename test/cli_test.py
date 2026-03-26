#!/usr/bin/env python3
"""Black-box CLI and trusted-Pkl adapter tests (standard library only)."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else ROOT / "build/common-cli/peerfs"


class CliTests(unittest.TestCase):
    def invoke(self, *args, code=0, env=None):
        result = subprocess.run(
            [str(BINARY), *map(str, args)], cwd=ROOT, env=env,
            text=True, capture_output=True, timeout=40,
        )
        self.assertEqual(result.returncode, code, (result.stdout, result.stderr))
        return result

    def example(self, *args, code=0):
        return self.invoke(
            "plan", "--rules", "examples/DISK-RULES.yaml",
            "--device", "laptop", "--node", "homelab=examples/node.yaml",
            *args, code=code,
        )

    def test_readme_preview(self):
        result = self.example("--preview", "--topology", "examples/laptop.yaml", "--home", "/home/alice")
        self.assertIn("admission: false", result.stdout)
        self.assertIn("validation: lexical-preview", result.stdout)
        self.assertIn("valid: true", result.stdout)
        self.assertIn("stale: false", result.stdout)
        self.assertIn("/home/alice/Media", result.stdout)
        self.assertIn("/mnt/peerfs/notes", result.stdout)

    def test_stale_and_fail_closed(self):
        self.assertIn("stale: true", self.example("--preview").stdout)
        result = self.example(code=1)
        self.assertIn("PF2", result.stdout)
        self.assertIn("remote PF2 verification is unavailable", result.stdout)

    def test_usage_and_input_errors(self):
        self.invoke(code=2)
        self.invoke("mount", code=2)
        self.invoke("--help")
        self.invoke("plan", "--unknown", code=2)
        self.invoke("plan", "--rules", code=2)
        self.invoke("plan", "--rules", "missing", "--device", "x", code=2)
        self.example("--preview", "--preview", code=2)
        self.example("--preview", "--local-owner", "homelab", code=2)
        self.example("--device", "another", code=2)
        self.example("--node", "homelab=examples/node.yaml", code=2)
        self.example("--node", "invalid", code=2)
        self.example("--preview", "--topology", "examples/laptop.yaml", code=2)

    def test_local_owner_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            share = root / "share"
            share.mkdir()
            outside = root / "outside"
            outside.mkdir()
            export = share / "data"
            export.mkdir()
            (share / "escape").symlink_to(outside, target_is_directory=True)
            node = root / "node.yaml"
            node.write_text(json.dumps({"ceiling": [str(share)]}))
            rules = root / "rules.yaml"
            rules.write_text(json.dumps({"homelab": {"exports": [
                {"name": "data", "path": str(export), "grant": {"laptop": "r"}}
            ]}}))
            topology = root / "topology.yaml"
            topology.write_text("{}")
            args = ["plan", "--rules", rules, "--device", "laptop", "--topology", topology,
                    "--node", f"homelab={node}", "--local-owner", "homelab"]
            self.assertIn("valid: true", self.invoke(*args).stdout)
            rules.write_text(rules.read_text().replace(str(export), str(share / "escape")))
            self.assertIn("PF2", self.invoke(*args, code=1).stdout)
            # Explicit preview is lexical-only; this distinction must remain visible.
            preview_args = args[:-2] + ["--preview"]
            self.assertIn("validation: lexical-preview", self.invoke(*preview_args).stdout)

    def test_all_pf_refusals_are_inspectable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule_file = root / "rules.yaml"
            topology_file = root / "topology.yaml"
            rule_file.write_text(json.dumps({"homelab": {"exports": [
                {"name": "media", "path": "/share", "grant": {"laptop": "r"}},
                {"name": "media", "path": "/share/inside", "grant": {"laptop": "rw"}}
            ]}}))
            topology_file.write_text("mounts: {not-granted: /elsewhere}")
            result = self.invoke("plan", "--rules", rule_file, "--device", "laptop", "--preview",
                                 "--node", "homelab=examples/node.yaml", "--topology", topology_file, code=1)
            for check in ["PF1", "PF3", "PF4", "PF5"]:
                self.assertIn(check, result.stdout)

    def test_pkl_adapter_arguments_and_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "pkl"
            log = root / "arguments.json"
            env = dict(os.environ, PATH=str(root), PKL_TEST_LOG=str(log))
            # Invoke Python by absolute path because PATH intentionally contains no real pkl.
            executable.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "open(os.environ['PKL_TEST_LOG'], 'w').write(json.dumps(sys.argv[1:]))\n"
                "print('homelab: {exports: []}')\n"
            )
            executable.chmod(0o755)
            filename = root / "rules; touch INJECTION.pkl"
            filename.write_text("trusted test module")
            result = self.invoke("plan", "--rules", filename, "--device", "laptop", env=env)
            self.assertIn("valid: true", result.stdout)
            self.assertEqual(json.loads(log.read_text()), ["eval", "--format", "yaml", str(filename)])
            self.assertFalse((ROOT / "INJECTION.pkl").exists())
            executable.write_text(f"#!{sys.executable}\nraise SystemExit(7)\n")
            result = self.invoke("plan", "--rules", filename, "--device", "laptop", env=env, code=2)
            self.assertIn("pkl evaluation failed", result.stderr)
            executable.write_text(f"#!{sys.executable}\nprint('x' * (1024 * 1024 + 1))\n")
            self.assertIn("exceeds 1 MiB", self.invoke(
                "plan", "--rules", filename, "--device", "laptop", env=env, code=2).stderr)
            executable.unlink()
            self.assertIn("cannot execute pkl", self.invoke(
                "plan", "--rules", filename, "--device", "laptop", env=env, code=2).stderr)

    def test_pkl_timeout_after_stdout_closes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "pkl"
            executable.write_text(
                f"#!{sys.executable}\nimport os, time\nos.close(1)\ntime.sleep(60)\n"
            )
            executable.chmod(0o755)
            env = dict(os.environ, PATH=str(root))
            result = self.invoke("plan", "--rules", root / "rules.pkl", "--device", "x", env=env, code=2)
            self.assertIn("timed out", result.stderr)

    def test_bad_yaml_and_oversized_input(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "bad.yaml"
            filename.write_text("node: {exports: [{name: bad, path: /a, grant: {x: root}}]}")
            self.invoke("plan", "--rules", filename, "--device", "x", code=2)
            filename.write_text(" " * (1024 * 1024 + 1))
            self.invoke("plan", "--rules", filename, "--device", "x", code=2)


if __name__ == "__main__":
    unittest.main()
