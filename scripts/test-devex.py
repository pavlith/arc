#!/usr/bin/env python3
"""Regression checks for verification routing, setup drift and safe profile installation."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def run(*args, cwd=ROOT, env=None):
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=30)


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        for directory in ("scripts", "client/node_modules", "bin"):
            (self.repo / directory).mkdir(parents=True)
        shutil.copy(ROOT / "scripts/verify-changed.sh", self.repo / "scripts")
        for script in ("check-agent-setup.py", "check-doc-links.py", "test-devex.py"):
            (self.repo / "scripts" / script).write_text("pass\n")
        self.log = self.repo / "commands"
        self.env = dict(os.environ, PATH=f"{self.repo / 'bin'}:{os.environ['PATH']}",
                        ARC_TEST_COMMANDS=str(self.log), GIT_CONFIG_NOSYSTEM="1")
        for tool in ("go", "npm"):
            path = self.repo / "bin" / tool
            path.write_text(f'#!/bin/sh\nprintf "%s\\n" "{tool} $*" >> "$ARC_TEST_COMMANDS"\n')
            path.chmod(0o755)
        self.git("init", "-q", "-b", "main")
        self.git("add", "scripts")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "Fixture baseline")

    def git(self, *args):
        result = run("git", *args, cwd=self.repo, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def change(self, path, text="fixture\n"):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def verify(self, base="HEAD"):
        result = run("bash", "scripts/verify-changed.sh", "--base", base,
                     cwd=self.repo, env=self.env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return self.log.read_text() if self.log.exists() else ""

    def test_docs_do_not_run_language_checks(self):
        self.change("client/web/README.md")
        self.change("services/task/README.md")
        self.assertEqual(self.verify(), "")

    def test_contract_only_change_checks_generated_client_and_ui(self):
        self.change("services/files/api/v1/contract/schemas/file.json", "{}\n")
        calls = self.verify()
        self.assertIn("check --workspace @arc/client", calls)
        self.assertIn("check --workspace ui", calls)
        self.assertIn("test:unit --workspace ui", calls)
        self.assertNotIn("go test", calls)

    def test_ui_change_runs_unit_check_and_build(self):
        self.change("client/web/src/routes/+page.svelte")
        calls = self.verify()
        for command in ("check", "test:unit", "build"):
            self.assertIn(f"{command} --workspace ui", calls)

    def test_local_service_and_shared_go_scopes(self):
        self.change("services/task/service.go", "package task\n")
        self.assertIn("go test ./services/task/...", self.verify())
        self.log.unlink()
        self.change("sdk/client/client.go", "package client\n")
        self.assertIn("go test ./...", self.verify())

    def test_staged_and_committed_changes_are_included(self):
        base = self.git("rev-parse", "HEAD")
        self.change("client/ts/src/index.ts")
        self.git("add", "client/ts")
        self.assertIn("check --workspace @arc/client", self.verify())
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "Fixture contract change")
        self.log.unlink()
        self.assertIn("check --workspace @arc/client", self.verify(base))

    def test_deleted_contract_still_checks_client(self):
        path = "services/task/api/v1/contract/schemas/removed.json"
        self.change(path, "{}\n")
        self.git("add", path)
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "Fixture schema")
        (self.repo / path).unlink()
        self.assertIn("check --workspace @arc/client", self.verify())


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        for directory in (".codex", ".agents", "docs"):
            shutil.copytree(ROOT / directory, self.repo / directory)
        for pattern in ("AGENTS.md", "README.md", "skills-lock.json", "scripts/check-agent-setup.py",
                        "services/*/migrations/sqlite.go"):
            for source in ROOT.glob(pattern):
                target = self.repo / source.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(source, target)

    def check(self):
        return run(sys.executable, "scripts/check-agent-setup.py", cwd=self.repo)

    def test_current_setup(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_profile_rejected(self):
        (self.repo / ".codex/profiles/deep.config.toml").unlink()
        self.assertNotEqual(self.check().returncode, 0)

    def test_stale_migration_reference_rejected(self):
        (self.repo / "docs/MIGRATION.md").write_text("Apply `000099_missing` before startup.\n")
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown migration 000099_missing", result.stderr)

    def test_invalid_budget_rejected(self):
        path = self.repo / ".codex/config.toml"
        path.write_text(path.read_text().replace("max_context_tokens = 1200", "max_context_tokens = 0"))
        self.assertNotEqual(self.check().returncode, 0)


class InstallerTests(unittest.TestCase):
    def test_install_idempotency_and_conflict_preserve_user_files(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            command = (sys.executable, str(ROOT / "scripts/install-codex-profiles.py"),
                       "--codex-home", directory)
            self.assertEqual(run(*command).returncode, 0)
            profile = home / "fast.config.toml"
            modified = profile.stat().st_mtime_ns
            self.assertEqual(run(*command).returncode, 0)
            self.assertEqual(profile.stat().st_mtime_ns, modified)
            profile.write_text("# Personal profile\n")
            (home / "deep.config.toml").unlink()
            self.assertNotEqual(run(*command).returncode, 0)
            self.assertEqual(profile.read_text(), "# Personal profile\n")
            self.assertFalse((home / "deep.config.toml").exists())


if __name__ == "__main__":
    unittest.main()
