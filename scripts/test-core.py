#!/usr/bin/env python3
"""Standalone Core startup/lifecycle guardrails with isolated TLS/NKey fixtures."""
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import tempfile
import time


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    server = shutil.which("nats-server")
    if server is None:
        raise SystemExit("nats-server is required (use the version pinned in compose.yaml)")
    pinned = re.search(r"image:\s*nats:(\d+\.\d+\.\d+)", (root / "compose.yaml").read_text())
    actual = re.search(r"v(\d+\.\d+\.\d+)", subprocess.check_output([server, "--version"], text=True))
    if pinned is None or actual is None or pinned.group(1) != actual.group(1):
        raise SystemExit("nats-server version must match the image pinned in compose.yaml")
    with tempfile.TemporaryDirectory(prefix="arc-core-") as directory:
        scratch = pathlib.Path(directory)
        secrets = scratch / "secrets"
        subprocess.run([
            "go", "run", "./test/bootstrap", "-out", str(secrets),
            "-runtime-dir", str(secrets), "-store-dir", str(scratch / "jetstream"),
        ], cwd=root, check=True, stdout=subprocess.DEVNULL)
        config = secrets / "nats-server.conf"
        original = config.read_text()
        keys = re.findall(r'nkey:\s*"([A-Z0-9]+)"', original)
        if len(keys) != 3:
            raise SystemExit("unexpected bootstrap NKey fixture")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        header = original.split("authorization {", 1)[0]
        header = header.replace("port: 4222", f'listen: "127.0.0.1:{port}"')
        header = header.replace("http: 8222", "http: -1")
        users = [
            {"nkey": keys[0], "permissions": {
                "publish": {"allow": ["_INBOX.>", "ctl.arc.fabric.probe.>", "$SRV.INFO.>", "evt.arc.fabric.routes.changed"]},
                "subscribe": {"allow": ["rpc.identity.v1.>", "rpc.access.v1.>", "ctl.arc.fabric.>", "$SRV.>"]},
            }},
            {"nkey": keys[1], "permissions": {
                "publish": {"allow": ["rpc.identity.v1.>", "rpc.access.v1.>", "ctl.arc.fabric.>", "ctl.runtime.v1.>", "$SRV.INFO.arc-core"]},
                "subscribe": {"allow": ["_INBOX.>"]},
            }},
        ]
        config.write_text(header + "authorization " + json.dumps({"users": users}))
        core_binary = scratch / "arc-core"
        migrator = scratch / "arc-migrate"
        subprocess.run(["go", "build", "-race", "-o", str(core_binary), "./cmd/arc-core"], cwd=root, check=True)
        subprocess.run(["go", "build", "-o", str(migrator), "./deploy/migrate"], cwd=root, check=True)
        with (scratch / "nats.log").open("w+") as log:
            process = subprocess.Popen([server, "-c", str(config)], stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise SystemExit("isolated Core NATS server exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise SystemExit("isolated Core NATS readiness timeout")
                env = dict(os.environ, ARC_CORE_NATS_URL=f"tls://localhost:{port}", ARC_CORE_NATS_SECRETS=str(secrets), ARC_CORE_BINARY=str(core_binary), ARC_CORE_MIGRATOR=str(migrator))
                subprocess.run(["go", "test", "-race", "-count=1", "-timeout=2m", "-v", "./services/core"], cwd=root, env=env, check=True)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode) from None
