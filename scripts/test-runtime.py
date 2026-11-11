#!/usr/bin/env python3
"""Isolated Runtime TLS/NKey guardrails; no Docker or production credentials."""
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
    actual = subprocess.check_output([server, "--version"], text=True)
    version = re.search(r"v(\d+\.\d+\.\d+)", actual)
    if pinned is None or version is None or pinned.group(1) != version.group(1):
        raise SystemExit("nats-server version must match the image pinned in compose.yaml")
    with tempfile.TemporaryDirectory(prefix="arc-runtime-") as directory:
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
        users = [{"nkey": keys[0], "permissions": {
            "publish": {"allow": ["_INBOX.>", "ctl.arc.fabric.probe.>", "$SRV.INFO.>", "evt.arc.fabric.routes.changed"]},
            "subscribe": {"allow": ["rpc.identity.v1.>", "rpc.access.v1.>", "ctl.arc.fabric.>", "ctl.runtime.v1.node.>", "$SRV.>"]},
        }}]
        for key, node in zip(keys[1:], ("node-one", "node-two")):
            prefix = f"ctl.runtime.v1.node.{node}."
            users.append({"nkey": key, "permissions": {
                "publish": {"allow": ["rpc.identity.v1.invocations.exchange_service", prefix + "inventory", prefix + "desired.get", prefix + "report", prefix + "profile.plan"]},
                "subscribe": {"allow": [f"_INBOX.runtime.{node}.>"]},
            }})
        config.write_text(header + "authorization " + json.dumps({"users": users}))
        with (scratch / "nats.log").open("w+") as log:
            process = subprocess.Popen([server, "-c", str(config)], stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise SystemExit("isolated Runtime NATS server exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise SystemExit("isolated Runtime NATS readiness timeout")
                agent_binary = scratch / "arc-agent"
                subprocess.run(["go", "build", "-o", str(agent_binary), "./cmd/arc-agent"], cwd=root, check=True)
                env = dict(os.environ, ARC_RUNTIME_NATS_URL=f"tls://localhost:{port}", ARC_RUNTIME_NATS_SECRETS=str(secrets), ARC_RUNTIME_AGENT_BINARY=str(agent_binary))
                subprocess.run(["go", "test", "-race", "-count=1", "-timeout=2m", "./sdk/agent", "./services/agent/...", "./services/core/modules/runtime"], cwd=root, env=env, check=True)
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
