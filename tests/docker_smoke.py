#!/usr/bin/env python3
"""Build the deployment image and verify its least-privilege live SOCKS relay."""

import os
import json
import pathlib
import secrets
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker" / "compose.yaml"
TIMEOUT = 45


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


def run(command, *, env, capture=False):
    print("+", " ".join(map(str, command)), flush=True)
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def socks_round_trip(proxy_port, echo_port):
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as sock:
        sock.settimeout(4)
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 method negotiation failed")
        hostname = b"host.docker.internal"
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(hostname)])
            + hostname
            + echo_port.to_bytes(2, "big")
        )
        reply = sock.recv(10)
        if len(reply) != 10 or reply[:2] != b"\x05\x00":
            raise RuntimeError(f"SOCKS5 tunnel open failed: {reply!r}")
        payload = b"container non-root relay smoke test"
        sock.sendall(payload)
        response = bytearray()
        while len(response) < len(payload):
            part = sock.recv(len(payload) - len(response))
            if not part:
                raise RuntimeError("origin closed before returning the full payload")
            response.extend(part)
        if bytes(response) != payload:
            raise RuntimeError(f"relay payload mismatch: {bytes(response)!r}")


def wait_for_port(port, deadline):
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"server container did not publish TCP port {port}")


def main():
    uid = 10001 if os.geteuid() == 0 else os.geteuid()
    gid = 10001 if os.geteuid() == 0 else os.getegid()
    ports = [free_port() for _ in range(4)]
    with tempfile.TemporaryDirectory(prefix="satmux-docker-") as directory:
        secret = pathlib.Path(directory) / "mux.psk"
        secret.write_text(secrets.token_hex(32) + "\n", encoding="ascii")
        secret.chmod(0o400)
        if os.geteuid() == 0:
            os.chown(secret, uid, gid)

        env = os.environ.copy()
        env.update(
            {
                "SATMUX_SECRET_FILE": str(secret),
                "SATMUX_CONTAINER_UID": str(uid),
                "SATMUX_CONTAINER_GID": str(gid),
                "SATMUX_SERVER_PORT": str(ports[0]),
                "SATMUX_SOCKS_PORT": str(ports[1]),
                "SATMUX_HTTP_PORT": str(ports[2]),
                "SATMUX_FAST_PORT": str(ports[3]),
                "SATMUX_CARRIERS": "1",
            }
        )
        compose = ["docker", "compose", "-f", str(COMPOSE)]
        origin = socketserver.ThreadingTCPServer(("0.0.0.0", 0), EchoHandler)
        origin.daemon_threads = True
        origin_port = origin.server_address[1]
        threading.Thread(target=origin.serve_forever, daemon=True).start()

        try:
            run(compose + ["config", "--quiet"], env=env)
            run(compose + ["build", "--quiet"], env=env)
            run(compose + ["up", "--detach", "server"], env=env)
            wait_for_port(ports[0], time.monotonic() + TIMEOUT)
            run(compose + ["--profile", "client", "up", "--detach", "client"], env=env)
            for service in ("server", "client"):
                container_id = run(
                    compose + ["ps", "-q", service],
                    env=env,
                    capture=True,
                ).stdout.strip()
                if not container_id:
                    raise RuntimeError(f"Docker Compose did not report a running {service} container")

                inspect = run(
                    [
                        "docker",
                        "inspect",
                        "--format",
                        "{{json .Config.User}} {{json .HostConfig.CapDrop}} {{json .HostConfig.Privileged}} {{json .HostConfig.ReadonlyRootfs}} {{json .HostConfig.SecurityOpt}} {{json .HostConfig.PortBindings}}",
                        container_id,
                    ],
                    env=env,
                    capture=True,
                ).stdout.strip()
                user, cap_drop, privileged, read_only, security, bindings = inspect.split(" ", 5)
                if (
                    json.loads(user) != f"{uid}:{gid}"
                    or "ALL" not in json.loads(cap_drop)
                    or json.loads(privileged)
                    or not json.loads(read_only)
                    or "no-new-privileges:true" not in json.loads(security)
                ):
                    raise RuntimeError(f"{service} container is missing least-privilege settings: {inspect}")
                if service == "client":
                    port_bindings = json.loads(bindings)
                    if not port_bindings or any(
                        binding["HostIp"] != "127.0.0.1"
                        for mappings in port_bindings.values()
                        for binding in mappings
                    ):
                        raise RuntimeError(f"client proxy ports must bind to host loopback: {bindings}")
            print("Verified both containers are non-root, read-only, and drop all capabilities.")
            print("Verified published client proxies bind only to host loopback.")

            deadline = time.monotonic() + TIMEOUT
            last_error = None
            while time.monotonic() < deadline:
                try:
                    socks_round_trip(ports[1], origin_port)
                    print("SOCKS5 through container client/server echoed the full payload.")
                    break
                except (OSError, RuntimeError) as error:
                    last_error = error
                    time.sleep(0.25)
            else:
                raise RuntimeError(f"container SOCKS5 round trip failed: {last_error}")
        except Exception:
            subprocess.run(
                compose + ["--profile", "client", "logs", "--no-color"],
                cwd=ROOT,
                env=env,
                check=False,
            )
            raise
        finally:
            subprocess.run(
                compose + ["--profile", "client", "down", "--volumes", "--remove-orphans"],
                cwd=ROOT,
                env=env,
                check=False,
            )
            origin.shutdown()


if __name__ == "__main__":
    main()
