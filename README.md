# satmux

Rust implementation of the TCP multiplexer and HTTP/TLS relay. The original
Python implementation, helpers, and documentation are preserved under [`py/`](py/).

## Build and run

Create a 32-byte pre-shared key as hexadecimal and keep it private:

```sh
openssl rand -hex 32 > mux.psk
chmod 600 mux.psk
```

Run the ground server:

```sh
SATMUX_PSK="$(cat mux.psk)" cargo run --release -- server --host 0.0.0.0 --port 8444
```

Run the local client:

```sh
SATMUX_PSK="$(cat mux.psk)" cargo run --release -- client \
  --host <SERVER_IP> --port 8444 --carriers 12
```

The client listens on SOCKS5 `127.0.0.1:1080`, HTTP proxy
`127.0.0.1:8080`, and the 1-RTT fetch gateway `127.0.0.1:8081`. The optional
GitHub CLI TLS bridge uses `/tmp/satmux-gh-tls.sock` by default; pass
`--gh-sock ""` to disable it. `SATMUX_PSK` or `ORB_MUX_PSK` may supply the key,
or use `--psk-hex` / `--psk-file`. A client can set `--proxy-host` to select
its local listener interface; loopback remains the default.

## Docker deployment

The [Docker Compose deployment](docker/compose.yaml) builds the Rust binary
from source. It runs as UID/GID `10001`, has a read-only root filesystem, drops
all Linux capabilities, and enables `no-new-privileges`. It does not use
privileged mode or require `NET_ADMIN`; TCP congestion-control tuning is
best-effort and uses host-kernel BBR only when available.

Create a hex-encoded PSK that is readable only by the container's service user:

```sh
install -d -m 0700 docker/secrets
umask 077
openssl rand -hex 32 > docker/secrets/mux.psk
sudo chown 10001:10001 docker/secrets/mux.psk
chmod 0400 docker/secrets/mux.psk
```

Start the ground server:

```sh
docker compose -f docker/compose.yaml up --build -d server
docker compose -f docker/compose.yaml logs -f server
```

Port `8444/tcp` is published on all host interfaces by default; restrict
inbound traffic to trusted client IPs with the host firewall or set
`SATMUX_SERVER_PUBLISH=127.0.0.1` when clients connect locally. The server
requires no extra container capabilities. For best-effort BBR congestion
control, use a Linux host kernel with BBR available and configure the host's
TCP congestion control and queue discipline (commonly `bbr` and `fq`) according
to the host OS. To allow this unprivileged process to select BBR per socket,
the host must have BBR available and include it in
`net.ipv4.tcp_allowed_congestion_control`; `net.core.default_qdisc=fq` is a
common BBR pairing. Docker does not change host-wide sysctls, and the container
does not receive `NET_ADMIN`.

The optional `client` service publishes its proxies only on host loopback:

```sh
SATMUX_SERVER_HOST=<SERVER_IP> docker compose -f docker/compose.yaml \
  --profile client up --build -d client
```

The SOCKS5, HTTP proxy, and fetch gateway use host ports `1080`, `8080`, and
`8081`; override these with `SATMUX_SOCKS_PORT`, `SATMUX_HTTP_PORT`, and
`SATMUX_FAST_PORT` if needed. The container listens on `0.0.0.0` internally
for Docker port forwarding, while the host-side bindings remain `127.0.0.1`.
To deliberately expose a proxy on a network interface, change the Compose
bindings only after applying appropriate firewall and access controls. The
GitHub CLI Unix socket bridge is disabled in this service.

For a different container UID/GID, set `SATMUX_CONTAINER_UID` and
`SATMUX_CONTAINER_GID`, then make the secret file readable by that identity.
Compose mounts the secret read-only at `/run/secrets/mux_psk`; `SATMUX_PSK_FILE`
can be used with direct `docker run` deployments as well. Keep the source PSK
out of version control.

Run the Rust and Docker regression suite with:

```sh
docker/test.sh
```

This runs Cargo tests, builds the image, checks the Compose deployment and
least-privilege container settings, then sends a SOCKS5 TCP round trip through
the actual containers. Docker Engine, Docker Compose, Python 3, and Cargo are
required.

The original helper scripts remain available as `py/bin/satmux-bench`,
`py/bin/satmux-get`, and `py/bin/satmux-macos`.

## Use as a library

The package provides both the `satmux` library and the `satmux` binary. Add it
to another crate using a local path (adjust the path to this checkout):

```toml
[dependencies]
anyhow = "1"
satmux = { path = "../satmux" }
tokio = { version = "1", features = ["full"] }
```

Call the async entry points from your application's Tokio runtime:

```rust,no_run
use satmux::{ClientConfig, ServerConfig, run_client, run_server};

async fn relay(psk: Vec<u8>) -> anyhow::Result<()> {
    let server = ServerConfig::new("0.0.0.0", 8444, psk.clone());
    let mut client = ClientConfig::new("127.0.0.1", 8444, psk);
    client.carriers = 4;
    client.socks_port = 1081;

    tokio::try_join!(run_server(server), run_client(client))?;
    Ok(())
}
```

Keys are raw bytes, not hex strings. Library calls do not read environment
variables, create a runtime, or exit the process; errors are returned to the
caller. `ClientConfig::new` uses 12 carriers and the usual TCP proxy ports, but
disables the Unix socket bridge unless `gh_socket` is explicitly set. The CLI
retains its existing defaults, environment variables, and flags.

Both entry points run until an error or cancellation. Drop their futures (or
abort their Tokio tasks) to close TCP listeners and abort their background
connections. An enabled Unix socket may leave its socket file behind after
cancellation; a subsequent client start removes it.

## Functional parity checks

Run the Rust unit tests with:

```sh
cargo test
```

The tests cover protocol key derivation, encrypted/compressed framing, a live
TCP tunnel, public library configuration and cancellation, and CLI compatibility.
The library example is also compiled as a doctest. The wire protocol remains
compatible with the Python implementation in `py/satmux.py`.

## License

MIT
