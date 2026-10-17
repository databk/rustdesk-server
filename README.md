# RustDesk Server

Self-host the server side of RustDesk, the open source remote desktop software. Run it on your own infrastructure so devices register, find each other, and relay traffic through machines you control.

Standard RustDesk clients connect out of the box, and an optional management API adds centralized configuration, monitoring and relay fleet control for operating servers at scale (see [Highlights](#highlights)).

## What's inside

A single Rust codebase produces three executables:

| Binary | Role |
| --- | --- |
| `hbbs` | ID/rendezvous server — registers devices and helps them connect |
| `hbbr` | Relay server — carries remote desktop traffic when direct connection is not possible |
| `rustdesk-utils` | Command line utilities for server administration |

The `ui` folder also contains an optional desktop app that runs the servers as Windows services.

## Quick start with Docker Compose

The fastest way to get running:

```yaml
services:
  hbbs:
    image: databk/rustdesk-server:latest
    container_name: hbbs
    ports:
      - 21115:21115
      - 21116:21116
      - 21116:21116/udp
      - 21118:21118
    command: hbbs -r <your-relay-server>:21117
    volumes:
      - ./data:/root
    restart: unless-stopped

  hbbr:
    image: databk/rustdesk-server:latest
    container_name: hbbr
    ports:
      - 21117:21117
      - 21119:21119
    command: hbbr
    volumes:
      - ./data:/root
    restart: unless-stopped
```

Start it with `docker compose up -d`, then point your RustDesk clients at `<your-server-host>` (ID server) and `<your-relay-server>:21117` (relay server). The public key your clients need is in `./data/id_ed25519.pub` after first start.

### Ports

| Port | Protocol | Used by | Purpose |
| --- | --- | --- | --- |
| 21115 | TCP | hbbs | NAT type test |
| 21116 | TCP/UDP | hbbs | ID registration and hole punching |
| 21117 | TCP | hbbr | Relay traffic |
| 21118 | TCP | hbbs | Web client |
| 21119 | TCP | hbbr | Web client relay |

## Highlights

- **Management REST API** — hbbs serves an opt-in `/v1` API for status, configuration, logs, peer lists, IP/device bans, sessions and live events (SSE), secured by a bearer token.
- **Relay fleet control** — run several hbbr instances; each one registers with hbbs over a control channel, so you can watch sessions, update settings, or restart any relay through a single API.
- **Live configuration** — change speed limits, bandwidth caps and the relay list without restarting the servers.
- **WebRTC signaling** — WebRTC session descriptions and candidates can be exchanged through the rendezvous server.

To enable the management API, set `RD_MANAGEMENT_BIND`, `RD_MANAGEMENT_TOKEN` and `RD_MANAGEMENT_DIR` on hbbs, and `RD_HBBS_API_URL` on each hbbr. Keep the listener on a private network — it is meant for operators, not clients. The full contract is documented in [docs/management.md](docs/management.md), and a companion web console is available in the [rustdesk-console](https://github.com/databk/rustdesk-console) repository.

Everything works without these settings too: with management disabled, the servers run a minimal, protocol-only setup.

## Build from source

Requires a recent Rust toolchain.

```bash
git clone --recurse-submodules https://github.com/databk/rustdesk-server.git
cd rustdesk-server
cargo build --release
```

The binaries appear in `target/release`. To build the optional Windows desktop app, build the `ui` workspace separately.

## Other ways to deploy

- **Plain binaries** — download from [Releases](https://github.com/databk/rustdesk-server/releases) or build your own, then run `hbbs` and `hbbr` directly.
- **Docker** — ready-made images and health checks under `docker/`; a minimal legacy variant under `docker-classic/`.
- **Kubernetes** — a sample manifest in `kubernetes/example.yaml`.
- **systemd** — service units for hbbs and hbbr in `systemd/`.
- **Debian package** — packaging files under `debian/`.

## Documentation

- [Management API reference](docs/management.md) — endpoints, configuration and relay control
- [rustdesk-console](https://github.com/databk/rustdesk-console) — companion web console for the management API

## License

Licensed under [AGPL-3.0](LICENSE).