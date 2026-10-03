# Console management integration

The opt-in `/v1` HTTP API is independent of RustDesk's client protocol ports. Set `RD_MANAGEMENT_BIND` to a private socket address, `RD_MANAGEMENT_TOKEN` to an independent random Bearer credential of at least 32 characters, and `RD_MANAGEMENT_DIR` to a persistent directory shared with the node agent. Do not publish this listener to the client-facing network.

hbbs exposes `GET /v1/status`, `GET /v1/config`, `GET /v1/peers` and `GET/PUT /v1/bans`. hbbr additionally exposes `GET /v1/sessions` and `DELETE /v1/sessions/:uuid`; it has no peers endpoint. All endpoints require authorization. API version is 1. Session closure is asynchronous (`202`, `state: closing`). IP bans check both relay endpoints. Reported target IDs are not authenticated source identities.

Files are service-specific: `hbbs-config.json`, `hbbr-config.json`, `hbbs-bans.json`, and `hbbr-bans.json`. Configurations use `{ "values": { "port": "21116" } }`, and policies use `{ "device_ids": [], "ips": [] }`. Saved bans are validated and restored before protocol startup even when `RD_MANAGEMENT_BIND` is empty. Disabling the HTTP listener does not clear admission policy; explicitly replace the bans with empty lists before disabling management if clearing is intended. Ban replacements serialize persistence outside the protocol admission lock and activate only after the write succeeds.

Managed settings override startup inputs; they require a restart. Schema and validation are provided by `management-schema.json`. The API returns key placeholders, never the private key. It exposes only `id_ed25519.pub` as the public key.

`docker-managed/Dockerfile` builds the managed hbbs/hbbr image in CI. The Console repository supplies the node agent, combined Compose deployment, permission enforcement, UI, integration workflow and detailed lifecycle documentation in `docs/server-management.md`. Existing binaries remain compatible with deployments that do not enable management.
