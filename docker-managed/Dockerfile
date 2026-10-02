FROM rust:1.90-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev libsodium-dev libx11-dev cmake clang && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# sqlx query macros validate against the checked-in schema database at build time.
ENV DATABASE_URL=sqlite:///src/db_v2.sqlite3
RUN cargo build --locked --release --bin hbbs --bin hbbr

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 libsodium23 libx11-6 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/hbbs /src/target/release/hbbr /usr/local/bin/
WORKDIR /data
CMD ["hbbs"]
