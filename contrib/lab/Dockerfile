# syntax=docker/dockerfile:1
FROM rust:1.96.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
RUN cargo build --release --locked -p wok-cli -p wok-bench

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data /results && chown 10001:10001 /data /results
COPY --from=build /src/target/release/wok /src/target/release/wok-bench /usr/local/bin/
COPY contrib/lab/wok.toml /etc/wok/lab.toml
COPY contrib/lab/load.py /usr/local/lib/wok-lab/load.py
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/erskingardner/wok" \
      org.opencontainers.image.revision=$SOURCE_REVISION
USER 10001:10001
ENTRYPOINT ["wok"]
CMD ["--config", "/etc/wok/lab.toml", "relay"]
