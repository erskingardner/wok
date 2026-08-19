FROM rust:1.94-slim-trixie AS builder

ARG FIPS_GIT_REV=9a2b85cd4f511c978de1b028d6124115f64ad7a8
ENV RUSTUP_TOOLCHAIN=1.94.1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        git \
        libclang-dev \
        libdbus-1-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src/wok
COPY . .
RUN grep -Fq "${FIPS_GIT_REV}" Cargo.lock && \
    cargo build --release --locked -p wok-cli --bin wok && \
    cargo build --release --locked -p wok-fips \
        --example native-client \
        --example native-event-matrix

RUN git init /src/fips && \
    git -C /src/fips remote add origin https://github.com/jmcorgan/fips.git && \
    git -C /src/fips fetch --depth 1 origin "${FIPS_GIT_REV}" && \
    git -C /src/fips checkout --detach FETCH_HEAD && \
    test "$(git -C /src/fips rev-parse HEAD)" = "${FIPS_GIT_REV}"

WORKDIR /src/fips
RUN cargo build --release --locked --bin fips --bin fipsctl

FROM debian:trixie-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl libdbus-1-3 tini && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system fips && \
    install -d -o root -g fips -m 0750 /run/fips /etc/fips /etc/wok /var/lib/wok

COPY --from=builder /src/wok/target/release/wok /usr/local/bin/wok
COPY --from=builder /src/wok/target/release/examples/native-client /usr/local/bin/native-client
COPY --from=builder /src/wok/target/release/examples/native-event-matrix /usr/local/bin/native-event-matrix
COPY --from=builder /src/fips/target/release/fips /usr/local/bin/fips
COPY --from=builder /src/fips/target/release/fipsctl /usr/local/bin/fipsctl
COPY testing/fips-native/fips-compose-smoke.sh /usr/local/bin/fips-compose-smoke

ENTRYPOINT []
