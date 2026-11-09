FROM rust:1-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY py/LICENSE ./py/LICENSE
COPY src ./src
RUN cargo build --locked --release --bin satmux

FROM debian:bookworm-slim AS runtime

ARG SATMUX_UID=10001
ARG SATMUX_GID=10001

COPY --from=build /src/target/release/satmux /usr/local/bin/satmux

USER ${SATMUX_UID}:${SATMUX_GID}
EXPOSE 8444/tcp
ENTRYPOINT ["/usr/local/bin/satmux"]
CMD ["server", "--host", "0.0.0.0", "--port", "8444"]
