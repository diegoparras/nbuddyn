# Static build: the final image holds one binary and nothing else.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
RUN cargo build --release --locked
# An empty directory for the history; a volume mounted here inherits its owner.
RUN mkdir /data

FROM scratch
COPY --from=build /src/target/release/nbuddyn /nbuddyn
COPY --from=build --chown=65534:65534 /data /data
ENV NBUDDYN_DATA_DIR=/data
USER 65534:65534
EXPOSE 8787
ENTRYPOINT ["/nbuddyn"]
