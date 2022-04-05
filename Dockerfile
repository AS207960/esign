FROM rustlang/rust:nightly AS builder
RUN update-ca-certificates
RUN mkdir /files
WORKDIR /usr/src/

RUN USER=root cargo new as207960-esign
WORKDIR /usr/src/as207960-esign
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

COPY src ./src
COPY migrations ./migrations
RUN cargo install --path .

FROM debian:buster-slim

RUN apt-get update && apt-get install -y libssl1.1 libpq5 ca-certificates p11-kit-modules gnutls-bin && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

WORKDIR /as207960-esign

COPY --from=builder --chown=0:0 /usr/local/cargo/bin/frontend /as207960-esign/frontend
COPY --from=builder --chown=0:0 /usr/local/cargo/bin/tasks /as207960-esign/tasks
COPY --from=builder --chown=0:0 /files /as207960-esign/files
COPY --chown=0:0 static /as207960-esign/static
COPY --chown=0:0 templates /as207960-esign/templates
COPY --chown=0:0 templates_email /as207960-esign/templates_email

ENTRYPOINT ["/as207960-esign/frontend"]
