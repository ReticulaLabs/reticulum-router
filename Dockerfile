FROM docker.io/rust:alpine3.24 as BUILD
RUN mkdir -p /tmp/src && apk update && apk add protobuf
COPY . /tmp/src
WORKDIR /tmp/src
RUN cargo build -r


FROM docker.io/alpine:3.24
COPY --from=BUILD /tmp/src/target/release/reticulum-router /usr/local/bin/reticulum-router
COPY --from=BUILD /tmp/src/target/release/rnid /usr/local/bin/rnid
COPY --from=BUILD /tmp/src/target/release/rnpath /usr/local/bin/rnpath
COPY --from=BUILD /tmp/src/target/release/rnperf /usr/local/bin/rnperf
COPY --from=BUILD /tmp/src/target/release/rnsh /usr/local/bin/rnsh
COPY --from=BUILD /tmp/src/target/release/rnpage /usr/local/bin/rnpage
COPY --from=BUILD /tmp/src/target/release/rnmcp /usr/local/bin/rnmcp
COPY --from=BUILD /tmp/src/target/release/rngit /usr/local/bin/rngit
ENTRYPOINT "/usr/local/bin/reticulum-router"
EXPOSE 4242/tcp
EXPOSE 4242/udp
