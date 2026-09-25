FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk --no-cache add squid ca-certificates
USER 65532:65532
ENTRYPOINT ["/usr/sbin/squid", "-N", "-f", "/etc/squid/loom.conf"]
