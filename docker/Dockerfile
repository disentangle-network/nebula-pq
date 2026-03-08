FROM gcr.io/distroless/static:latest

ARG TARGETOS TARGETARCH
COPY --chmod=755 build/$TARGETOS-$TARGETARCH/nebula /nebula
COPY --chmod=755 build/$TARGETOS-$TARGETARCH/nebula-cert /nebula-cert

VOLUME ["/config"]

ENTRYPOINT ["/nebula"]
# Allow users to override the args passed to nebula
CMD ["-config", "/config/config.yml"]
