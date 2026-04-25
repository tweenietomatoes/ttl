FROM gcr.io/distroless/static-debian13:nonroot
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/ttl /usr/bin/ttl
ENTRYPOINT ["/usr/bin/ttl"]
