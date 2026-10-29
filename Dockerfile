FROM ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG TARGETOS
ARG TARGETARCH

# see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
RUN apt-get update && apt-get install -y \
	ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

# Matches the Makefile output path: build/$GOOS/$GOARCH/server. Using
# TARGETOS/TARGETARCH (not TARGETPLATFORM) avoids the arm64 variant suffix
# (linux/arm64/v8), which would not match the build/linux/arm64/ path.
COPY build/$TARGETOS/$TARGETARCH/server /usr/local/sbin/defakto-spiffe-temporal

# The module reads its own config from the path the customer's ConfigMap mounts.
ENV DEFAKTO_SPIFFE_TEMPORAL_CONFIG=/etc/defakto-spiffe-temporal/config.yaml

# Run as a non-root UID. ubuntu:24.04 ships the 'ubuntu' user at UID 1000; the
# mounted ConfigMap (config + Cedar policy) is world-readable, so this UID can
# read it.
USER 1000:1000

STOPSIGNAL SIGTERM
CMD ["/usr/local/sbin/defakto-spiffe-temporal"]
