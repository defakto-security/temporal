FROM ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG TARGETPLATFORM

# see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
RUN apt-get update && apt-get install -y \
	ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

COPY build/$TARGETPLATFORM/server /usr/local/sbin/defakto-spiffe-temporal

# The module reads its own config from the path the customer's ConfigMap mounts.
ENV DEFAKTO_SPIFFE_TEMPORAL_CONFIG=/etc/defakto-spiffe-temporal/config.yaml

STOPSIGNAL SIGTERM
CMD ["/usr/local/sbin/defakto-spiffe-temporal"]
