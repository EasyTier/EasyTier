FROM alpine:latest AS base
FROM base AS builder

ARG TARGETPLATFORM

COPY . /tmp/artifacts
WORKDIR /tmp/output
RUN ARTIFACT_ARCH=""; \
    if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
        ARTIFACT_ARCH="x86_64"; \
    elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
        ARTIFACT_ARCH="aarch64"; \
    else \
        echo "Unsupported architecture: $TARGETARCH"; \
        exit 1; \
    fi; \
    cp /tmp/artifacts/easytier-linux-${ARTIFACT_ARCH}/* /tmp/output;

FROM base

RUN apk add --no-cache tzdata tini
WORKDIR /app
COPY --from=builder --chmod=755 /tmp/output/* /usr/local/bin

# users can use "-e TZ=xxx" to adjust it
ENV TZ=Asia/Shanghai

# tcp
EXPOSE 11010/tcp
# udp
EXPOSE 11010/udp
# wg
EXPOSE 11011/udp
# ws
EXPOSE 11011/tcp
# wss
EXPOSE 11012/tcp

ENTRYPOINT ["/sbin/tini", "--", "easytier-core"]
