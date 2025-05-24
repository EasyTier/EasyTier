FROM alpine:latest AS builder
WORKDIR /app

ENV S6_OVERLAY_VERSION="3.2.1.0"
ARG TARGETARCH

RUN apk update && apk add --no-cache git jq curl unzip wget && \
    if [ "$TARGETARCH" = "arm64" ]; then S6_ARCH="aarch64"; EASYTIER_ARCH="aarch64"; else S6_ARCH="x86_64"; EASYTIER_ARCH="x86_64"; fi && \
    LATEST_TAG=$(curl -s https://api.github.com/repos/EasyTier/EasyTier/tags | jq -r '.[0].name') && \
    wget -O /app/easytier.zip https://github.com/EasyTier/EasyTier/releases/download/${LATEST_TAG}/easytier-linux-${EASYTIER_ARCH}-${LATEST_TAG}.zip && \
    cd /app && \
    unzip easytier.zip && rm -rf easytier.zip && \
    mv easytier-linux-${EASYTIER_ARCH} easytier && \
    cd /tmp && \
    curl -L -o /tmp/s6-overlay-noarch.tar.xz https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz && \     
    curl -L -o /tmp/s6-overlay.tar.xz https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz     

FROM busybox:stable-glibc

ENV COMMAND="" \
    PATH="/command:${PATH}" \
    BASE_PATH="/etc/s6-overlay/s6-rc.d"

COPY --chmod=755 ./rootfs /
COPY --from=builder /app/easytier ${BASE_PATH}/easytier
COPY --from=builder /tmp/s6-overlay-noarch.tar.xz /tmp
COPY --from=builder /tmp/s6-overlay.tar.xz /tmp

RUN tar -C / -Jxf /tmp/s6-overlay-noarch.tar.xz && \
    rm -f /tmp/s6-overlay-noarch.tar.xz && \
    tar -C / -Jxf /tmp/s6-overlay.tar.xz && \
    rm -f /tmp/s6-overlay.tar.xz && \
    ln -sf /run /var/run
 
HEALTHCHECK --interval=10s --timeout=5s CMD /healthcheck.sh

ENTRYPOINT ["/init"]