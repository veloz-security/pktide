FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-x86 qemu-user rpm2cpio cpio e2fsprogs isolinux syslinux-common xorriso \
    curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
