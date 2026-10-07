FROM gcc:12-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends qemu-user tcpdump strace \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
CMD ["make", "both"]
