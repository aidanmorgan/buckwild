# Use Debian Bookworm slim for minimal footprint
FROM debian:bookworm-slim

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Set up non-root user
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN apt-get update \
    && apt-get install -y --no-install-recommends sudo \
    && groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m -s /bin/bash $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && rm -rf /var/lib/apt/lists/*

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    cmake \
    pkg-config \
    # eBPF development tools
    linux-headers-arm64 \
    libbpf-dev \
    bpftool \
    clang \
    llvm \
    libelf-dev \
    # Networking libraries
    libnl-3-dev \
    libnl-route-3-dev \
    libnetfilter-queue-dev \
    # TUN/TAP support
    iproute2 \
    iptables \
    # Development utilities
    git \
    curl \
    wget \
    vim-tiny \
    htop \
    strace \
    gdb \
    valgrind \
    # Protocol tools
    tcpdump \
    netcat-openbsd \
    # SSL/Crypto
    libssl-dev \
    # Other dependencies
    ca-certificates \
    gnupg \
    zsh \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain
USER $USERNAME
WORKDIR /home/$USERNAME

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && . $HOME/.cargo/env \
    && rustup component add rustfmt clippy rust-src \
    && rustup target add aarch64-unknown-linux-gnu \
    && rustup target add x86_64-unknown-linux-gnu

# Install cargo tools (skip bpf-linker for now - can add if needed)
RUN . $HOME/.cargo/env \
    && cargo install cargo-watch \
    && cargo install cargo-audit

# Add cargo to PATH
ENV PATH="/home/$USERNAME/.cargo/bin:${PATH}"

# Create workspace directory
USER root
RUN mkdir -p /workspace && chown $USERNAME:$USERNAME /workspace

# Enable IP forwarding for TUN device testing
RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf \
    && echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

# Create TUN device node if it doesn't exist
RUN mkdir -p /dev/net \
    && mknod /dev/net/tun c 10 200 || true \
    && chmod 0666 /dev/net/tun || true

# Set final user
USER $USERNAME
WORKDIR /workspace

# Set shell to zsh
ENV SHELL=/bin/zsh

CMD ["/bin/zsh"]
