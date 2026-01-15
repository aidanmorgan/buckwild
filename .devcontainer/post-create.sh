#!/bin/bash

set -e

echo "🚀 Running post-create setup..."

# Ensure we're in the workspace directory
cd /workspace

# Source Rust environment
source "$HOME/.cargo/env"

# Display versions
echo ""
echo "📦 Installed versions:"
echo "  Rust:    $(rustc --version)"
echo "  Cargo:   $(cargo --version)"
echo "  Clang:   $(clang --version | head -n 1)"
echo "  LLVM:    $(llvm-config --version)"
echo "  CMake:   $(cmake --version | head -n 1)"
echo "  Kernel:  $(uname -r)"
echo ""

# Check for eBPF support
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "✅ BTF (BPF Type Format) is available"
else
    echo "⚠️  BTF is not available (this is OK for development)"
fi

# Create TUN device if needed (requires privileged container)
if [ ! -c /dev/net/tun ]; then
    echo "⚠️  TUN device not found - attempting to create..."
    sudo mkdir -p /dev/net
    sudo mknod /dev/net/tun c 10 200 || echo "  (TUN device creation requires privileged mode)"
    sudo chmod 0666 /dev/net/tun || true
fi

# Check if we're in the project directory
if [ -f "Cargo.toml" ] || [ -f "CMakeLists.txt" ]; then
    echo ""
    echo "📋 Project structure detected"

    # Build the project to cache dependencies
    echo "🔨 Fetching dependencies (this may take a few minutes)..."

    if [ -f "Cargo.toml" ]; then
        cargo fetch || echo "⚠️  Cargo fetch failed (dependencies may need to be added)"
    fi

    echo ""
    echo "✅ Setup complete!"
    echo ""
    echo "🎯 Next steps:"
    echo "  1. Run 'cargo check' to verify the project compiles"
    echo "  2. Run 'cargo build' to build the project"
    echo "  3. Run 'cargo test' to run tests"
    echo ""
    echo "eBPF-specific commands:"
    echo "  - 'cargo build --package buckwild-ebpf' to build eBPF programs"
    echo "  - 'sudo bpftool prog list' to list loaded eBPF programs"
    echo "  - 'sudo bpftool map list' to list eBPF maps"
    echo ""
else
    echo "⚠️  No project files found in /workspace"
    echo "   The workspace may not be mounted correctly"
    echo "   Expected: /workspace should contain the Buckwild project"
fi

# Set up git configuration hints
if ! git config --global user.name > /dev/null 2>&1; then
    echo "💡 Remember to configure git:"
    echo "   git config --global user.name \"Your Name\""
    echo "   git config --global user.email \"your.email@example.com\""
    echo ""
fi

echo "Happy coding! 🦀"
