#!/bin/bash
set -e

# Add any post-creation steps here
echo "Setting up RpingMesh development environment..."

# Verify Go installation
go version

# Set up environment variables
cat <<EOF >> ~/.bashrc

# RpingMesh Environment
export PATH=\$PATH:/go/bin
export GOPATH=/go
export GO111MODULE=on
EOF

# Set up fish shell environment (if needed)
if command -v fish &> /dev/null; then
    mkdir -p ~/.config/fish
    cat <<EOF >> ~/.config/fish/config.fish

# RpingMesh Environment
set -gx PATH \$PATH /go/bin
set -gx GOPATH /go
set -gx GO111MODULE on
EOF
fi

echo "Installing Claude Code..."
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
npm install -g @anthropic-ai/claude-code

# Find the workspace directory
WORKSPACE_DIR=${WORKSPACE_DIR:-$(pwd)}
echo "Workspace directory: $WORKSPACE_DIR"

if [ -f "$WORKSPACE_DIR/go.mod" ]; then
    cd "$WORKSPACE_DIR"
    echo "Found go.mod in $WORKSPACE_DIR"

    # Check for eBPF directory
    if [ -d "$WORKSPACE_DIR/internal/ebpf" ]; then
        echo "Found eBPF directory, running go generate"
        cd "$WORKSPACE_DIR/internal/ebpf"
        go generate ./... || echo "Warning: Failed to generate eBPF bindings. You may need to set the correct KERNEL_VERSION environment variable."
    else
        echo "eBPF directory not found at $WORKSPACE_DIR/internal/ebpf, skipping go generate"
    fi

    # Go back to project root and run go mod tidy
    cd "$WORKSPACE_DIR"
    go mod tidy
else
    echo "go.mod not found in $WORKSPACE_DIR - this may not be the project root"
    echo "Skipping go mod tidy and eBPF generation"
    echo "Current directory contents:"
    ls -la
fi

echo "Development environment setup complete!"
