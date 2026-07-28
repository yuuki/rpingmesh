#!/usr/bin/env bash

set -e

cd "$(dirname "$0")/.."

# Check protoc installation
if ! command -v protoc &> /dev/null; then
    echo "Error: protoc compiler is not installed."
    echo "Please install Protocol Buffer Compiler."
    echo "See: https://grpc.io/docs/protoc-installation/"
    exit 1
fi

# Check protoc-gen-go installation
if ! command -v protoc-gen-go &> /dev/null; then
    echo "Installing protoc-gen-go..."
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
fi

# Check protoc-gen-go-grpc installation
if ! command -v protoc-gen-go-grpc &> /dev/null; then
    echo "Installing protoc-gen-go-grpc..."
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi

# Make the output directories if they don't exist
mkdir -p proto/controller_agent
mkdir -p proto/agent_analyzer

# Generate controller_agent proto
echo "Generating controller_agent code..."
protoc \
    --go_out=. \
    --go_opt=paths=source_relative \
    --go-grpc_out=. \
    --go-grpc_opt=paths=source_relative \
    proto/controller_agent/controller_agent.proto

# Generate agent_analyzer proto
echo "Generating agent_analyzer code..."
protoc \
    --go_out=. \
    --go_opt=paths=source_relative \
    --go-grpc_out=. \
    --go-grpc_opt=paths=source_relative \
    proto/agent_analyzer/agent_analyzer.proto

echo "Proto generation complete!"
