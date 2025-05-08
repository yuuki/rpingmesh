#!/bin/bash
set -e

IMAGE_NAME="rpingmesh-agent"
VERSION="0.1.0"
TAG="${IMAGE_NAME}:${VERSION}"

# Parse command line arguments
BUILD=true
RUN=false
PRIVILEGED=true
CONFIG_PATH=""

function show_help {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --no-build      Skip building the Docker image"
    echo "  --run           Run the Docker container after building"
    echo "  --no-privileged Run container without privileged mode (eBPF won't work)"
    echo "  --config PATH   Path to config file (defaults to ./agent.yaml)"
    echo "  --help          Show this help message"
}

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --no-build)
            BUILD=false
            shift
            ;;
        --run)
            RUN=true
            shift
            ;;
        --no-privileged)
            PRIVILEGED=false
            shift
            ;;
        --config)
            CONFIG_PATH="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Build the Docker image
if $BUILD; then
    echo "Building Docker image: $TAG"
    docker build -t $TAG .
    echo "Build completed successfully"
fi

# Run the Docker container if requested
if $RUN; then
    echo "Running Docker container from image: $TAG"

    # Set privileged flag if needed
    PRIVILEGED_FLAG=""
    if $PRIVILEGED; then
        PRIVILEGED_FLAG="--privileged"
    fi

    # Set config volume if provided
    CONFIG_VOLUME=""
    CONFIG_ARG=""
    if [ -n "$CONFIG_PATH" ]; then
        CONFIG_VOLUME="-v $(realpath $CONFIG_PATH):/app/config.yaml"
        CONFIG_ARG="--config /app/config.yaml"
    fi

    # Run with necessary capabilities for eBPF and RDMA
    docker run -it --rm \
        $PRIVILEGED_FLAG \
        --cap-add SYS_ADMIN \
        --cap-add NET_ADMIN \
        --cap-add IPC_LOCK \
        --network host \
        $CONFIG_VOLUME \
        $TAG $CONFIG_ARG
fi
