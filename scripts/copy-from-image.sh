#!/bin/bash

# Script to copy files from a docker image to the host
# Usage: ./scripts/copy-from-image.sh <image_name> <container_name> <source_path> <dest_path>
# Example: ./scripts/copy-from-image.sh rpingmesh-cursor-controller-builder controller-temp /app/controller ./bin/

# Error handling function
cleanup() {
  local container_exists=$(docker ps -a --filter "name=$CONTAINER_NAME" --format "{{.Names}}" | grep -w "$CONTAINER_NAME" || true)
  if [ -n "$container_exists" ]; then
    echo "Removing temporary container"
    docker rm "$CONTAINER_NAME" > /dev/null || true
  fi
}

# Set trap to ensure cleanup happens even if script fails
trap cleanup EXIT

# Get arguments
IMAGE_NAME=$1
CONTAINER_NAME=$2
SOURCE_PATH=$3
DEST_PATH=$4

# Validate arguments
if [ -z "$IMAGE_NAME" ] || [ -z "$CONTAINER_NAME" ] || [ -z "$SOURCE_PATH" ] || [ -z "$DEST_PATH" ]; then
  echo "Error: Missing required arguments"
  echo "Usage: $0 <image_name> <container_name> <source_path> <dest_path>"
  exit 1
fi

# Ensure destination directory exists
mkdir -p $(dirname "$DEST_PATH")

# Create temporary container
echo "Creating temporary container from image: $IMAGE_NAME"
docker create --name "$CONTAINER_NAME" "$IMAGE_NAME" > /dev/null

# Copy the file
echo "Copying $SOURCE_PATH to $DEST_PATH"
docker cp "$CONTAINER_NAME:$SOURCE_PATH" "$DEST_PATH"

echo "Done."
