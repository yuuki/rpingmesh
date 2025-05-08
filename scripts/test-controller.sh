#!/bin/bash
set -e

# Clean up containers on script exit
cleanup() {
  echo "Cleaning up containers..."
  docker-compose -f docker-compose.test.yml down
}
trap cleanup EXIT

# Change current directory to project root
cd "$(dirname "$0")/.."

# Stop and remove existing containers if any
docker-compose -f docker-compose.test.yml down -v

# Run tests
echo "Starting registry unit tests in Docker..."
docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from controller_test

# No need to manually get exit code - the --exit-code-from flag will propagate it
exit $?
