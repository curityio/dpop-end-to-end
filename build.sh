#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"
set -euo pipefail

#
# Build the custom API gateway Docker image
#
cd gateway
docker build --no-cache -t custom-api-gateway:1.0 .
cd ..

#
# Build the example API Docker image
#
cd api
npm install
npm run build
docker build --no-cache -t example-api:1.0 .
cd ..
