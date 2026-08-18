#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"
set -euo pipefail

#
# Get the license file for the Curity Identity Server
#
if [ "$LICENSE_FILE_PATH" == '' ]; then
  echo '*** Please provide a LICENSE_FILE_PATH environment variable with the path to a Curity Identity Server license file'
  exit 1
fi

export LICENSE_KEY=$(cat "$LICENSE_FILE_PATH" | jq -r .License)
if [ "$LICENSE_KEY" == '' ]; then
  echo 'An invalid license file was provided for the Curity Identity Server'
  exit 1
fi

#
# Create SSL certificates if required
#
./gateway/certs/create.sh

#
# Trigger the deployment
#
docker pull curity.azurecr.io/curity/idsvr:latest
docker compose up --force-recreate
