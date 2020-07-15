#!/bin/bash
BASE_DIR=${BASE_DIR:-./}
DOCKER_COMPOSE_FILE=${BASE_DIR}/docker/docker-compose.yml

#enable debug
set -x

running_testnet=$(docker network ls --filter=name=ripple-testnet --format "{{.Name}}" | head -n 1)

if [[ -n $running_testnet ]] ; then
  echo "Found a running ripple-testnet. Attaching the unl-publisher container to it."
else
  echo "The ripple-testnet docker network couldn't be found!"
  return 1;
fi;

TESTNET_NAME=${running_testnet} docker-compose -f ${DOCKER_COMPOSE_FILE} up -d

set +x
