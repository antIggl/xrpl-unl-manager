#!/bin/bash
BASE_DIR=${BASE_DIR:-./}
DOCKER_COMPOSE_FILE=${BASE_DIR}/docker/docker-compose.yml
TESTNET_NAME=${TESTNET_NAME:-""}


VALIDATORS_KEYS_PATH=${VALIDATORS_KEYS_PATH:-"${BASE_DIR}/validators-config/"}
UNL_PUBLISHER_CONTAINER_NAME=${UNL_PUBLISHER_CONTAINER_NAME:-xrpl-unl-publisher}
UNL_SCENARIO_FILE=${UNL_SCENARIO_FILE:-"${BASE_DIR}/sample-unl-scenario.json"}
UNL_MANAGER_KEYFILE=${UNL_MANAGER_KEYFILE:-"${BASE_DIR}/unl-manager-token.txt"}

#enable debug
set -x

if [[ -n $TESTNET_NAME ]]; then
  running_testnet=$TESTNET_NAME
else
  running_testnet=$(docker network ls --filter=name=${TESTNET_NAME} --format "{{.Name}}" | head -n 1)
fi;

if [[ -n $running_testnet ]] ; then
  echo "Found a running ripple-testnet. Attaching the unl-publisher container to it."
else
  echo "The ripple-testnet docker network couldn't be found!"
  return 1;
fi;

existing_UNL_publisher_volume=$(docker volume ls --filter=name=xrpl-unls-root --format "{{.Name}}" | head -n 1)

if [[ -n $existing_UNL_publisher_volume ]] ; then
  echo "Found an UNL publisher volume. Using it."
else
  echo "Creating UNL publisher volume..."
  docker volume create xrpl-unls-root
fi;


TESTNET_NAME=${running_testnet} UNL_PUBLISHER_CONTAINER_NAME=$UNL_PUBLISHER_CONTAINER_NAME \
UNL_PUBLISHER_CONFIG=${BASE_DIR}/docker/nginx/conf.d \
UNL_MANAGER_APP_ROOT=${BASE_DIR} \
UNL_MANAGER_CONFIGFILE=${BASE_DIR}/unl-manager-docker.conf \
UNL_SCENARIO_FILE=${UNL_SCENARIO_FILE} \
UNL_MANAGER_KEYFILE=${UNL_MANAGER_KEYFILE} \
VALIDATORS_KEYS_PATH=${VALIDATORS_KEYS_PATH} \
    docker-compose -f ${DOCKER_COMPOSE_FILE} up -d



echo "Waiting for everything goes up..."
sleep 3

if [[ -n $(docker container ls -q --filter=name=${UNL_PUBLISHER_CONTAINER_NAME}) ]]; then
  echo "   ${UNL_PUBLISHER_CONTAINER_NAME} is running.  OK"
  echo "  UNL manager container log: $(docker container logs xrpl-unl-manager)"
else;
  echo "   ${UNL_PUBLISHER_CONTAINER_NAME} is not running.  FAIL!"
fi;


set +x
