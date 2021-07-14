#! /bin/bash

SRC_PATH=${SRC_PATH:-$(pwd)}
CONTAINER_NAME=xrpl-unl-manager-2
UNL_SCENARIO_FILE=$(realpath ../unl-scenario.json)
UNL_MANAGER_KEYFILE=$(realpath ../configfiles/unl-manager/validator-token.txt)
VALIDATORS_KEYS_PATH=$(realpath ../configfiles/)

# check if it's already running
if [ ! -e $(docker container ls -qa --filter=name=${CONTAINER_NAME}) ]; then
  echo "Container ${CONTAINER_NAME} is already running"
  echo "Exitting"
else
  # docker run -it --rm --name ${CONTAINER_NAME} \
  #           -v ${SRC_PATH}:/app \
  #           --workdir /app \
  #           --entrypoint /app/docker/init_container.sh \
  #           python:3 /bin/bash


  docker run -it --rm --name ${CONTAINER_NAME} \
      -v xrpl-unls-root:/working_dir/publish/ \
      -v ${UNL_MANAGER_APP_ROOT:-$(pwd)}:/app/ \
      -v ${UNL_MANAGER_CONFIGFILE:-$(pwd)/unl-manager-docker.conf}:/working_dir/unl-manager.conf \
      -v ${UNL_SCENARIO_FILE:-$(pwd)/unl-scenario.json}:/working_dir/unl-scenario.json \
      -v ${UNL_MANAGER_KEYFILE:-$(pwd)/validator-token.txt}:/working_dir/unlmanager-token.txt \
      -v ${VALIDATORS_KEYS_PATH:-$(pwd)/validators-config/}:/working_dir/validators-config/ \
      -e UNL_MANAGER_CONFIGFILE:/working_dir/unl-manager.conf \
      -e UNL_VISUALIZATION_PATH:/working_dir/publish/graph/   \
      -e UNL_VISUALIZATION_FORMAT:"dot" \
      --workdir /app \
      --entrypoint /app/docker/init_container.sh \
      python:3 /bin/bash
fi

