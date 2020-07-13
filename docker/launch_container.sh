#! /bin/bash

SRC_PATH=${SRC_PATH:-$(pwd)}
CONTAINER_NAME=xrpl-unl-manager

# check if it's already running
if [ ! -e $(docker container ls -qa --filter=name=${CONTAINER_NAME}) ]; then
  echo "Container ${CONTAINER_NAME} is already running"
  echo "Exitting"
else
  docker run -it --rm --name ${CONTAINER_NAME} \
            -v ${SRC_PATH}:/app \
            --workdir /app \
            --entrypoint /app/docker/init_container.sh \
            python:3 /bin/bash
fi

#docker run -it --rm --name ${CONTAINER_NAME} \
#            -v ${SRC_PATH}:/app \
#            --workdir /app \
#            python:3 /bin/bash


