#!/bin/bash -e

NAME=$1

if [ "$NAME" == "" ]
then
    echo "Usage: ds-container-remove.sh <name>"
    exit 1
fi

echo "Stopping DS container"

docker stop $NAME > /dev/null

echo "Removing DS container"

docker rm $NAME > /dev/null

echo "Removing DS volume"

docker volume rm $NAME-data > /dev/null

echo "DS container has been removed"
