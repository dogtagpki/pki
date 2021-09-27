#!/bin/bash -e

if [ "$NAME" == "" ]
then
    NAME=ds
fi

echo "Stopping DS container"

docker stop $NAME > /dev/null

echo "Removing DS container"

docker rm $NAME > /dev/null

echo "DS container has been removed"
