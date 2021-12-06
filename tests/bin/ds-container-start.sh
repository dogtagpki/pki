#!/bin/bash

# https://fy.blackhats.net.au/blog/html/2020/03/28/389ds_in_containers.html

NAME=$1

if [ "$NAME" == "" ]
then
    echo "Usage: ds-container-start.sh <name>"
    exit 1
fi

if [ "$PASSWORD" == "" ]
then
    PASSWORD=Secret.123
fi

if [ "$MAX_WAIT" == "" ]
then
    MAX_WAIT=60 # seconds
fi

echo "Starting DS container"
start_time=$(date +%s)

if [ "$IMAGE" == "" ]
then
    docker exec $NAME dsctl localhost start
else
    docker start $NAME > /dev/null
fi

if [ $? -ne 0 ]
then
    exit 1
fi

HOSTNAME=$(docker exec $NAME uname -n)

while :
do
    sleep 1

    docker exec $NAME \
        ldapsearch \
        -H ldap://$HOSTNAME:3389 \
        -D "cn=Directory Manager" \
        -w $PASSWORD \
        -x \
        -b "" \
        -s base > /dev/null 2> /dev/null

    if [ $? -eq 0 ]
    then
        break
    fi

    current_time=$(date +%s)
    elapsed_time=$(expr $current_time - $start_time)

    if [ $elapsed_time -ge $MAX_WAIT ]
    then
        echo "DS container did not start after ${MAX_WAIT}s"
        exit 1
    fi

    echo "Waiting for DS container to start (${elapsed_time}s)"
done

echo "DS container is started"
