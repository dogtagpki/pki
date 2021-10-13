#!/bin/bash

INSTANCE=localhost
OUTPUT=

while getopts v-: arg ; do
    case $arg in
    -)
        LONG_OPTARG="${OPTARG#*=}"

        case $OPTARG in
        instance=?*)
            INSTANCE="$LONG_OPTARG"
            ;;
        output=?*)
            OUTPUT="$LONG_OPTARG"
            ;;
        '')
            break # "--" terminates argument processing
            ;;
        instance* | output*)
            echo "ERROR: Missing argument for --$OPTARG option" >&2
            exit 1
            ;;
        *)
            echo "ERROR: Illegal option --$OPTARG" >&2
            exit 1
            ;;
        esac
        ;;
    \?)
        exit 1 # getopts already reported the illegal option
        ;;
    esac
done

# remove parsed options and args from $@ list
shift $((OPTIND-1))

NAME=$1

if [ "$OUTPUT" == "" ]
then
    OUTPUT=/tmp/artifacts/$NAME
fi

docker exec $NAME ls -la /etc/dirsrv
mkdir -p $OUTPUT/etc
docker cp $NAME:/etc/dirsrv $OUTPUT/etc

docker exec $NAME ls -la /var/log/dirsrv
mkdir -p $OUTPUT/var/log
docker cp $NAME:/var/log/dirsrv $OUTPUT/var/log

mkdir -p $OUTPUT/var/log/dirsrv/slapd-$INSTANCE
docker exec $NAME journalctl -u dirsrv@$INSTANCE.service > $OUTPUT/var/log/dirsrv/slapd-$INSTANCE/systemd.log

docker logs $NAME > $OUTPUT/var/log/dirsrv/slapd-$INSTANCE/container.log 2>&1
