#!/bin/bash

CURRENT_JOB_ID=$1

OLD_JOB_ID=""

BEAKER_DIR="`cd ../../../; pwd`/beaker"

if [ ! -d $BEAKER_DIR ] ; then
    mkdir $BEAKER_DIR
fi

rm -rf $BEAKER_DIR/regressions.txt

if [ -f $BEAKER_DIR/last_beaker_run ] ; then
    OLD_JOB_ID=`cat $BEAKER_DIR/last_beaker_run`
else
    echo $CURRENT_JOB_ID > $BEAKER_DIR/last_beaker_run
    exit 0
fi

bkr job-results --prettyxml "J:$CURRENT_JOB_ID" > $BEAKER_DIR/logsxml.new

bkr job-results --prettyxml "J:$OLD_JOB_ID" > $BEAKER_DIR/logsxml.old

rm -rf $BEAKER_DIR/last_beaker_run

echo $CURRENT_JOB_ID > $BEAKER_DIR/last_beaker_run

python find_regressions.py $BEAKER_DIR/logsxml.old $BEAKER_DIR/logsxml.new

if [ $? -gt 0 ] ; then
   echo "No Regressions Found."
   exit 0
fi

mv regressions.txt $BEAKER_DIR/
