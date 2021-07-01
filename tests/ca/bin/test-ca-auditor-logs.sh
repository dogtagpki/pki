#!/bin/bash -ex

# list of audit log files
pki -n caauditor ca-audit-file-find | sed -n "s/^\s*File name: \s*\(\S*\)$/\1/p" > /tmp/audit.filenames

# retrieve audit log files
for filename in `cat /tmp/audit.filenames`
do
    pki -n caauditor ca-audit-file-retrieve $filename
done
