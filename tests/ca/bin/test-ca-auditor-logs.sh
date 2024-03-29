#!/bin/bash -ex

# list of audit log files
pki -u caauditor -w Secret.123 ca-audit-file-find | sed -n "s/^\s*File name: \s*\(\S*\)$/\1/p" > /tmp/audit.filenames

# retrieve audit log files
for filename in `cat /tmp/audit.filenames`
do
    pki -u caauditor -w Secret.123 ca-audit-file-retrieve $filename
done
