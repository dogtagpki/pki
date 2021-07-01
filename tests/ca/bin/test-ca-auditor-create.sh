#!/bin/bash -ex

# create a user
pki -n caadmin ca-user-add caauditor --fullName "CA Auditor" --password Secret.123

# add the user to Auditors group
pki -n caadmin ca-user-membership-add caauditor "Auditors"

# test username and password
pki -u caauditor -w Secret.123 ca-audit-file-find
