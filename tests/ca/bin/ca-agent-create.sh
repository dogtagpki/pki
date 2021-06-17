#!/bin/bash -ex

# create a user
pki -n caadmin ca-user-add caagent --fullName "CA Agent" --password Secret.123

# add the user to agent group
pki -n caadmin ca-user-membership-add caagent "Certificate Manager Agents"

# test the username and password
pki -u caagent -w Secret.123 ca-cert-request-find
