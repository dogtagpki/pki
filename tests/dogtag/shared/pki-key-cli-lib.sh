#!/bin/sh
#Include below files
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/env.sh
#  PKI KEY SHARED LIBRARY
#######################################################################
# Includes:
#
#       generate_approved symmetric key
######################################################################

#####################################################################
#generate_approve_key() accepts parameters:
#client-ID, algorithm, keysize, usages, action, kra_host, krap_port
#agent_cert_nick, output file where the output is saved
#####################################################################
generate_key()
{
        local client_id=$1
        local algo=$2
        local key_size=$3
        local usages=$4
        local action=$5
        local tmp_kra_host=$6
        local target_port=$7
        local valid_agent_cert=$8
        local key_generate_output=$9
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
		-p $target_port \
		-h $tmp_kra_host \
		-n \"$valid_agent_cert\" \
		key-generate $client_id \
		--key-algorithm $algo \
		--key-size $key_size \
		--usages $usages > $key_generate_output" 0 "Generate Symmetric Key for client id $client_id"
        local key_request_id=$(cat $key_generate_output | grep "Request ID:" | awk -F ": " '{print $2}')
	if [ "$action" == "approve" ] || [ "$action" == "reject" ] || [ "$action" == "cancel" ]; then
	        rlRun "pki -d $CERTDB_DIR \
        	         -c $CERTDB_DIR_PASSWORD \
			 -h $tmp_kra_host \
			 -p $target_unsecure_port \
        	         -n \"$valid_agent_cert\" \
                	 key-request-review $key_request_id \
	                 --action $action > $key_generate_output" 0 "$action $key_request_id"
	fi

}
archive_passphrase()
{
        local client_id=$1
	local passphrase=$2
        local action=$3
        local tmp_kra_host=$4
        local target_port=$5
        local valid_agent_cert=$6
        local key_archive_output=$7
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_kra_host \
                -p $target_port \
                -n \"$valid_agent_cert\" \
                key-archive --clientKeyID $client_id \
                 --passphrase $passphrase > $key_archive_output" 0 "Archive $passphrase in DRM"
	local passphrase_request_id=$(cat $key_archive_output | grep "Request ID:" | awk -F ": " '{print $2}')
	if [ "$action" == "approve" ] || [ "$action" == "reject" ] || [ "$action" == "cancel" ]; then
	        rlLog "Approve Key request id $tmp_request_id"
        	rlRun "pki -d $CERTDB_DIR \
                	-c $CERTDB_DIR_PASSWORD \
	                -h $tmp_kra_host \
        	        -p $target_port \
                	-n \"$valid_agent_cert\" \
	                key-request-review $passphrase_request_id --action $action > $key_archive_output"
	fi
}
