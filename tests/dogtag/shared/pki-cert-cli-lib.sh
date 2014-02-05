#!/bin/sh

########################################################################
#  PKI CERT SHARED LIBRARY
#######################################################################
# Includes:
#
#	generate_PKCS10
######################################################################
#######################################################################

#########################################################################
# create_certdb  Usage:
#       create_certdb <location of certdb> <certdb_password>
#######################################################################

create_certdb()
{
	local certdb_loc=$1
        local certdb_pwd=$2
        rlLog "certdb_loc = $certdb_loc"
        rlRun "mkdir $certdb_loc"
        rlRun "echo \"$certdb_pwd\" > $certdb_loc/passwd_certdb"
        rlRun "certutil -d $certdb_loc -N -f $certdb_loc/passwd_certdb"
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

#########################################################################
# generate_PKCS10 Usage:
#	generate_PKCS10 <location of certdb> <certdb_password> <algorithm> <rsa key length> <output file> <subjectDN>
#######################################################################

generate_PKCS10()
{
	local certdb_loc=$1
	local certdb_pwd=$2
	local algorithm=$3
	local rsa_key_length=$4
	local output_file=$5
	local subjectDN=$6
	local rc=0
	exp=$certdb_loc/../expfile.out
	tmpout=$certdb_loc/../tmpout.out

	local cmd="PKCS10Client -p $certdb_pwd -d $certdb_loc -a $algorithm -l $rsa_key_length -o $output_file -n $subjectDN"
	rlLog "Executing: $cmd"
        rlRun "$cmd" 0 "Creating PKCS10 request"
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
##############################
#
#Function Usage create_cert <Temporary NSS DB Directory> <NSS DB Directory Password> <pkcs10/crmf> <rsa/ec> <cn> <uid> <email> 
#<organizationalUnit> <organization> <country> <profilename> <return_status> <return_id> <return_dn>
#return_status, return_id & return_dn are return variables emitting out Status of the request, Request id & Request DN Submitted
#
#TODO: Currently we have implemented only for caUserCert profile, Need to extend for other profiles
#CRMF Request needs to be generated
#############################
create_cert_request()
{
local dir=$1
local password=$2
local request_type=$3
local algo=$4
local key_size=$5
local cn="$6"
local uid="$7"
local email="$8"
local ou="$9"
local organization="${10}"
local country="${11}"
local profilename="${12}"
local request_status="${13}"
local request_id="${14}"
local cert_subject="${15}"
local rand=`cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1`

#### First we create  NSS Database

	if [ -d "$dir" ]
	then
		rlLog "$dir Directory exists"
	else
		rlLog "Creating Security Database"
		rlRun "pki -d $dir -c $password client-init" 0 "Initializing Security Database"

		RETVAL=$?
		if  [ $RETVAL != 0 ]; then
		  rlLog "FAIL :: NSS Database was not created"
		fi
	fi

### Construct Subject based on $6,$7,$8,$9,$10,$11

	if [ "$cn" == "--" ]; then
		cn="pkiuser$rand"
	fi
	if [ "$uid" == "--" ]; then
	        uid=$cn
	fi
	if [ "$email" == "--" ]; then
	        email="$cn@example.org"
	fi
	if [ "$ou" == "--" ]; then
	        ou="Engineering"
	fi
	if [ "$organization" == "--" ]; then
	        organization="Example.Inc"
	fi
	if [ "$country" == "--" ]; then
	        country="US"
	fi
	if [ "$profilename" == "--" ]; then
		profilename=caUserCert
	fi
#### Generate request

	local cert_request_file="cert-request-$rand.pem"
	local $cert_request_file-sumbit.out

	subject="CN=$cn,UID=$uid,E=$email,OU=$ou,O=$organization,C=$country"

	rlLog "Generating PKCS10 Request for $subject"
	rlRun "PKCS10Client -p $password -d $dir -a $algo -l $key_size -o $dir/$cert_request_file -n \"$subject\""
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
        rlLog "Create of PKCS10 Request failed for $subject"
	fi

#### Strip  headers from request

	rlLog "Stripping headers from the $cert_request_file"
	rlRun "sed -e '/-----BEGIN NEW CERTIFICATE REQUEST-----/d' -i $dir/$cert_request_file"
	rlRun "sed -e '/-----END NEW CERTIFICATE REQUEST-----/d' -i $dir/$cert_request_file"
	
### use dos2unix to convert the request to unix format 

	rlLog "Converting $cert_request_file to unix format to strip CRLF lines"
	rlRun "dos2unix $dir/$cert_request_file" 0 
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "FAIL :: Convert to UNIX format failed"
	fi

### Get the xml profile from the argument "profliename", in future, we have implement this with switch case. so that it can be extended to other profiles.
	
	local xml_profile_file=$dir/$cert_request_file_$profilename.xml

	rlLog "Getting the $profilename XML file to submit the request"

	rlRun "pki -d $dir -c $password cert-request-profile-show $profilename --output $xml_profile_file"
	pid=$!
	wait=$pid
	if [ $? != 0 ]; then
		rlLog "FAIL :: We have some problem getting $profile xml"
	fi 
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v 'pkcs10' $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $dir/$cert_request_file)\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_uid']/Value\" -v \"$uid\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_e']/Value\" -v \"$email\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v \"$cn\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_ou']/Value\" -v \"$ou\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_o']/Value\" -v \"$organization\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_c']/Value\" -v \"$country\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$cn\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$email\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"

#### submit the request to CA 

	rlLog "Submit PKCS10 Request to CA"
	rlRun "pki cert-request-submit $xml_profile_file >> $dir/$cert_request_file-sumbit.out" 0 "Submit Request"
	RETVAL=$?
        if [ $RETVAL != 0 ]; then
                rlLog "We have some problem getting $profile xml"
        fi

	local REQUEST_SUBMIT_STATUS=`cat $dir/$cert_request_file-sumbit.out | grep "Operation Result" | awk -F ": " '{print $2}'`
	eval $request_status="$REQUEST_SUBMIT_STATUS"
	rlLog "Certificate Request was $request_status"
	local REQUEST_ID=`cat $dir/$cert_request_file-sumbit.out  | grep "Request ID" | awk -F ": " '{print $2}'`
	eval $request_id="$REQUEST_ID"		
	rlLog "Request id : $request_id"
	local CERT_SUBJ=$subject
	eval $cert_subject="$CERT_SUBJ"
	rlLog "Certificate Request DN: $cert_subject"
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
