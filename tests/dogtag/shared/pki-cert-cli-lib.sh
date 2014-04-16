#!/bin/sh
#Include below files
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/env.sh
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
#Function Usage create_cert <Temporary NSS DB Directory> <NSS DB Directory Password> <pkcs10/crmf> <rsa/ec> <cn> <uid> <email> 
#<organizationalUnit> <organization> <country> <profilename> <return_status> <return_id> <return_dn>
#return_status, return_id & return_dn are return variables emitting out Status of the request, Request id & Request DN Submitted
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
local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)

#### First we create  NSS Database

	if [ -d "$dir" ]
	then
		rlLog "$dir Directory exists"
	else
		rlLog "Creating Security Database"
		rlRun "pki -d $dir -c $password client-init" 0 "Initializing Security Database"
		RETVAL=$?
		if  [ $RETVAL != 0 ]; then
		  rlFail "FAIL :: NSS Database was not created"
		  return 1
		fi
	fi

### Construct Subject based on $6,$7,$8,$9,$10,$11

	if [ "$cn" == "--" ]; then
		cn="pkiuser$rand"
	fi
	if [ "$uid" == "--" ] && [ "$uid" != " " ]; then
	        uid=$cn
	fi
	if [ "$email" == "--" ] && [ "$email" != " " ]; then
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
	local cert_request_file_sumbit="$cert_request_file-submit.out"

	if [ "$uid" != "" ] && [ "$email" != "" ]; then
		local subject="UID=$uid,E=$email,CN=$cn,OU=$ou,O=$organization,C=$country"
	else
		local subject="CN=$cn,OU=$ou,O=$organization,C=$country"
	fi

	if [ "$request_type" == "pkcs10" ];then
		rlRun "PKCS10Client -p $password -d $dir -a $algo -l $key_size -o $dir/$cert_request_file -n \"$subject\" 1> $dir/pkcs10.out" 0 "Generating PKCS10 Request for $subject"
		RETVAL=$?
		if [ $RETVAL != 0 ]; then
			rlFail "Create of PKCS10 Request failed for $subject"
			return 1
		fi
	fi
	if [ "$request_type" == "crmf" ] && [ "$profilename" != "caDualCert" ];then
		rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/usr/share/java/pki/pki-silent.jar:/opt/rhqa_pki/java/generateCRMFRequest.jar:\"" 0 "Setting Java CLASSPATH"
		rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
		rlRun "java -cp $CLASSPATH generateCRMFRequest -client_certdb_dir $dir -client_certdb_pwd $password -debug false -request_subject \"$subject\" -request_keytype $algo -request_keysize $key_size -output_file $dir/$cert_request_file 1> $dir/crmf.out" 0 "Execute generateCRMFRequest to generate CRMF Request"
	fi
	if [ "$request_type" == "crmf" ] && [ "$profilename" == "caDualCert" ];then
		rlRun "cat $CA_SERVER_ROOT/conf/CS.cfg | grep ca.connector.KRA.transportCert | awk -F \"=\" '{print \$2}' > transport.txt" 0 "Get Transport Cert"
		rlRun "CRMFPopClient -d $dir -p $password -o $dir/$cert_request_file -n \"$subject\" -a $algo -l $key_size -u $uid -r $uid 1> $dir/CRMFPopClient.out" 0 "Executing CRMFPopClient"
		RETVAL=$?
		if [ $RETVAL != 0 ]; then
			rlFail "CRMFPopClient Failed"
			return 1
		fi
	fi
#### Strip  headers from request
#### Note for CRMF requests Our class doesn't generate the headers

	if [ "$request_type" == "pkcs10" ] || [ "$profilename" == "caDualCert" ]; then

		rlLog "Stripping headers from the $cert_request_file"
		rlRun "sed -e '/-----BEGIN NEW CERTIFICATE REQUEST-----/d' -i $dir/$cert_request_file"
		rlRun "sed -e '/-----END NEW CERTIFICATE REQUEST-----/d' -i $dir/$cert_request_file"
	fi
	
### use dos2unix to convert the request to unix format 
	rlRun "dos2unix $dir/$cert_request_file" 0 "Converting $cert_request_file to unix format to strip CRLF lines" 
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlFail "FAIL :: Convert to UNIX format failed"
		return 1
	fi

### Get the xml profile from the argument "profliename", in future, we have implement this with switch case. so that it can be extended to other profiles.
	
	local xml_profile_file=$dir/$cert_request_file_$profilename.xml

	rlLog "Getting the $profilename XML file to submit the request"
	rlRun "pki -d $dir -c $password cert-request-profile-show $profilename --output $xml_profile_file"
	pid=$!
	wait $pid
	if [ $? != 0 ]; then
		rlLog "FAIL :: We have some problem getting $profile xml"
		return 1
	fi 

	if [ "$profilename" == "caUserCert" ]  || [ "$profilename" ==  "caUserSMIMEcapCert" ] || [ "$profilename" ==  "caDualCert" ];then
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
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
	fi
	
	if [ "$profilename" != "CaDualCert" ] || \
	[ "$profilename" != "caDirPinUserCert" ] || \
	[ "$profilename" != "caDirUserCert" ] || \
	[ "$profilename" != "caECDirUserCert" ] || \
	[ "$profilename" != "caAgentServerCert" ] && \
        [ "$profilename" != "caUserCert" ]; then
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $dir/$cert_request_file)\" $xml_profile_file"
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v \"$cn\" $xml_profile_file"
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$cn\" $xml_profile_file"
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$email\" $xml_profile_file"
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"
	fi
#### submit the request to CA 

	rlLog "Submit PKCS10 Request to CA"
	rlRun "pki cert-request-submit $xml_profile_file >> $dir/$cert_request_file_sumbit" 0 "Submit Request"
	RETVAL=$?
        if [ $RETVAL != 0 ]; then
                rlFail "We have some problem getting $profile xml"
		return 1
        fi

	local REQUEST_SUBMIT_STATUS=$(cat $dir/$cert_request_file_sumbit | grep "Operation Result" | awk -F ": " '{print $2}')
	eval "$request_status"="'$REQUEST_SUBMIT_STATUS'"
	rlLog "Certificate Request was $request_status"
	local REQUEST_ID=`cat $dir/$cert_request_file_sumbit  | grep "Request ID" | awk -F ": " '{print $2}'`
	eval "$request_id"="'$REQUEST_ID'"		
	rlLog "Request id : $request_id"
	eval "$cert_subject"="'$subject'"
	return 0 
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
create_new_cert_request()
{
	local dir=$(echo $1|cut -d: -f2)
	local password=$(echo $2|cut -d: -f2)
	local request_type=$(echo $3|cut -d: -f2)
	local algo=$(echo $4|cut -d: -f2)
	local key_size=$(echo $5|cut -d: -f2)
	local cn="$(echo $6|cut -d: -f2)"
	local uid="$(echo $7|cut -d: -f2)"
	local email="$(echo $8|cut -d: -f2)"
	local ou="$(echo $9|cut -d: -f2)"
	local organization="$(echo ${10}|cut -d: -f2)"
	local country="$(echo ${11}|cut -d: -f2)"
	local archive="$(echo ${12}|cut -d: -f2)"
	local cert_request_file="$(echo ${13}|cut -d: -f2)"
	local cert_subject_file="$(echo ${14}|cut -d: -f2)"
	local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)

#### First we create  NSS Database

	if [ -d "$dir" ]; then
	
		rlLog "$dir Directory exists"
	else
		rlLog "Creating Security Database"
		rlRun "pki -d $dir -c $password client-init" 0 "Initializing Security Database"
		RETVAL=$?
		if  [ $RETVAL != 0 ]; then
		  rlLog "FAIL :: NSS Database was not created"
		  return 1
		fi
	fi
	if [ "$cn" == "" ]; then
		cn="pkiuser$rand"
	fi
	if [ "$uid" == "" ] && [ "$cn" == pkiuser$rand ]; then
	        uid=$cn
	fi
	if [ "$email" == "" ] && [ "$cn" == pkiuser$rand ];then 
	        email="$cn@example.org"
	fi
	if [ "$ou" == "" ]; then
	        ou="Engineering"
	fi
	if [ "$organization" == "" ]; then
	        organization="Example.Inc"
	fi
	if [ "$country" == "" ]; then
	        country="US"
	fi
#### Generate request
	if [ "$uid" != "" ] && [ "$email" != "" ]; then
		#local subject="CN=$cn,UID=$uid,E=$email,OU=$ou,O=$organization,C=$country"
		local subject="UID=$uid,E=$email,CN=$cn,OU=$ou,O=$organization,C=$country"
	else
		local subject="CN=$cn,OU=$ou,O=$organization,C=$country"
	fi
	
	if [ "$request_type" == "pkcs10" ];then

		rlRun "PKCS10Client -p $password -d $dir -a $algo -l $key_size -o $cert_request_file -n \"$subject\" 1> $dir/pkcs10.out" 0
		RETVAL=$?
		if [ $RETVAL != 0 ]; then
			rLog "Create of PKCS10 Request failed for $subject"
			return 1
		fi
	fi
	if [ "$request_type" == "crmf" ] && [ "$archive" != "true" ];then
		rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/usr/share/java/pki/pki-silent.jar:/opt/rhqa_pki/java/generateCRMFRequest.jar:\"" 0 "Setting Java CLASSPATH"
		rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
		rlLog "Execute generateCRMFRequest to generate CRMF Request"
		rlRun "java -cp $CLASSPATH generateCRMFRequest -client_certdb_dir $dir -client_certdb_pwd $password -debug false -request_subject \"$subject\" -request_keytype $algo -request_keysize $key_size -output_file $cert_request_file 1> $dir/crmf.out" 0 "Execute generateCRMFRequest to generata CRMF Request"
	fi
	
	if [ "$request_type" == "crmf" ] && [ "$archive" == "true" ];then
		rlLog "Get Transport Cert"
		rlRun "cat $CA_SERVER_ROOT/conf/CS.cfg | grep ca.connector.KRA.transportCert | awk -F \"=\" '{print \$2}' > transport.txt"
		rlRun "CRMFPopClient  -d $dir -p $password -o $cert_request_file -n "$subject" -a $algo -l $key_size -u $uid -r $uid 1> $dir/CRMFPopClient.out" 0 "Executing CRMFPopClient"
		RETVAL=$?
                if [ $RETVAL != 0 ]; then
                        rlFail "CRMFPopClient Failed"
                        return 1
                fi
	fi
#### Strip  headers from request, Note for CRMF requests Our class doesn't generate the headers
	if [ "$request_type" == "pkcs10" ] || [ "$archive" == "false" ]; then

		rlLog "Stripping headers from the $cert_request_file"
		rlRun "sed -e '/-----BEGIN NEW CERTIFICATE REQUEST-----/d' -i $cert_request_file"
		rlRun "sed -e '/-----END NEW CERTIFICATE REQUEST-----/d' -i $cert_request_file"
	fi
	
### use dos2unix to convert the request to unix format 

	rlLog "Converting $cert_request_file to unix format to strip CRLF lines"
	rlRun "dos2unix $cert_request_file"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlFail "FAIL :: Convert to UNIX format failed"
		return 1
	fi
	echo -e "RequestType:$request_type" > $cert_subject_file
	echo -e "CN:$cn" >> $cert_subject_file
	echo -e "UID:$uid" >> $cert_subject_file
	echo -e "Email:$email" >> $cert_subject_file
	echo -e "OU:$ou" >> $cert_subject_file
	echo -e "Org:$organization" >> $cert_subject_file
	echo -e "Country:$country" >> $cert_subject_file
	echo -e "Request_DN:$subject" >> $cert_subject_file
	rlLog "Certificate Request file is saved in $cert_request_file"
	rlLog "Subject DN information for Certificate Requeset is saved in $cert_subject_file"
	return 0
}	

submit_new_request(){
	local dir=$(echo $1|cut -d: -f2)
	local dir_pwd=$(echo $2|cut -d: -f2)
	local target_host=$(echo $3|cut -d: -f2)
	local nickname=$(echo $4|cut -d: -f2)
	local protocol=$(echo $5|cut -d: -f2)
	local port=$(echo $6|cut -d: -f2)
	local url=$(echo $7|cut -d: -f2)
	local username=$(echo $8|cut -d: -f2)
	local userpwd=$(echo $9|cut -d: -f2)
	local profilename=$(echo ${10}|cut -d: -f2)
	local cert_request_file=$(echo ${11}|cut -d: -f2)
	local subj_request_file=$(echo ${12}|cut -d: -f2)
	local output_file=$(echo ${13}|cut -d: -f2)
	local request_type=$(cat $subj_request_file | grep "RequestType" | cut -d: -f2)
	local uid=$(cat $subj_request_file | grep ^"UID" | cut -d: -f2)
	local cn=$(cat $subj_request_file | grep ^"CN" | cut -d: -f2)
	local email=$(cat $subj_request_file | grep ^"Email" | cut -d: -f2)
	local ou=$(cat $subj_request_file | grep ^"OU" | cut -d: -f2)
	local organization=$(cat $subj_request_file | grep ^"Org" | cut -d: -f2)
	rlLog "organization=$organization"
	local country=$(cat $subj_request_file | grep ^"Country" | cut -d: -f2)
	local cert_request_dn=$(cat $subj_request_file | grep ^"Request_DN" | cut -d: -f2)
	local rand=$(cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1)


        if [ "$target_host" == "" ]; then
                target_host="$(hostname)"
        fi
        if [ "$protocol" == "" ]; then
                protocol="http"
        fi
        if [ "$port" == "" ]; then
                port=8080
        fi
        if [ "$profilename" == "" ]; then
		profilename="caUserCert"
        fi

	local xml_profile_file=$dir/$profilename-$rand.xml

	rlLog "Getting the $profilename XML file to submit the request"
	rlRun "pki -d $dir -h $target_host -p $port -c $dir_pwd cert-request-profile-show $profilename --output $xml_profile_file 1> $xml_profile_file-out" 
	if [ $? != 0 ]; then
		rlFail "FAIL :: We have some problem getting $profile xml"
		return 1
	fi 
	if [ "$profilename" == "caUserCert" ]  || [ "$profilename" ==  "caUserSMIMEcapCert" ] || [ "$profilename" ==  "caDualCert" ];then
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $cert_request_file)\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_uid']/Value\" -v \"$uid\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_e']/Value\" -v \"$email\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v \"$cn\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_ou']/Value\" -v \"$ou\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_o']/Value\" -v \"$organization\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_c']/Value\" -v \"$country\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$cn\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$email\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"
	fi

	 if [ "$profilename" != "CaDualCert" ] || \
        [ "$profilename" != "caDirPinUserCert" ] || \
        [ "$profilename" != "caDirUserCert" ] || \
        [ "$profilename" != "caECDirUserCert" ] || \
        [ "$profilename" != "caAgentServerCert" ] && \
	[ "$profilename" != "caUserCert" ]; then
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $cert_request_file)\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$cn\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$email\" $xml_profile_file"
	rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"
	fi
	
#### submit the request to CA 

	rlLog "Submiting  Request $target_host at $port"
	rlRun "pki -d $dir -c $dir_pwd -h $target_host -P $protocol -p $port cert-request-submit $xml_profile_file 1> $output_file"
	RETVAL=$?
        if [ $RETVAL != 0 ]; then
                rlFail "Could not submit request"
		return 1
		
        fi

        REQUEST_SUBMIT_STATUS=$(cat $output_file | grep "Operation Result" | awk -F ": " '{print $2}')
        REQUEST_ID=$(cat $output_file  | grep "Request ID" | awk -F ": " '{print $2}')

	echo -e "----------------------------------------" >> $output_file
	echo -e "REQUEST_ID_RETURNED:$REQUEST_ID" >> $output_file
	echo -e "REQUEST_SUBMIT_STATUS:$REQUEST_SUBMIT_STATUS" >> $output_file
	echo -e "REQUEST_DN:$cert_request_dn" >> $output_file
	echo -e "------------------------------------------" >> $output_file
	
	return 0;
}

generate_user_cert()
{
                local reqstatus
                local requestid
                local requestdn
                local CERT_INFO="$1"
                local file_no="$2"
                local user_id="$3"
                local userfullname="$4"
                local ext=".out"
                local cert_ext=".pem"
                local req_email="$5"
                local num="$7"
                local file_name="$6"
                        rlRun "create_cert_request $CERTDB_DIR redhat123 pkcs10 rsa 2048 \"$userfullname\" \"$user_id\" "$req_email" "Engineering" "Example" "US" "--" "reqstatus" "requestid" "requestdn""

                rlRun "pki cert-request-show $requestid > $TmpDir/$file_name-CA_certrequestshow_00$file_no$num$ext" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/$file_name-CA_certrequestshow_00$file_no$num$ext"
                rlAssertGrep "Type: enrollment" "$TmpDir/$file_name-CA_certrequestshow_00$file_no$num$ext"
                rlAssertGrep "Status: pending" "$TmpDir/$file_name-CA_certrequestshow_00$file_no$num$ext"
                rlAssertGrep "Operation Result: success" "$TmpDir/$file_name-CA_certrequestshow_00$file_no$num$ext"

                #Agent Approve the certificate after reviewing the cert for the user
                rlLog "Executing: pki -d $CERTDB_DIR/ \
                                      -n CA_agentV \
                                      -c $CERTDB_DIR_PASSWORD \
                                      -t ca \
                                      cert-request-review --action=approve $requestid"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_agentV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                           cert-request-review --action=approve $requestid > $TmpDir/$file_name-CA_certapprove_00$file_no$num$ext" \
                           0 \
                           "CA agent approve the cert"
                rlAssertGrep "Approved certificate request $requestid" "$TmpDir/$file_name-CA_certapprove_00$file_no$num$ext"
                rlRun "pki cert-request-show $requestid > $TmpDir/$file_name-CA_certapprovedshow_00$file_no$num$ext" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/$file_name-CA_certapprovedshow_00$file_no$num$ext"
                rlAssertGrep "Type: enrollment" "$TmpDir/$file_name-CA_certapprovedshow_00$file_no$num$ext"
                rlAssertGrep "Status: complete" "$TmpDir/$file_name-CA_certapprovedshow_00$file_no$num$ext"
                rlAssertGrep "Certificate ID:" "$TmpDir/$file_name-CA_certapprovedshow_00$file_no$num$ext"
                local certificate_serial_number=`cat $TmpDir/$file_name-CA_certapprovedshow_00$file_no$num$ext | grep "Certificate ID:" | awk '{print $3}'`
                rlLog "Cerificate Serial Number=$certificate_serial_number"
                #Verify the certificate is valid
                rlRun "pki cert-show  $certificate_serial_number --encoded > $TmpDir/$file_name-CA_certificate_show_00$file_no$num$ext" 0 "Executing pki cert-show $certificate_serial_number"

                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/$file_name-CA_certificate_show_00$file_no$num$ext > $TmpDir/$file_name-CA_validcert_00$file_no$num$cert_ext"
                 rlRun "certutil -d $CERTDB_DIR -A -n \"$user_id\" -i $TmpDir/$file_name-CA_validcert_00$file_no$num$cert_ext  -t "u,u,u""
                echo cert_serialNumber-$certificate_serial_number > $CERT_INFO
                echo cert_requestdn-$requestdn >> $CERT_INFO
                return 0;

}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
