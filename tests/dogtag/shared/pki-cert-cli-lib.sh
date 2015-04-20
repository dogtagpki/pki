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
        rlRun "mkdir -p $certdb_loc"
        rlRun "echo \"$certdb_pwd\" > $certdb_loc/passwd_certdb"
	certutil -L -d $certdb_loc
        if [ $? = 0 ]; then

                rlLog "$certdb_loc already exists"
        else
                rlRun "certutil -d $certdb_loc -N -f $certdb_loc/passwd_certdb"
        fi
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
local cert_subject="${17}"
local host="${15}"
local port="${16}"
local rand=$RANDOM
local prefix="${18}"

#### First we create  NSS Database
	rlLog "In create_cert"
	if [ -d "$dir" ]
	then
		rlLog "$dir Directory exists"
	else
		rlLog "Creating Security Database"
		rlLog "pki -d $dir -c $password -h $host -p $port client-init" 0 "Initializing Security Database"
		rlRun "pki -d $dir -c $password -h $host -p $port client-init" 0 "Initializing Security Database"
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
		rlLog "PKCS10Client -p $password -d $dir -a $algo -l $key_size -o $dir/$cert_request_file -n \"$subject\""
		rlRun "PKCS10Client -p $password -d $dir -a $algo -l $key_size -o $dir/$cert_request_file -n \"$subject\" 1> $dir/pkcs10.out" 0 "Generating PKCS10 Request for $subject"
		RETVAL=$?
		if [ $RETVAL != 0 ]; then
			rlFail "Create of PKCS10 Request failed for $subject"
			return 1
		fi
	fi
	if [ "$request_type" == "crmf" ] && [ "$profilename" != "caDualCert" ];then
		rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
		rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
		rlLog "Executing java -cp"
		rlLog "java -cp $CLASSPATH generateCRMFRequest -client_certdb_dir $dir -client_certdb_pwd $password -debug false -request_subject \"$subject\" -request_keytype $algo -request_keysize $key_size -output_file $dir/$cert_request_file 1> $dir/crmf.out"
		rlRun "java -cp $CLASSPATH generateCRMFRequest -client_certdb_dir $dir -client_certdb_pwd $password -debug false -request_subject \"$subject\" -request_keytype $algo -request_keysize $key_size -output_file $dir/$cert_request_file 1> $dir/crmf.out" 0 "Execute generateCRMFRequest to generate CRMF Request"
	fi
	if [ "$request_type" == "crmf" ] && [ "$profilename" == "caDualCert" ];then
		rlRun "cat $(eval echo \$${prefix}_SERVER_ROOT)/conf/CS.cfg | grep ca.connector.KRA.transportCert | awk -F \"=\" '{print \$2}' > transport.txt" 0 "Get Transport Cert"
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
	rlRun "pki -d $dir -c $password -h $host -p $port cert-request-profile-show $profilename --output $xml_profile_file"
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
	
	if [ "$profilename" != "CaDualCert" ] && \
	[ "$profilename" != "caDirPinUserCert" ] && \
	[ "$profilename" != "caDirUserCert" ] && \
	[ "$profilename" != "caECDirUserCert" ] && \
	[ "$profilename" != "caAgentServerCert" ] && \
        [ "$profilename" != "caUserCert" ] && \
	[ "$profilename" != "caUserSMIMEcapCert" ]; then
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $dir/$cert_request_file)\" $xml_profile_file"
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v \"$cn\" $xml_profile_file"
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$cn\" $xml_profile_file"
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$email\" $xml_profile_file"
		rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"
	fi
#### submit the request to CA 

	rlLog "Submit PKCS10 Request to CA"
	rlRun "pki -d $dir -c $password -h $host -p $port cert-request-submit $xml_profile_file >> $dir/$cert_request_file_sumbit" 0 "Submit Request"
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
##############################
#Function Usage create_new_cert_request() <Temporary NSS DB Directory> <NSS DB Directory Password> <pkcs10/crmf> <rsa/ec> \
# <key size> <cn> <uid> <email> <ou> <org> <country> <archive> <cert_request_file> <cert_subject_file> <return_dn>
#Example request:
#"create_new_cert_request dir:$tmp_nss_db pass:Secret123 req_type:pkcs10 algo:rsa size:1024 cn: uid: email: ou: org: c: \
#archive:false myreq:/tmp_nss_db/rand-request.pem subj:/tmp_nss_db/$rand-request-dn.txt"
#values to the function are passed as <name>:<value> pair,  name can be of any meaningful name, function only takes vales
#Anything after ":" is treated as an argument to function
#To create a cert request that requires keys to be archived pass archive:true , else pass archive:false
#Example:
#"create_new_cert_request dir:$tmp_nss_db pass:Secret123 req_type:pkcs10 algo:rsa size:1024 cn: uid: email: ou: org: country
#archive:true myreq:/tmp_nss_db/rand-request.pem subj:/tmp_nss_db/$rand-request-dn.txt"
#############################
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
	local rand=$RANDOM
	local state="North Carolina"
	local location="Raleigh"

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
		local subject="CN=$cn,OU=$ou,O=$organization,ST=$state,L=$location,C=$country"
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
		rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
		rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
		rlLog "Execute generateCRMFRequest to generate CRMF Request"
		rlRun "java -cp $CLASSPATH generateCRMFRequest -client_certdb_dir $dir -client_certdb_pwd $password -debug false -request_subject \"$subject\" -request_keytype $algo -request_keysize $key_size -output_file $cert_request_file 1> $dir/crmf.out" 0 "Execute generateCRMFRequest to generata CRMF Request"
	fi
	### FIXME: This should not be needed, But putting here temporarily so as to not break this function API

        if [ "$MYROLE" == "MASTER" ]; then
                ROOTCA_TOMCAT_INSTANCE_NAME=pki-master
                CA_SERVER_ROOT=/var/lib/pki/$ROOTCA_TOMCAT_INSTANCE_NAME/ca/
	elif [  "$MY_ROLE" == "SUBCA1" ]; then
		SUBCA1_TOMCAT_INSTANCE_NAME=pki-subca1
		CA_SERVER_ROOT=/var/lib/pki/$SUBCA1_TOMCAT_INSTANCE_NAME/ca/
	elif [ "$MY_ROLE" = "SUBCA2" ]; then
		SUBCA2_TOMCAT_INSTANCE_NAME=pki-subca2
		CA_SERVER_ROOT=/var/lib/pki/$SUBCA2_TOMCAT_INSTANCE_NAME/ca/
	fi

	if [ "$request_type" == "crmf" ] && [ "$archive" == "true" ];then
		rlLog "Get Transport Cert"
		rlRun "cat $CA_SERVER_ROOT/conf/CS.cfg | grep ca.connector.KRA.transportCert | awk -F \"=\" '{print \$2}' > transport.txt"
		rlRun "CRMFPopClient -d $dir -p $password -o $cert_request_file -n \"$subject\" -a $algo -l $key_size -u $uid -r $uid 1> $dir/CRMFPopClient.out" 0 "Executing CRMFPopClient"
		RETVAL=$?
                if [ $RETVAL != 0 ]; then
                        rlFail "CRMFPopClient Failed"
                        return 1
                fi
	fi
        if [ "$request_type" == "crmfdual" ] && [ "$archive" == "true" ];then
                rlLog "PWD=$PWD"
                rlLog "Get Transport Cert"
                rlRun "cat $CA_SERVER_ROOT/conf/CS.cfg | grep ca.connector.KRA.transportCert | awk -F \"=\" '{print \$2}' > transport.txt"
                rlRun "set_newjavapath \":./:/usr/lib/java/jss4.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/apache-commons-codec.jar:/opt/rhqa_pki/jars/pki-qe-tools.jar:\"" 0 "Setting Java CLASSPATH"
                rlRun "source /opt/rhqa_pki/env.sh" 0 "Set Environment Variables"
                rlLog "Executing  generateDualCRMFRequest"
                rlLog "java -cp $CLASSPATH generateDualCRMFRequest -client_certdb_dir $dir -client_certdb_pwd $password -debug false -request_subject \"$subject\" -request_keytype $algo -request_keysize $key_size -output_file $cert_request_file -transport_cert_file transport.txt 1> $dir/crmf.out"
                rlRun "java -cp $CLASSPATH generateDualCRMFRequest -client_certdb_dir $dir -client_certdb_pwd $password -debug false -request_subject \"$subject\" -request_keytype $algo -request_keysize $key_size -output_file $cert_request_file -transport_cert_file transport.txt 1> $dir/crmf.out"
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
	echo -e "State:$state" >> $cert_subject_file
	echo -e "Location:$location" >> $cert_subject_file
	echo -e "Country:$country" >> $cert_subject_file
	echo -e "Request_DN:$subject" >> $cert_subject_file
	rlLog "Certificate Request file is saved in $cert_request_file"
	rlLog "Subject DN information for Certificate Requeset is saved in $cert_subject_file"
	return 0
}	
#######################################################################################
#submit_new_request sumbits the request to the CA for further action, this function only submits the request
#approval of the request should be done as separate action. 
#submit_new_request <temp_nss_db_dir:$path_to_directory> <temp_nss_db_dir_pwd:$nss_db_password> <target_host:$target_host> \
#<protocol:HTTP/HTTPS> <port:8080/15080> <url:https://<server:port> <username:$username> <password:$password> <profile:$profilename> \
#<cert_request_file:$file_containing_request_details> <subj_request_file:$file_containing_details_of_certsubject> <request_type:crmf/pkcs10> \
#<output_file:$file_where_certificate_request_details_will_be_available>
#Example:
#submit_new_request dir:$tmp_nss_db pass:Secret123 cahost: nickname: protocol: port: url: username: userpwd: profile: \
#myreq:$tmp_nss_db/$rand-request.pem subj:$tmp_nss_db/$rand-request-dn.txt out:$tmp_nss_db/$rand-request-result.txt"
###############################################################################
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
	local country=$(cat $subj_request_file | grep ^"Country" | cut -d: -f2)
	local cert_request_dn=$(cat $subj_request_file | grep ^"Request_DN" | cut -d: -f2)
	local rand=$RANDOM

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
	if [[ "$profilename" =~ "caUserCert" ]]  || [[ "$profilename" =~  "caUserSMIMEcapCert" ]] || [[ "$profilename" =~  "caDualCert" ]];then
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

	 if [[ "$profilename" != *CaDual* ]] && \
        [[ "$profilename" != *caDirPin* ]] && \
        [[ "$profilename" != *caDir* ]] && \
        [[ "$profilename" != *caECDirUser* ]] && \
        [[ "$profilename" != *caAgentServer* ]] && \
	[[ "$profilename" != *caUser* ]] && \
	[[ "$profilename" != *caUserSMIMEcap* ]]; then
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
        local num="${11}"
        local file_name="$6"
        local cert_type="$7"
	local host="${8}"
	local port="${9}"
	local prefix="${10}"
        local TEMP_NSS_DB="$TmpDir/nssdb"
		rlLog "In generate user cert"
	
		rlLog "create_cert_request $TEMP_NSS_DB redhat123 $cert_type rsa 2048 \"$userfullname\" \"$user_id\" "$req_email" "Engineering" "Example" "US" "--" "reqstatus" "requestid" $host $port "requestdn" $prefix"

                        rlRun "create_cert_request $TEMP_NSS_DB redhat123 $cert_type rsa 2048 \"$userfullname\" \"$user_id\" "$req_email" "Engineering" "Example" "US" "--" "reqstatus" "requestid" $host $port "requestdn" $prefix"

                rlRun "pki -h $host -p $port cert-request-show $requestid > $TmpDir/$file_name-CA_certrequestshow_00$file_no$cert_type$num$ext" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/$file_name-CA_certrequestshow_00$file_no$cert_type$num$ext"
                rlAssertGrep "Type: enrollment" "$TmpDir/$file_name-CA_certrequestshow_00$file_no$cert_type$num$ext"
                rlAssertGrep "Status: pending" "$TmpDir/$file_name-CA_certrequestshow_00$file_no$cert_type$num$ext"
                rlAssertGrep "Operation Result: success" "$TmpDir/$file_name-CA_certrequestshow_00$file_no$cert_type$num$ext"

                #Agent Approve the certificate after reviewing the cert for the user
                rlLog "Executing: pki -d $CERTDB_DIR/ \
                                      -n ${prefix}_agentV \
				      -h $host \
				      -p $port \
                                      -c $CERTDB_DIR_PASSWORD \
                                      -t ca \
                                      cert-request-review --action=approve $requestid"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n ${prefix}_agentV \
				-h $host \
			     -p $port \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                           cert-request-review --action=approve $requestid > $TmpDir/$file_name-CA_certapprove_00$file_no$cert_type$num$ext" \
                           0 \
                           "CA agent approve the cert"
                rlAssertGrep "Approved certificate request $requestid" "$TmpDir/$file_name-CA_certapprove_00$file_no$cert_type$num$ext"
                rlRun "pki -h $host -p $port cert-request-show $requestid > $TmpDir/$file_name-CA_certapprovedshow_00$file_no$cert_type$num$ext" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/$file_name-CA_certapprovedshow_00$file_no$cert_type$num$ext"
                rlAssertGrep "Type: enrollment" "$TmpDir/$file_name-CA_certapprovedshow_00$file_no$cert_type$num$ext"
                rlAssertGrep "Status: complete" "$TmpDir/$file_name-CA_certapprovedshow_00$file_no$cert_type$num$ext"
                rlAssertGrep "Certificate ID:" "$TmpDir/$file_name-CA_certapprovedshow_00$file_no$cert_type$num$ext"
                local certificate_serial_number=`cat $TmpDir/$file_name-CA_certapprovedshow_00$file_no$cert_type$num$ext | grep "Certificate ID:" | awk '{print $3}'`
                rlLog "Cerificate Serial Number=$certificate_serial_number"
                #Verify the certificate is valid
                rlRun "pki -h $host -p $port cert-show  $certificate_serial_number --encoded > $TmpDir/$file_name-CA_certificate_show_00$file_no$cert_type$num$ext" 0 "Executing pki cert-show $certificate_serial_number"

                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/$file_name-CA_certificate_show_00$file_no$cert_type$num$ext > $TmpDir/$file_name-CA_validcert_00$file_no$cert_type$num$cert_ext"
                 rlRun "certutil -d $TEMP_NSS_DB -A -n \"$user_id-$cert_type\" -i $TmpDir/$file_name-CA_validcert_00$file_no$cert_type$num$cert_ext  -t "u,u,u""
                echo cert_serialNumber-$certificate_serial_number > $CERT_INFO
                echo cert_requestdn-$requestdn >> $CERT_INFO
                return 0;
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
######################################################################
#	Generate Certificate 
#	Examples:
#
#1. Generate cert for profile caServerCert
#  rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
#                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn:server1.example.org subject_uid: subject_email: \
#                subject_ou: subject_o: subject_c: archive:false req_profile:caServerCert target_host: \
#                protocol: port: cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
#                certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
#
#2. Generate cert for profile caUserCert
#        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
#                myreq_type:pkcs10 algo:rsa key_size:1024 subject_cn:\"Idm User1\" subject_uid:idmuser1 subject_email:idmuser1@example.org \
#                subject_ou:Engineering subject_o: subject_c: archive:false req_profile: target_host: \
#                protocol: port: cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
#                certdb_nick:\"$CA_agentV_user\" cert_info:$cert_info"
#####################################################################
generate_new_cert()
{
	local tmp_nss_db=$(echo $1| cut -d: -f2)
	local tmp_nss_db_pwd=$(echo $2| cut -d: -f2)
	local req_type=$(echo $3|cut -d: -f2)
	local algo=$(echo $4|cut -d: -f2)
	local key_size=$(echo $5|cut -d: -f2)
	local subject_cn="$(echo $6|cut -d: -f2)"
	local subject_uid="$(echo $7|cut -d: -f2)"
	local subject_email="$(echo $8|cut -d: -f2)"
	local subject_ou="$(echo $9|cut -d: -f2)"
	local subject_o="$(echo ${10}|cut -d: -f2)"
	local subject_c="$(echo ${11}|cut -d: -f2)"
	local archive="$(echo ${12}|cut -d: -f2)"
	local req_profile="$(echo ${13}|cut -d: -f2)"
	local target_host="$(echo ${14}|cut -d: -f2)"
	local target_protocol="$(echo ${15}|cut -d: -f2)"
	local target_port="$(echo ${16}|cut -d: -f2)"
	local cert_db_dir="$(echo ${17}|cut -d: -f2)"
	local cert_db_pwd="$(echo ${18}|cut -d: -f2)"
	local cert_db_nick="$(echo ${19}|cut -d: -f2)"
	local target_cert_info="$(echo ${20}|cut -d: -f2)"
	local certout="$tmp_nss_db/cert_out"
	local rand=$RANDOM
	rlRun "create_new_cert_request \
        dir:$tmp_nss_db \
        pass:$tmp_nss_db_pwd \
        req_type:$req_type \
        algo:$algo \
        size:$key_size \
        cn:\"$subject_cn\" \
        uid:\"$subject_uid\" \
        email:\"$subject_email\" \
        ou:\"$subject_ou\" \
        org:\"$subject_o\" \
        country:\"$subject_c\" \
        archive:$archive \
        myreq:$tmp_nss_db/$rand-request.pem \
        subj:$tmp_nss_db/$rand-request-dn.txt"
         if [ $? != 0 ]; then
         {
                 rlFail "Request Creation failed"
                 return 1;
         }
         fi
	rlRun "submit_new_request dir:$tmp_nss_db \
		pass:$tmp_nss_db_pwd \
		cahost:$target_host \
		nickname:\"$cert_db_nick\" \
		protocol:$target_protocol \
		port:$target_port \
		url: \
		username: \
		userpwd: \
		profile:$req_profile \
		myreq:$tmp_nss_db/$rand-request.pem \
		subj:$tmp_nss_db/$rand-request-dn.txt \
		out:$tmp_nss_db/$rand-request-result.txt"
         if [ $? != 0 ]; then
         {
                 rlFail "Request Submission failed"
                 return 1;
         }
         fi
	local subject_cn=$(cat $tmp_nss_db/$rand-request-dn.txt | grep "CN" | cut -d":" -f2)
	rlAssertGrep "Request Status: pending" "$tmp_nss_db/$rand-request-result.txt"
	rlAssertGrep "Operation Result: success" "$tmp_nss_db/$rand-request-result.txt"
	local cert_requestid=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_ID_RETURNED" | cut -d":" -f2)
	local cert_requestdn=$(cat $tmp_nss_db/$rand-request-result.txt |grep "REQUEST_DN" | cut -d":" -f2)
	local cert_requeststatus=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_SUBMIT_STATUS" | cut -d":" -f2)
	if [ "$target_host" == "" ]; then
               target_host="$(hostname)"
        fi
        if [ "$target_port" == "" ]; then
                target_port=8080
        fi
	rlRun "pki -d $cert_db_dir \
                 -c $cert_db_pwd \
		 -h $target_host \
		 -p $target_port \
                 -n \"$cert_db_nick\" \
                 ca-cert-request-review $cert_requestid \
                 --action approve 1> $tmp_nss_db/pki-req-approve-out" 0 "As $cert_db_nick Approve Certificate Request"
	if [ $? != 0 ]; then
	{
        	rlFail "cert approval failed"
		return 1;
        }
        fi
        rlAssertGrep "Approved certificate request $cert_requestid" "$tmp_nss_db/pki-req-approve-out"
        local valid_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $cert_requestid | grep "Certificate ID" | sed 's/ //g' | cut -d: -f2)
	local cert_start_date=$(pki -h $target_host -p $target_port cert-show $valid_serialNumber | grep "Not Before" | awk -F ": " '{print $2}')
        local cert_end_date=$(pki -h $target_host -p $target_port cert-show $valid_serialNumber | grep "Not After" | awk -F ": " '{print $2}')
	local cert_subject=$(pki -h $target_host -p $target_port cert-show $valid_serialNumber | grep "Subject" | awk -F ": " '{print $2}')
	local STRIP_HEX=$(echo $valid_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL=${STRIP_HEX^^}
        local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
#        rlLog "Get the cert in a output file"
#        rlRun "pki -h $target_host -p $target_port cert-show $valid_serialNumber --encoded --output $tmp_nss_db/$cn-out.pem 1> $tmp_nss_db/pki-cert-show.out"
#        rlAssertGrep "Certificate \"$valid_serialNumber\"" "$tmp_nss_db/pki-cert-show.out"
#        rlRun "pki -h $target_host -p $target_port cert-show 0x1 --encoded --output  $tmp_nss_db/ca_cert.pem 1> $tmp_nss_db/ca-cert-show.out"
#        rlAssertGrep "Certificate \"0x1\"" "$tmp_nss_db/ca-cert-show.out"
#        rlLog "Add the $cn cert to $tmp_nss_db NSS DB"
#        rlRun "pki -d $tmp_nss_db \
#                -h $target_host \
#                -p $target_port \
#                -c $tmp_nss_db_pwd \
#                -n \"$subject_cn\" client-cert-import \
#                --cert $tmp_nss_db/$cn-out.pem 1> $tmp_nss_db/pki-client-cert.out"
#        rlAssertGrep "Imported certificate \"$subject_cn\"" "$tmp_nss_db/pki-client-cert.out"
#        rlLog "Get CA cert imported to $TEMP_NSS_DB NSS DB"
#        rlRun "pki -d $tmp_nss_db \
#                -h $target_host \
#                -p $target_port \
#                -c $tmp_nss_db_pwd \
#                -n \"casigningcert\" client-cert-import \
#                --ca-cert $tmp_nss_db/ca_cert.pem 1> $tmp_nss_db/pki-ca-cert.out"
#        rlAssertGrep "Imported certificate \"casigningcert\"" "$tmp_nss_db/pki-ca-cert.out"

        echo cert_serialNumber-$valid_serialNumber > $cert_info
        echo cert_start_date-$cert_start_date >> $cert_info
        echo cert_end_date-$cert_end_date >> $cert_info
        echo cert_subject-$cert_subject >> $cert_info
	echo STRIP_HEX-$STRIP_HEX >> $cert_info
	echo CONV_UPP_VAL-$CONV_UPP_VAL >> $cert_info
	echo decimal_valid_serialNumber-$decimal_valid_serialNumber >> $cert_info
	echo cert_requestid-$cert_requestid >> $cert_info
	echo cert_requestdn-$cert_requestdn >> $cert_info
	echo cert_requeststatus-$cert_requeststatus >> $cert_info
	return 0;
}
#########################################################################
#generate_modified_cert generates a cert with given validity period, this function
#generates cert request based on validity period given as argument, Validity period should 
#be either in days or months, but not both. This function can be used to get any cert modified
#irrespective of CA
#Example1: Generate Cert based on crmf request with caUserCert Profile
#"generate_modified_cert validity_period:\"1 Day\" tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
#req_type:crmf algo:rsa key_size:2048 cn: uid: email: ou: org: country: archive:false host: port: profile: \
#cert_db:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD admin_nick:\"$CA_agentV_user\" cert_info:$cert_info expect_data:$exp"
#
#Example2: Generate cert based on pkcs10 request with caServerCert profile
#"generate_modified_cert validity_period:\"1 Day\" tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PWD \
#req_type:pkcs10 algo:rsa key_size:2048 cn:server1.example.org uid: email: ou: org: country: archive:false host: port: profile: \
#cert_db:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD admin_nick:\"$CA_agentV_user\" cert_info:$cert_info expect_data:$exp" 
########################################################################
generate_modified_cert()
{
        local tmp_validity_period=$(echo $1|cut -d: -f2)
        local tmp_nss_db=$(echo $2|cut -d: -f2)
        local tmp_nss_db_pwd=$(echo $3|cut -d: -f2)
        local tmp_req_type=$(echo $4|cut -d: -f2)
        local tmp_algo=$(echo $5|cut -d: -f2)
        local tmp_keysize=$(echo $6|cut -d: -f2)
        local tmp_cn=$(echo $7|cut -d: -f2)
        local tmp_uid=$(echo $8|cut -d: -f2)
        local tmp_email=$(echo $9|cut -d: -f2)
        local tmp_ou=$(echo ${10}|cut -d: -f2)
        local tmp_org=$(echo ${11}|cut -d: -f2)
        local tmp_country=$(echo ${12}|cut -d: -f2)
        local tmp_archive=$(echo ${13}|cut -d: -f2)
        local tmp_host=$(echo ${14}|cut -d: -f2)
        local tmp_port=$(echo ${15}|cut -d: -f2)
        local tmp_profile=$(echo ${16}|cut -d: -f2)
        local tmp_cert_db=$(echo ${17}|cut -d: -f2)
        local tmp_cert_db_pwd=$(echo ${18}|cut -d: -f2)
        local tmp_cert_nick=$(echo ${19}|cut -d: -f2)
        local tmp_cert_info=$(echo ${20}|cut -d: -f2)
        local tmp_expfile=$(echo ${21}|cut -d: -f2)
        rlRun "create_new_cert_request \
                dir:$tmp_nss_db \
                pass:$tmp_nss_db_pwd \
                req_type:$tmp_req_type \
                algo:$tmp_algo \
                size:$tmp_keysize \
                cn:\"$tmp_cn\" \
                uid:\"$tmp_uid\" \
                email:\"$tmp_email\" \
                ou:\"$tmp_ou\" \
                org:\"$tmp_org\" \
                country:\"$tmp_country\" \
                archive:$tmp_archive \
                myreq:$tmp_nss_db/$rand-request.pem \
                subj:$tmp_nss_db/$rand-request-dn.txt"
        if [ $? != 0 ]; then
        {
                rlFail "Request Creation failed"
                return 1
        }
        fi
        rlRun "submit_new_request dir:$tmp_nss_db \
                pass:$tmp_nss_db_pwd \
                cahost:$tmp_host \
                nickname: \
                protocol: \
                port:$tmp_port \
                url: \
                username: \
                userpwd: \
                profile:$tmp_profile \
                myreq:$tmp_nss_db/$rand-request.pem \
                subj:$tmp_nss_db/$rand-request-dn.txt \
                out:$tmp_nss_db/$rand-request-result.txt"
        if [ $? != 0 ]; then
        {
                rlFail "Request Submission failed"
                return 1
        }
        fi
        rlAssertGrep "Request Status: pending" "$tmp_nss_db/$rand-request-result.txt"
        rlAssertGrep "Operation Result: success" "$tmp_nss_db/$rand-request-result.txt"
        local tmp_requestid=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_ID_RETURNED" | cut -d":" -f2)
        local tmp_requestdn=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_DN" | cut -d":" -f2)
        local tmp_updated_date=$(date --date="$tmp_validity_period" +%Y-%m-%d)
        if [ "$tmp_host" == "" ]; then
               tmp_host="$(hostname)"
        fi
        if [ "$tmp_port" == "" ]; then
                tmp_port=8080
        fi
        echo "set timeout 5" > $tmp_expfile
        echo "set force_conservative 0" >> $tmp_expfile
        echo "set send_slow {1 .1}" >> $tmp_expfile
        echo "spawn -noecho pki -d $tmp_cert_db -h $tmp_host -p $tmp_port -n "$tmp_cert_nick" -c $tmp_cert_db_pwd  cert-request-review $tmp_requestid --file $tmp_nss_db/$tmp_requestid-req.xml" >> $tmp_expfile
        echo "expect \"Action \(approve/reject/cancel/update/validate/assign/unassign\):\"" >> $tmp_expfile
        echo "system \"xmlstarlet ed -L -u \\\"certReviewResponse/ProfilePolicySet/policies/def/policyAttribute\[\@name='notAfter'\]/Value\\\" -v \\\"$tmp_updated_date 00:00:10\\\" $tmp_nss_db/$tmp_requestid-req.xml\"" >> $tmp_expfile
        echo "send -- \"approve\r\"" >> $tmp_expfile
        echo "expect eof" >> $tmp_expfile
        rlRun "/usr/bin/expect -f $tmp_expfile > $tmp_nss_db/expout 2>&1"
        if [ $? != 0 ]; then
        {
                rlFail "Request Approval failed"
                return 1;
        }
        fi
        rlAssertGrep "Approved certificate request $tmp_requestid" "$tmp_nss_db/expout"
        local valid_serialNumber=$(pki -h $tmp_host -p $tmp_port cert-request-show $tmp_requestid | grep "Certificate ID" | sed 's/ //g' | cut -d: -f2)
        local cert_start_date=$(pki -h $tmp_host -p $tmp_port cert-show $valid_serialNumber | grep "Not Before" | awk -F ": " '{print $2}')
        local cert_end_date=$(pki -h $tmp_host -p $tmp_port cert-show $valid_serialNumber | grep "Not After" | awk -F ": " '{print $2}')
        local cert_subject=$(pki -h $tmp_host -p $tmp_port cert-show $valid_serialNumber | grep "Subject" | awk -F ": " '{print $2}')
        echo cert_serialNumber-$valid_serialNumber > $cert_info
        echo cert_start_date-$cert_start_date >> $cert_info
        echo cert_end_date-$cert_end_date >> $cert_info
        echo cert_subject-$cert_subject >> $cert_info
        return 0;
}
########################################################
#generate_cert_request_xml fills the xml template with required
#certificate request information. 
#Arguments: 
#certificate request file (Base 64pkcs10/crmf request)
#certificate subject file : containing details of cert like cn,email,uid 
#profile template : xml template file of the profile for which cert request to be submitted 
#profile name: Name of the profile for which the details should be filled.
#generate_cert_request_xml $cert_request_file $cert_subject_file $xml_profile_file $profile_name
########################################################
generate_cert_request_xml()
{
        cert_request_file=$1
        cert_subject_file=$2
        xml_profile_file=$3
        cert_profile=$4

        local request_type=$(cat $cert_subject_file | grep RequestType: | cut -d: -f2)
        local subject_cn=$(cat $cert_subject_file | grep CN: | cut -d: -f2)
        local subject_uid=$(cat $cert_subject_file | grep UID: | cut -d: -f2)
        local subject_email=$(cat $cert_subject_file | grep Email: | cut -d: -f2)
        local subject_ou=$(cat $cert_subject_file | grep OU: | cut -d: -f2)
        local subject_org=$(cat $cert_subject_file | grep Org: | cut -d: -f2)
        local subject_c=$(cat $cert_subject_file | grep Country: | cut -d: -f2)

        if [[ "$cert_profile" =~ "caUserCert" ]]  || [[ "$cert_profile" =~  "caUserSMIMEcapCert" ]] || [[ "$cert_profile" =~  "caDualCert" ]];then
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $cert_request_file)\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_uid']/Value\" -v \"$subject_uid\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_e']/Value\" -v \"$subject_email\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v \"$subject_cn\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_ou']/Value\" -v \"$subject_ou\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_o']/Value\" -v \"$subject_org\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_c']/Value\" -v \"$subject_c\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$subject_cn\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$subject_email\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"
        fi

        if [[ "$cert_profile" != *CaDual* ]] && \
        [[ "$cert_profile" != *caDirPin* ]] && \
        [[ "$cert_profile" != *caDirUser* ]] && \
        [[ "$cert_profile" != *caECDirUser* ]] && \
        [[ "$cert_profile" != *caAgentServer* ]] && \
        [[ "$cert_profile" != *caUser* ]] &&
        [[ "$cert_profile" != *caUserSMIMEcap* ]]; then
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $cert_request_file)\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$subject_cn\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$subject_email\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"
        fi
        return 0;
}

run_req_action_cert()
{
        local tmp_nss_db=$(echo $1| cut -d: -f2)
        local tmp_nss_db_pwd=$(echo $2| cut -d: -f2)
        local req_type=$(echo $3|cut -d: -f2)
        local algo=$(echo $4|cut -d: -f2)
        local key_size=$(echo $5|cut -d: -f2)
        local subject_cn="$(echo $6|cut -d: -f2)"
        local subject_uid="$(echo $7|cut -d: -f2)"
        local subject_email="$(echo $8|cut -d: -f2)"
        local subject_ou="$(echo $9|cut -d: -f2)"
        local subject_o="$(echo ${10}|cut -d: -f2)"
        local subject_c="$(echo ${11}|cut -d: -f2)"
        local archive="$(echo ${12}|cut -d: -f2)"
        local req_profile="$(echo ${13}|cut -d: -f2)"
        local target_host="$(echo ${14}|cut -d: -f2)"
        local target_protocol="$(echo ${15}|cut -d: -f2)"
        local target_port="$(echo ${16}|cut -d: -f2)"
        local cert_db_dir="$(echo ${17}|cut -d: -f2)"
        local cert_db_pwd="$(echo ${18}|cut -d: -f2)"
        local cert_db_nick="$(echo ${19}|cut -d: -f2)"
        local target_cert_info="$(echo ${20}|cut -d: -f2)"
        local certout="$tmp_nss_db/cert_out"
        local rand=$RANDOM

        rlRun "create_new_cert_request \
        dir:$tmp_nss_db \
        pass:$tmp_nss_db_pwd \
        req_type:$req_type \
        algo:$algo \
        size:$key_size \
        cn:\"$subject_cn\" \
        uid:\"$subject_uid\" \
        email:\"$subject_email\" \
        ou:\"$subject_ou\" \
        org:\"$subject_o\" \
        country:\"$subject_c\" \
        archive:$archive \
        myreq:$tmp_nss_db/$rand-request.pem \
        subj:$tmp_nss_db/$rand-request-dn.txt"
         if [ $? != 0 ]; then
         {
                 rlFail "Request Creation failed"
                 return 1;
         }
         fi
        rlRun "submit_new_request dir:$tmp_nss_db \
                pass:$tmp_nss_db_pwd \
                cahost:$target_host \
                nickname:\"$cert_db_nick\" \
                protocol:$target_protocol \
                port:$target_port \
                url: \
                username: \
                userpwd: \
                profile:$req_profile \
                myreq:$tmp_nss_db/$rand-request.pem \
                subj:$tmp_nss_db/$rand-request-dn.txt \
                out:$tmp_nss_db/$rand-request-result.txt"
         if [ $? != 0 ]; then
         {
                 rlFail "Request Submission failed"
                 return 1;
         }
         fi
        rlAssertGrep "Request Status: pending" "$tmp_nss_db/$rand-request-result.txt"
        rlAssertGrep "Operation Result: success" "$tmp_nss_db/$rand-request-result.txt"
        local cert_requestid=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_ID_RETURNED" | cut -d":" -f2)
        local cert_requestdn=$(cat $tmp_nss_db/$rand-request-result.txt |grep "REQUEST_DN" | cut -d":" -f2)
        local cert_requeststatus=$(cat $tmp_nss_db/$rand-request-result.txt | grep "REQUEST_SUBMIT_STATUS" | cut -d":" -f2)
        if [ "$target_host" == "" ]; then
               target_host="$(hostname)"
        fi
        if [ "$target_port" == "" ]; then
                target_port=8080
        fi
        rlRun "pki -d $cert_db_dir \
                 -c $cert_db_pwd \
                 -h $target_host \
                 -p $target_port \
                 -n \"$cert_db_nick\" \
                 ca-cert-request-review $cert_requestid \
                 --action approve  > $tmp_nss_db/pki-req-approve-out 2>&1" 0,255
        RETVAL=$?
        if [ $RETVAL -eq 0 ]
        then
                rlLog "We where here"
                rlAssertGrep "Approved certificate request $cert_requestid" "$tmp_nss_db/pki-req-approve-out"
                local valid_serialNumber=$(pki -h $target_host -p $target_port cert-request-show $cert_requestid | grep "Certificate ID" | sed 's/ //g' | cut -d: -f2)
                local cert_start_date=$(pki -h $target_host -p $target_port cert-show $valid_serialNumber | grep "Not Before" | awk -F ": " '{print $2}')
                local cert_end_date=$(pki -h $target_host -p $target_port cert-show $valid_serialNumber | grep "Not After" | awk -F ": " '{print $2}')
                local cert_subject=$(pki -h $target_host -p $target_port cert-show $valid_serialNumber | grep "Subject" | awk -F ": " '{print $2}')
                local STRIP_HEX=$(echo $valid_serialNumber | cut -dx -f2)
                local CONV_UPP_VAL=${STRIP_HEX^^}
                local decimal_valid_serialNumber=$(echo "ibase=16;$CONV_UPP_VAL"|bc)
                echo cert_serialNumber-$valid_serialNumber > $cert_info
                echo cert_start_date-$cert_start_date >> $cert_info
                echo cert_end_date-$cert_end_date >> $cert_info
                echo cert_subject-$cert_subject >> $cert_info
                echo STRIP_HEX-$STRIP_HEX >> $cert_info
                echo CONV_UPP_VAL-$CONV_UPP_VAL >> $cert_info
                echo decimal_valid_serialNumber-$decimal_valid_serialNumber >> $cert_info
                echo cert_requestid-$cert_requestid >> $cert_info
                echo cert_requestdn-$cert_requestdn >> $cert_info
                echo cert_requeststatus-$cert_requeststatus >> $cert_info
        elif [ $RETVAL -eq 255 ]
        then
             echo PKI_ERROR=$(cat $tmp_nss_db/pki-req-approve-out) >> $cert_info
        fi
}
##################################################################
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
### This script generates an xml file with the certificate request
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
generate_xml()
{
        cert_request_file=$1
        cert_subject_file=$2
        xml_profile_file=$3
        cert_profile=$4
        rlLog "cert_request_file=$cert_request_file"
        rlLog "cert_subject_file=$cert_subject_file"
        rlLog "xml_profile_file=$xml_profile_file"
        rlLog "cert_profile=$cert_profile"

        local request_type=$(cat $cert_subject_file | grep RequestType: | cut -d: -f2)
        local subject_cn=$(cat $cert_subject_file | grep CN: | cut -d: -f2)
        local subject_uid=$(cat $cert_subject_file | grep UID: | cut -d: -f2)
        local subject_email=$(cat $cert_subject_file | grep Email: | cut -d: -f2)
        local subject_ou=$(cat $cert_subject_file | grep OU: | cut -d: -f2)
        local subject_org=$(cat $cert_subject_file | grep Org: | cut -d: -f2)
        local subject_c=$(cat $cert_subject_file | grep Country: | cut -d: -f2)


        if [ "$cert_profile" == "caUserCert" ]  || [ "$cert_profile" ==  "caUserSMIMEcapCert" ] || [ "$cert_profile" ==  "caDualCert" ];then
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $cert_request_file)\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_uid']/Value\" -v \"$subject_uid\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_e']/Value\" -v \"$subject_email\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_cn']/Value\" -v \"$subject_cn\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_ou']/Value\" -v \"$subject_ou\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_o']/Value\" -v \"$subject_org\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='sn_c']/Value\" -v \"$subject_c\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$subject_cn\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$subject_email\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"
        fi

        if [ "$cert_profile" != "CaDualCert" ] && \
        [ "$cert_profile" != "caDirPinUserCert" ] && \
        [ "$cert_profile" != "caDirUserCert" ] && \
        [ "$cert_profile" != "caECDirUserCert" ] && \
        [ "$cert_profile" != "caAgentServerCert" ] && \
        [ "$cert_profile" != "caUserCert" ] &&
        [ "$cert_profile" != "caUserSMIMEcapCert" ]; then
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request_type']/Value\" -v \"$request_type\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='cert_request']/Value\" -v \"$(cat -v $cert_request_file)\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_name']/Value\" -v \"$subject_cn\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_email']/Value\" -v \"$subject_email\" $xml_profile_file"
        rlRun "xmlstarlet ed -L -u \"CertEnrollmentRequest/Input/Attribute[@name='requestor_phone']/Value\" -v 123-456-7890 $xml_profile_file"
        fi
}
