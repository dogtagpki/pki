#!/bin/sh

########################################################################
#  RHCS SERVER SHARED LIBRARY
#######################################################################
# Includes:
#       verifyErrorMsg
#       submit_log
#       submit_instance_logs
#	submit_log <file>
#	submit_instance_logs <instance_name>
#	rhcs_start_instance <instance_name>
#	rhcs_stop_instance <instance_name>
#	runJava <java class> <input>
#	set_javapath
#	install_and_trust_CA_cert <ca_server_root> <nss_db_dir>
#       install_and_trust_user_cert <certificate pem file> <nickname> <nss-db-directory>
#	disable_ca_nonce <ca_server_root>
#	enable_ca_nonce <ca_server_root>
#	importP12File <P12FileLocation> <P12FilePassword> <nssdbDirectory> <nssdbPassword> <cert_nickname>
#       forward_system_clock <number_of_days>
#       reverse_system_clock <number_of_days>
#       replace_string_in_a_file <file_name> <original_string> <replace_string>
#       scep_do_enroll_with_sscep <scep_enroll_pin> <scep_enroll_url>  <scep_host_ipaddr> <temp_dir> <fingerprint>
######################################################################
#######################################################################

#########################################################################
# verifyErrorMsg Usage:
#	verifyErrorMsg <command> <expected_msg>
#######################################################################

verifyErrorMsg()
{
   local command="$1"
   local expmsg=$2
   local expErrorCode=$3
   local rc=0

   rm -rf /tmp/errormsg.out /tmp/errormsg_clean.out
   rlLog "Executing: $command"
   $command
   rc=$?
   if [ $rc -eq 0 ] ; then
        rlLog "ERROR: Expected \"$command\" to fail."
        rc=1
   else
        rlLog "\"$command\" failed as expected."
        rlRun "$command 2> /tmp/errormsg.out" 255 "\"$command\" failed"
        sed 's/"//g' /tmp/errormsg.out > /tmp/errormsg_clean.out
        actual=`cat /tmp/errormsg_clean.out`
        if [[ "$actual" = "$expmsg" ]] ; then
                rlPass "Error message as expected: $actual"
                if [ $expErrorCode ] ; then
                        if [[ "$rc" = "$expErrorCode" ]] ; then
                                rlPass "Error code as expected: $rc"
                                return 0
                        else
                                rlLog "ERROR: Error code is not expected. GOT: $rc EXP: $expErrorCode"
                                return 1
                        fi
                else
                        rlLog "Error code validation is not selected."
                        return 0
                fi
        else
                rlFail "ERROR: Message not as expected. GOT: $actual  EXP: $expmsg"
                return 1
        fi
  fi
  return $rc
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   rhcs_quick_uninstall
#   Usage: rhcs_quick_uninstall
#
# This will uninstall RHCS and related components.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rhcs_quick_uninstall(){
	echo "rhcs_quick_uninstall"
	# Uninstall/unconfigure RHCS

} #rhcs_quick_uninstall


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# submit_log
#   Usage: submit_log <logfilename>
#
# This will backup and submit a log file to beaker.  The backup file
# submitted is named $LOGFILE.$DATE
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
submit_log(){
	if [ $# -ne 1 ]; then
		echo "Usage: $FUNCNAME <log filename>"
		return 1
	fi

	if [ ! -d /tmp/logbackups ]; then
		mkdir /tmp/logbackups
	fi
	local DATE=$(date +%Y%m%d-%H%M%S)
	local LOGFILE=$1
	local LOGBACK=$LOGFILE.$DATE
	if [ -f $LOGFILE ]; then
		rlLog "Backing up and submitting $LOGFILE"
		cp $LOGFILE $LOGBACK
		rhts-submit-log -l $LOGBACK
	else
		rlLog "Cannot file $LOGFILE"
	fi
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# submit_instance_logs
#   Usage: submit_instance_logs <instance_name>
#
# This will rhts-submit various/all RHCS subsystem related log files to beaker for
# debugging, troubleshooting, and/or record keeping
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
submit_instance_logs(){
	INSTANCE_ID=$1
	submit_log /var/log/$INSTANCE_ID-install.log
	submit_log /var/lib/$INSTANCE_ID/logs/selftests.log
	submit_log /var/lib/$INSTANCE_ID/logs/catalina.out
	submit_log /var/lib/$INSTANCE_ID/logs/debug
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# rhcs_start_instance
#   Usage: rhcs_start_instance <instance_name>
#
# This will
# start RHCS instance
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rhcs_start_instance(){
        TOMCAT_ID=$1
	rlLog "Executing: systemctl start pki-tomcatd@$TOMCAT_ID.service"
	systemctl start pki-tomcatd@$TOMCAT_ID.service
	sleep 60
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# rhcs_stop_instance
#   Usage: rhcs_stop_instance <instance_name>
#
# This will
# stop RHCS instance
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rhcs_stop_instance(){
        TOMCAT_ID=$1
	rlLog "Executing: systemctl stop pki-tomcatd@$TOMCAT_ID.service"
	systemctl stop pki-tomcatd@$TOMCAT_ID.service
        sleep 60
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# runJava
#   Usage: runJava <java class> <input>
# This will execute the java classes
# returns the output of the java program
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
runJava(){
	javaclass="$1"
        input_file="$2"
	data=$(< $input_file)
	input=`echo $data|tr '\n' ' '`
	rlLog "input=$input"
	command="$javaclass $input"
	echo $CLASSPATH | grep "."
	if [ $? -eq 0 ] ; then
		rlRun "/usr/bin/java $command > /tmp/java_output.out"
	else
		rlRun "set_javapath"
		rlRun ". /opt/rhqa_pki/env.sh"
		rlRun "/usr/bin/java -cp \"$CLASSPATH\" $command > /tmp/java_output.out"
	fi
        cat /tmp/java_output.out
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# set_javapath
#   Usage: set_javapath
# function to set java path
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
set_javapath(){
        arch=`uname -p`
        os_flavor=`uname -s`
        classpath=""
        echo $os_flavor | grep "Linux"
        if [ $? -eq 0 ] ; then
		echo $arch | grep "x86_64"
                if [ $? -eq 0 ] ; then
                        classpath="./:/usr/lib/java/jss4.jar:/usr/share/java/ldapjdk.jar:/usr/share/java/pki/pki-certsrv.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/pki/pki-tools.jar:/usr/share/java/xml-commons-resolver.jar:/usr/share/java/xerces-j2.jar:/usr/share/java/apache-commons-codec.jar:/usr/share/java/pki/pki-silent.jar:/opt/rhqa_pki/java/generateCRMFRequest.jar:"
                else
                        classpath="./:/usr/lib/java/jss4.jar:/usr/share/java/ldapjdk.jar:/usr/share/java/pki/pki-certsrv.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/pki/pki-tools.jar:/usr/share/java/xml-commons-resolver.jar:/usr/share/java/xerces-j2.jar:/usr/share/java/apache-commons-codec.jar:/usr/share/java/pki/pki-silent.jar:/opt/rhqa_pki/java/generateCRMFRequest.jar:"
                fi
		echo "export CLASSPATH=$classpath" >> /opt/rhqa_pki/env.sh
                return 0
        else
                rlLog "OS flavor is not Linux"
                return 1
        fi
}
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#set_newjavapath()
#	Usage: set_newjavapath <classpath>
#	Function to add new jar files to the classpath
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
set_newjavapath()
{
	classpath=$1
	arch=$(uname -p)
	os_flavour=$(uname -s)
	echo $os_flavour | grep "Linux"
	if [ $? -eq 0 ]; then
	#we check CLASSPATH variable is already available
	echo $CLASSPATH | grep  "."
		if [ $? -eq 0 ]; then
		echo $CLASSPATH | grep $classpath
			if [ $? -eq 0 ]; then
				rlRun "echo \"export CLASSPATH=$classpath\" >> /opt/rhqa_pki/env.sh"
				return 0
			else
				#CLASSPATH is set but the jar file that we are newly adding is missing
				#so we add the missing jar files to the classpath 
				CLASSPATH=$CLASSPATH:$classpath:
				rlRun "echo \"export CLASSPATH=$classpath\" >> /opt/rhqa_pki/env.sh"
				return 0
			fi
		else
	#No ClASSPATH environment variable available so set set CLASSPATH
			rlLog "Set CLASSPATH we are here"
			rlRun "echo \"export CLASSPATH=./:$classpath\" >> /opt/rhqa_pki/env.sh"
		return 0
		fi
	else
		rlLog "OS flavour is not Linux"
		return 1
	fi
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# install_and_trust_CA_cert
#   Usage: install_and_trust_CA_cert <ca_server_root> <nss-db-directory>
#
# This will check and install CA certificate in a given nss-db
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
install_and_trust_CA_cert(){
	local ca_server_root="$1"
	local nss_db_dir="$2"
	local rc=0
	ca_cert_nick=`cat $ca_server_root/conf/CS.cfg | grep "ca.cert.signing.nickname="|  cut -d "=" -f 2`
	ca_nss_dir="$ca_server_root/alias"
	rlLog "CA cert nickname = $ca_cert_nick"
	rlRun "certutil -d $ca_nss_dir -L -n \"$ca_cert_nick\" -a > $nss_db_dir/ca_cert.pem"
	rlRun "certutil -d $nss_db_dir -A -n \"$ca_cert_nick\" -i $nss_db_dir/ca_cert.pem -t \"CT,CT,CT\" "
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# install_and_trust_KRA_cert
#   Usage: install_and_trust_KRA_cert <kra_server_root> <nss-db-directory>
#
# This will check and install CA certificate in a given nss-db
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
install_and_trust_KRA_cert(){
        local kra_server_root="$1"
        local nss_db_dir="$2"
        local rc=0
        kra_cert_nick=`cat $kra_server_root/conf/CS.cfg | grep "kra.cert.subsystem.nickname="|  cut -d "=" -f 2`
        kra_nss_dir="$kra_server_root/alias"
        rlLog "KRA cert nickname = $kra_cert_nick"
        rlRun "certutil -d $kra_nss_dir -L -n \"$kra_cert_nick\" -a > $nss_db_dir/kra_cert.pem"
        rlRun "certutil -d $nss_db_dir -A -n \"$kra_cert_nick\" -i $nss_db_dir/kra_cert.pem -t \"CT,CT,CT\" "
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# install_and_trust_user_cert
#   Usage: install_and_trust_user_cert <certificate pem file> <nickname> <nss-db-directory>
#
# This will check and install user certificate in a given nss-db
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
install_and_trust_user_cert(){
        local cert_pem_file="$1"
        local user_cert_nick="$2"
        local nss_db_dir="$3"
        rlRun "certutil -d $nss_db_dir -A -n \"$user_cert_nick\" -i $cert_pem_file -t \"u,u,u\" "
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# forward_system_clock
#   Usage: forward_system_clock <number_of_days>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
forward_system_clock(){
        local number_of_days=$1
        rlLog "Current Date/Time: $(date)"
        rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        local cur_date=$(date)
        rlLog "Move system to $cur_date + $number_of_days days ahead"
        rlRun "chronyc -a -m 'offline' 'settime $cur_date + $number_of_days days' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# reverse_system_clock
#   Usage: reverse_system_clock <number_of_days>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
reverse_system_clock(){
        local numdays=$1
        rlLog "number_of_days=$numdays"
        rlLog "Current Date/Time: $(date)"
        local new_string="$numdays days ago"
        local new_date=$(date -d "$new_string")
        rlRun "chronyc -a -m 'settime $new_date' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
        rlAssertGrep "200 OK" "$TmpDir/chrony.out"
        rlLog "Date after modifying using chrony: $(date)"
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#       replace_string_in_a_file <file_name> <original_string> <replace_string>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
replace_string_in_a_file()
{
        local file_name=$1
        local original_string=$2
        local replace_string=$3
        local rc=0
        temp_file="$file_name.temp"
        rlRun "sed 's/$original_string/$replace_string/g' $file_name > $temp_file"
        cp $temp_file $file_name
        cat $file_name | grep $replace_string
        if [ $? -ne 0 ] ; then
                rlLog "$file_name did not get replaced with $replace_string"
                rc=1
        fi
        return $rc
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#       scep_do_enroll_with_sscep <scep_enroll_pin> <scep_enroll_url> <scep_host_ipaddr> <temp_dir> <fingerprint>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
scep_do_enroll_with_sscep()
{
        local scep_enroll_pin=$1
        local scep_enroll_url=$2
        local ipaddress=$3
        local temp_dir=$4
        local digest=$5
        local rc=0

        rlRun "/bin/rm -f $temp_dir/local.csr $temp_dir/local.key $temp_dir/ca.crt $temp_dir/cert.crt"

        #generate a key
        rlLog "/usr/bin/mkrequest -ip $ipaddress $scep_enroll_pin $digest"
        rlRun "/usr/bin/mkrequest -ip $ipaddress $scep_enroll_pin $digest > $temp_dir/gen_key"

        #get ca cert
        rlLog "/usr/bin/sscep getca -c $temp_dir/ca.crt -u $scep_enroll_url"
        rlRun "/usr/bin/sscep getca -c $temp_dir/ca.crt -u $scep_enroll_url > $temp_dir/getca_out"

        #submit enrollment request
        rlLog "/usr/bin/sscep enroll -f $temp_dir/sscep.conf -c $temp_dir/ca.crt -k $temp_dir/local.key -r $temp_dir/local.csr -S $digest -l $temp_dir/cert.crt -u $scep_enroll_url"
        rlRun "/usr/bin/sscep enroll -f $temp_dir/sscep.conf -c $temp_dir/ca.crt -k $temp_dir/local.key -r $temp_dir/local.csr -S $digest -l $temp_dir/cert.crt -u $scep_enroll_url > $temp_dir/scep_enroll.out"
        if [ $? -ne 0 ] ; then
                rc=1
        fi

        return $rc
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# disable_ca_nonce
#   Usage: disable_ca_nonce <ca_server_root>
#
# Disable Nonce -- no session id required for command line requests
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
disable_ca_nonce(){
        local ca_tomcat_name=$1
        local rc=0
        rlLog "Configuring ca.enableNonces=false ..."
        ca_config_file="/var/lib/pki/$ca_tomcat_name/ca/conf/CS.cfg"
        temp_file="$ca_config_file.temp"
        search_string="ca.enableNonces=true"
        replace_string="ca.enableNonces=false"
        rlRun "sed 's/$search_string/$replace_string/g' $ca_config_file > $temp_file"
        cp $temp_file $ca_config_file
        chown pkiuser:pkiuser $ca_config_file
        cat $ca_config_file | grep $replace_string
        if [ $? -eq 0 ] ; then
                rhcs_stop_instance $ca_tomcat_name
                rhcs_start_instance $ca_tomcat_name
        else
                lLog "$ca_config_file did not get configured with $replace_string"
                rc=1
        fi
        return $rc
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# enable_ca_nonce
#   Usage: enable_ca_nonce <ca_server_root>
#
# Enable Nonce -- session id is required for command line requests
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
enable_ca_nonce(){
        local ca_tomcat_name=$1
        local rc=0
        rlLog "Configuring ca.enableNonces=true ..."
        ca_config_file="/var/lib/pki/$ca_tomcat_name/ca/conf/CS.cfg"
        temp_file="$ca_config_file.temp"
        search_string="ca.enableNonces=false"
        replace_string="ca.enableNonces=true"
        rlRun "sed 's/$search_string/$replace_string/g' $ca_config_file > $temp_file"
        cp $temp_file $ca_config_file
        chown pkiuser:pkiuser $ca_config_file
        cat $ca_config_file | grep $replace_string
        if [ $? -eq 0 ] ; then
                rhcs_stop_instance $ca_tomcat_name
                rhcs_start_instance $ca_tomcat_name
        else
                rlLog "$ca_config_file did not get configured with $replace_string"
                rc=1
        fi
        return $rc
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# importP12File Usage:
#       importP12File <P12FileLocation> <P12FilePassword> <nssdbDirectory> <nssdbPassword> <cert_nickname>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
importP12File()
{
        local cert_p12file=$1
        local p12file_password=$2
        local nssdb_dir=$3
        local nss_db_password=$4
        local cert_nickname=$5
        local rc=0
        exp=$nssdb_dir/expfile.out
        tmpout=$nssdb_dir/tmpout.out

        rlLog "cert_p12file = $cert_p12file"
        rlLog "nss_db_dir = $nssdb_dir"
        rlRun "echo \"$nss_db_password\" > $nssdb_dir/passwd_certdb"
	create_certdb $nssdb_dir $nss_db_password
        rlRun "echo \"$p12file_password\" > $nssdb_dir/cert_p12_password"
        local cmd="pk12util -i $cert_p12file -d $nssdb_dir -w $nssdb_dir/cert_p12_password"
        echo "set timeout 5" > $exp
        echo "set force_conservative 0" >> $exp
        echo "set send_slow {1 .1}" >> $exp
        echo "spawn $cmd" >> $exp
        echo 'expect "*Password*: "' >> $exp
        echo "send -s -- \"$nss_db_password\r\"" >> $exp
        echo 'expect eof ' >> $exp
        rlLog "cat $exp"
        /usr/bin/expect $exp > $tmpout 2>&1
        if [ $? = 0 ]; then
                cat $tmpout | grep "pk12util: PKCS12 IMPORT SUCCESSFUL"
                if [ $? = 0 ]; then
                        rlPass "pk12util command executed successfully"
                        rlRun "certutil -L -d $nssdb_dir | grep $cert_nickname" 0 "Verify certificate is installed"
                else
                        rlFail "ERROR: Certificate is not installed in $nssdb_dir"
                        rc=1
                fi

        else
                rlFail "ERROR: pk12util execution failed."
        fi
        return $rc
}



# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# check_coredump
#   Usage: check_coredump
#
# This will check for any coredump messages in abrt output and try to
# generate backtrace.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
check_coredump(){

        /usr/bin/abrt-cli list | grep Directory |  awk '{print $2}'
                crashes=`/usr/bin/abrt-cli list | grep Directory |  awk '{print $2}' | wc -l`
                if [ $crashes -ne 0 ]; then
                        echo "Crash detected."
                        for dir in `/usr/bin/abrt-cli list | grep Directory |  awk '{print $2}'`; do
                                cd $dir
                                /usr/bin/abrt-action-install-debuginfo -v;
                                /usr/bin/abrt-action-generate-backtrace -v;
                                /usr/bin/rhts-submit-log -l backtrace
                                /usr/bin/reporter-mailx -v
                        done
                else
                        echo "No crash detected."
                fi


} #check_coredump

#############################################################################
# makereport Usage: (generates summary report)
#       makereport <full_path_and_name_for_report_location>
#############################################################################

makereport()
{
    #check_coredump
    local report=$1
    if [ -n "$report" ];then
        touch $report
    else
        if [ ! -w "$report" ];then
            report=/tmp/rhts.report.$RANDOM.txt
            touch $report
        else
            touch $report
        fi
    fi
    # capture the result and make a simple report
    local total=`rlJournalPrintText | grep "RESULT" | wc -l`
    local unfinished=`rlJournalPrintText | grep "RESULT" | grep "\[unfinished\]" | wc -l`
    local pass=`rlJournalPrintText | grep "RESULT" | grep "\[   PASS   \]" | wc -l`
    local fail=`rlJournalPrintText | grep "RESULT" | grep "\[   FAIL   \]" | wc -l`
    local abort=`rlJournalPrintText | grep "RESULT" | grep "\[  ABORT   \]" | wc -l`
    if rlJournalPrintText | grep "^:: \[   FAIL   \] :: RESULT: $"
    then
        total=$((total-1))
        fail=$((fail-1))
    fi
    echo "========================== Final Pass/Fail Report ===========================" > $report
    echo "  Test Date: `date` " >> $report
    echo "     Total : [$total] "  >> $report
    echo "     Passed: [$pass] "   >> $report
    echo "     Failed: [$fail] "   >> $report
    echo " Unfinished: [$unfinished] "   >> $report
    echo "     Abort : [$abort]"   >> $report
    echo "     Crash : [$crashes]" >> $report
    echo " ---------------------------------------------------------" >> $report
    rlJournalPrintText | grep "RESULT" | grep "\[   PASS   \]"| sed -e 's/:/ /g' -e 's/RESULT//g' >> $report
    echo "" >> $report
    rlJournalPrintText | grep "RESULT" | grep "\[   FAIL   \]"| grep -v "^:: \[   FAIL   \] :: RESULT: $" | sed -e 's/:/ /g' -e 's/RESULT//g'  >> $report
    echo "" >> $report
    rlJournalPrintText | grep "RESULT" | grep "\[unfinished\]"| sed -e 's/:/ /g' -e 's/RESULT//g' >> $report
    echo "" >> $report
    rlJournalPrintText | grep "RESULT" | grep "\[  ABORT   \]"| sed -e 's/:/ /g' -e 's/RESULT//g' >> $report
    echo "===========================[$report]===============================" >> $report
    cat $report
    echo "[`date`] test summary report saved as: $report"
    echo ""
} #makereport


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
#################################################################################
#This functions is alternate of importP12File function,
#importP12FileNew <P12FileLocation> <P12FilePassword> <nssdbDirectory> <nssdbPassword> <cert_nickname>
#################################################################################
importP12FileNew()                                                                                                                                                                            
{                                                                                                                                                                                             
        local cert_p12file=$1                                                                                                                                                                 
        local p12file_password=$2                                                                                                                                                             
        local nssdb_dir=$3                                                                                                                                                                    
        local nss_db_password=$4                                                                                                                                                              
        local cert_nickname=$5                                                                                                                                                                
        rlLog "cert_p12file = $cert_p12file"                                                                                                                                                  
        rlLog "nss_db_dir = $nssdb_dir"
	rlLog "Verify $nssdb_dir is already NSS Database"
	if [ -d "$nssdb_dir" ]; then
		rlLog "$nssdb_dir is already a existing database we don't create a new one"
	else
		rlLog "$nssdb_dir doesn't exist"
		rlRun "pki -d $nssdb_dir -c $nss_db_password client-init" 0 "Initialiaize $nssdb_dir with password $nss_db_password"
	fi
        rlRun "pk12util -i $cert_p12file -d $nssdb_dir -K $nss_db_password -W $p12file_password"
        if [ $? = 0 ]; then                                                                                                                                                                   
                        rlPass "pk12util command executed successfully"                                                                                                                       
                        rlRun "certutil -L -d $nssdb_dir | grep $cert_nickname" 0 "Verify certificate is installed"                                                                           
                else                                                                                                                                                                          
                        rlFail "ERROR: pk12util execution failed."                                                                                                                            
                        rlFail "ERROR: Certificate is not installed in $nssdb_dir"                                                                                                            
                        rc=1                                                                                                                                                                  
                fi                                                                                                                                                                            
        return $rc                                                                                                                                                                            
}
###############################################
#set_time_source setups up chrony with a clocksource 
#set_time_source $timeserver
###############################
set_time_source()
{
	# first stop the existing chrony daemon
	local clocksource=$1
	local chrony_config_file=/etc/chrony.conf
	local chrony_config_backupfile=/etc/chrony.conf.backup
	rlLog "Stopping chrony daemon"
	rlRun "systemctl stop chronyd"
	rlLog "Backup existing chrony config file"
	rlRun "/usr/bin/cp -f $chrony_config_file $chrony_config_backupfile"
	# we setup initial chrony configuration
	echo -e "server $clocksource" > $chrony_config_file
	echo -e "stratumweight 0" >> $chrony_config_file
	echo -e "driftfile /var/lib/chrony/drift" >> $chrony_config_file
	echo -e "rtcsync" >> $chrony_config_file
	echo -e "makestep 10 3" >> $chrony_config_file
	echo -e "bindcmdaddress 127.0.0.1" >> $chrony_config_file
	echo -e "bindcmdaddress ::1" >> $chrony_config_file
	echo -e "keyfile /etc/chrony.keys" >> $chrony_config_file
	echo -e "commandkey 1" >> $chrony_config_file
	echo -e "generatecommandkey" >> $chrony_config_file
	echo -e "noclientlog" >> $chrony_config_file
	echo -e "logchange 0.5" >> $chrony_config_file
	echo -e "logdir /var/log/chrony" >> $chrony_config_file
	echo -e "log measurements statistics tracking" >> $chrony_config_file
	#restore the selinux context just in case
	rlRun "restorecon -v $chrony_config_file"
	rlRun "systemctl start chronyd"
	#Run makestep to sync the time 
	rlLog "Sync time"
	rlRun "chronyc -a makestep 1> /tmp/chrony.out"
	rlAssertGrep "200 OK" "/tmp/chrony.out"
	
}
#################################################
#cert-hold_expect_data <file where expect data will be written> <file_containing_certificate_details> 
#<command line to be spawned>
##################################################
cert-hold_expect_data()
{
        local expfile=$1
        local cert_info=$2
        local cmdline=$3
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local start_date=$(cat $cert_info | grep cert_start_date | cut -d- -f2)
        local end_date=$(cat $cert_info | grep cert_end_date | cut -d- -f2)
        local requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        echo "set timeout 5" > $expfile
        echo "spawn $cmdline" >> $expfile
        echo "expect -exact \"Placing certificate on-hold:\\r" >> $expfile
        echo "   Serial Number: $cert_serialNumber\\r" >> $expfile
        echo "   Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain\\r" >> $expfile
        echo "   Subject: $requestdn\\r" >> $expfile
        echo "   Status: VALID\\r" >> $expfile
        echo "   Not Before: $start_date\\r" >> $expfile
        echo "   Not After: $end_date\\r" >> $expfile
        echo "Are you sure \(Y/N\)? \"" >> $expfile
        echo "send -- \"y\\r\"" >> $expfile
        echo "expect eof" >> $expfile
}
#################################################
#cert-revoke_expect_data <file where expect data will be written> <file_containing_certificate_details> 
#<command line to be spawned>
##################################################
cert-revoke_expect_data()
{
        local expfile=$1
        local cert_info=$2
        local cmdline=$3
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local start_date=$(cat $cert_info | grep cert_start_date | cut -d- -f2)
        local end_date=$(cat $cert_info | grep cert_end_date | cut -d- -f2)
        local requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        local cmd=$cmdline
        echo "set timeout 5" > $expfile
        echo "spawn $cmdline" >> $expfile
        echo "expect -exact \"Revoking certificate:\\r" >> $expfile
        echo "   Serial Number: $cert_serialNumber\\r" >> $expfile
        echo "   Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain\\r" >> $expfile
        echo "   Subject: $requestdn\\r" >> $expfile
        echo "   Status: VALID\\r" >> $expfile
        echo "   Not Before: $start_date\\r" >> $expfile
        echo "   Not After: $end_date\\r" >> $expfile
        echo "Are you sure \(Y/N\)? \"" >> $expfile
        echo "send -- \"y\\r\"" >> $expfile
        echo "expect eof" >> $expfile
}
#################################################
#cert-release-hold_expect_data <file where expect data will be written> <file_containing_certificate_details> 
#<command line to be spawned>
##################################################
cert-release-hold_expect_data()
{
        local expfile=$1
        local cert_info=$2
        local cmdline=$3
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local start_date=$(cat $cert_info | grep cert_start_date | cut -d- -f2)
        local end_date=$(cat $cert_info | grep cert_end_date | cut -d- -f2)
        local requestdn=$(cat $cert_info | grep cert_requestdn | cut -d- -f2)
        echo "set timeout 5" > $expfile
        echo "spawn $cmdline" >> $expfile
        echo "expect -exact \"Placing certificate off-hold:\\r" >> $expfile
        echo "   Serial Number: $cert_serialNumber\\r" >> $expfile
        echo "   Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain\\r" >> $expfile
        echo "   Subject: $requestdn\\r" >> $expfile
        echo "   Status: REVOKED\\r" >> $expfile
        echo "   Not Before: $start_date\\r" >> $expfile
        echo "   Not After: $end_date\\r" >> $expfile
        echo "Are you sure \(Y/N\)? \"" >> $expfile
        echo "send -- \"y\\r\"" >> $expfile
        echo "expect eof" >> $expfile
}
##################################################
# Returns Subsystem used by particular Topology
#get_topo_stack takes 2 arguments, 
#1. Role 
#2. Ouptut file to save the topology details
#Examples:
#get_topo_stack MASTER $TmpDir/topo_file
#local KRA_INST=$(cat $TmpDir/topo_file | grep MY_KRA | cut -d= -f2)
#local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
################################################
get_topo_stack()
{
	MY_ROLE=$1
	TOPO_FILE=$2
	if [ $MY_ROLE == "MASTER" ]; then
        	echo "MY_CA=ROOTCA" > $TOPO_FILE
	        echo "MY_KRA=KRA3" >> $TOPO_FILE
        	echo "MY_OCSP=OCSP3" >> $TOPO_FILE
	        echo "MY_TKS=TKS1" >> $TOPO_FILE
		echo "MY_TPS=TPS1" >> $TOPO_FILE
		echo "MY_SUBCA=SUBCA1" >> $TOPO_FILE
                echo "MY_CLONE_CA=CLONE_CA1" >> $TOPO_FILE
                echo "MY_CLONE_KRA=CLONE_KRA1" >> $TOPO_FILE
                echo "MY_CLONE_OCSP=CLONE_OCSP1" >> $TOPO_FILE
                echo "MY_CLONE_TKS=CLONE_TKS1" >> $TOPO_FILE
		echo "MY_CLONE_TPS=CLONE_TPS1" >> $TOPO_FILE
	elif [ $MY_ROLE == "SUBCA1" ]; then
        	echo "MY_CA=SUBCA1" > $TOPO_FILE
	        echo "MY_KRA=KRA1" >> $TOPO_FILE
        	echo "MY_OCSP=OCSP1" >> $TOPO_FILE
	elif [ $MY_ROLE = "SUBCA2" ]; then
        	echo "MY_CA=SUBCA2" >> $TOPO_FILE
	        echo "MY_KRA=KRA2" >> $TOPO_FILE
        	echo "MY_OCSP=OCSP2" >> $TOPO_FILE
	elif [ $MY_ROLE = "CLONECA1" ]; then
        	echo "MY_CA=CLONE_CA1" > $TOPO_FILE
	        echo "MY_KRA=CLONE_KRA1" >> $TOPO_FILE
        	echo "MY_OCSP=CLONE_OCSP1" >> $TOPO_FILE
	elif [ $MY_ROLE = "CLONECA2" ]; then
        	echo "MY_CA=CLONE_CA2" > $TOPO_FILE
	        echo "MY_KRA=CLONE_KRA2" >> $TOPO_FILE
        	echo "MY_OCSP=CLONE_OCSP2" >> $TOPO_FILE
	fi
}
#################################################################
#
#When using curl to query/update a resource in console,
#use this function to process the output receieved
#
##################################################################
process_curl_output()
{
        output_file=$1
        sed -i "s/\&/\n&/g" $output_file
        sed -i "s/+//g"  $output_file
        sed -i "s/^&//g" $output_file
        sed -i "s/%3A/":"/g" $output_file
        sed -i "s/%3B/":"/g" $output_file
        sed -i "s/%3D/"="/g" $output_file
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
### This script Creates Posix Users with inetOrgPerson , PosixAccount and ShadowAccount ObjectClass
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
create_dir_user()
{
local SUFFIX=$1
local MAX=`expr $2`
local COUNT=`expr 1`
local temp=`expr 0`
local UIDVALUE=14583100
local GIDVALUE=14564100
local DOMAIN=$(hostname)

                while [ "$COUNT" -le "$MAX" ]
                do

                                echo -e "dn: uid=idmuser$(expr $COUNT),ou=People,$SUFFIX"
                                echo -e "uid: idmuser$(expr $COUNT)"
                                echo -e "cn: idmuser$(expr $COUNT)"
                                echo -e "sn: $(expr $COUNT)"
                                echo -e "objectClass: top"
                                #echo -e "objectClass: account"
                                echo -e "objectClass: posixAccount"
                                echo -e "objectClass: inetOrgPerson"
                                echo -e "loginShell: /bin/sh"
                                echo -e "homeDirectory: /home/student$(expr $COUNT)"
                                uidNumber=$(expr $UIDVALUE + $temp)
                                echo -e "uidNumber: $uidNumber"
                                echo -e "gidNumber: $GIDVALUE"
                                echo -e "userPassword: {SSHA}j3lBh1Seqe4rqF1+NuWmjhvtAni1JC5A"
                                echo -e "mail: idmuser$(expr $COUNT)@$DOMAIN"
                                echo -e "gecos: idmuser$(expr $COUNT) User"
                                echo -e "l: India\n"
                                COUNT=`expr $COUNT + 1`
                                temp=`expr $temp + 1`

                done
                COUNT=`expr 1`
                echo -e "dn: cn=idmusers,ou=Groups,$SUFFIX"
                echo -e "objectClass: posixGroup"
                echo -e "objectClass: top"
                echo -e "objectClass: groupOfUniqueNames"
                echo -e "cn: idmusers"
                echo -e "userPassword: {crypt}x"
                echo -e "gidNumber: $GIDVALUE"
                while [ "$COUNT" -le "$MAX" ]
                do
                        echo -e "memberUid: idmuser$COUNT"
                        COUNT=`expr $COUNT + 1`
                done
}

#################################################################
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
### This script creates a tpsclient enrollment file
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
gen_enroll_data_file()
{
        tps_host=$1
        tps_port=$2
        tokenid=$3
        ldapuser=$4
        ldap_userpwd=$5
        data_file=$6
        new_pin="redhat"
        rlLog "$data_file"
        echo "op=var_set name=ra_host value=$tps_host" > $data_file
        echo "op=var_set name=ra_port value=$tps_port" >> $data_file
        echo "op=var_set name=ra_uri value=/tps/tps" >> $data_file
        echo "op=token_set cuid=$tokenid msn=01020304 app_ver=6FBBC105 key_info=0101 major_ver=0 minor_ver=0" >> $data_file
        echo "op=token_set auth_key=404142434445464748494a4b4c4d4e4f" >> $data_file
        echo "op=token_set mac_key=404142434445464748494a4b4c4d4e4f" >> $data_file
        echo "op=token_set kek_key=404142434445464748494a4b4c4d4e4f" >> $data_file
        echo "op=ra_enroll uid=$ldapuser pwd=$ldap_userpwd new_pin=$new_pin num_threads=1" >> $data_file
        echo "op=exit" >> $data_file
}
############################################################################################################
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
### This script createa a tpsclient format file
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
gen_format_data_file()
{
        tps_host=$1
        tps_port=$2
        tokenid=$3
        ldapuser=$4
        ldap_userpwd=$5
        data_file=$6
        new_pin="redhat"
        rlLog "$data_file"
        echo "op=var_set name=ra_host value=$tps_host" > $data_file
        echo "op=var_set name=ra_port value=$tps_port" >> $data_file
        echo "op=var_set name=ra_uri value=/tps/tps" >> $data_file
        echo "op=token_set cuid=$tokenid msn=01020304 app_ver=6FBBC105 key_info=0101 major_ver=0 minor_ver=0" >> $data_file
        echo "op=token_set auth_key=404142434445464748494a4b4c4d4e4f" >> $data_file
        echo "op=token_set mac_key=404142434445464748494a4b4c4d4e4f" >> $data_file
        echo "op=token_set kek_key=404142434445464748494a4b4c4d4e4f" >> $data_file
        echo "op=ra_format uid=$ldapuser pwd=$ldap_userpwd new_pin=$new_pin num_threads=1 extensions=tokenType=userKey" >> $data_file
        echo "op=exit" >> $data_file
}
############################################################################################################
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
### This script creates a tpsclient pin reset file
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
gen_pin_reset_data_file()
{
        tps_host=$1
        tps_port=$2
        tokenid=$3
        ldapuser=$4
        ldap_userpwd=$5
        data_file=$6
        new_pin="redhat"
        rlLog "$data_file"
        echo "op=var_set name=ra_host value=$tps_host" > $data_file
        echo "op=var_set name=ra_port value=$tps_port" >> $data_file
        echo "op=var_set name=ra_uri value=/tps/tps" >> $data_file
        echo "op=token_set cuid=$tokenid msn=01020304 app_ver=6FBBC105 key_info=0101 major_ver=0 minor_ver=0" >> $data_file
        echo "op=token_set auth_key=404142434445464748494a4b4c4d4e4f" >> $data_file
        echo "op=token_set mac_key=404142434445464748494a4b4c4d4e4f" >> $data_file
        echo "op=token_set kek_key=404142434445464748494a4b4c4d4e4f" >> $data_file
        echo "op=ra_reset_pin uid=$ldapuser pwd=$ldap_userpwd new_pin=$new_pin num_threads=1" >> $data_file
        echo "op=exit" >> $data_file
}
#################################################################

