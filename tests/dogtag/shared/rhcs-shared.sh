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
#	disable_ca_nonce <ca_server_root>
#	enable_ca_nonce <ca_server_root>
#	importP12File <P12FileLocation> <P12FilePassword> <nssdbDirectory> <nssdbPassword> <cert_nickname>
#
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
        $command 2> /tmp/errormsg.out
	sed 's/"//g' /tmp/errormsg.out > /tmp/errormsg_clean.out
        actual=`cat /tmp/errormsg_clean.out`
        if [[ "$actual" = "$expmsg" ]] ; then
                rlPass "Error message as expected: $actual"
		return 0
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
	INSTANCE_ID=$1
	echo $FLAVOR | grep "Fedora"
        if [ $? -eq 0 ] ; then
		rlLog "Executing: systemctl start pki-tomcatd@pki-tomcat.service"
		systemctl start pki-tomcatd@pki-tomcat.service
	else
		service $INSTANCE_ID start
	fi
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
        INSTANCE_ID=$1
	echo $FLAVOR | grep "Fedora"
        if [ $? -eq 0 ] ; then
		rlLog "Executing: systemctl stop pki-tomcatd@pki-tomcat.service"
		systemctl stop pki-tomcatd@pki-tomcat.service
	else
		service $INSTANCE_ID stop
	fi
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
		rlRun "source /opt/rhqa_pki/env.sh"
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
                        classpath="./:/usr/lib64/java/jss4.jar:/usr/share/java/ldapjdk.jar:/usr/share/java/pki/pki-certsrv.jar:/usr/share/java/pki/pki-cmscore.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/pki/pki-tools.jar:/usr/share/java/xml-commons-resolver.jar:/usr/share/java/xerces-j2.jar:"
                else
                        classpath="./:/usr/lib/java/jss4.jar:/usr/share/java/ldapjdk.jar:/usr/share/java/pki/pki-certsrv.jar:/usr/share/java/pki/pki-cmscore.jar:/usr/share/java/pki/pki-nsutil.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/share/java/pki/pki-tools.jar:/usr/share/java/xml-commons-resolver.jar:/usr/share/java/xerces-j2.jar:"
                fi
		echo "export CLASSPATH=$classpath" >> /opt/rhqa_pki/env.sh
                return 0
        else
                rlLog "OS flavor is not Linux"
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
# disable_ca_nonce
#   Usage: disable_ca_nonce <ca_server_root>
#
# Disable Nonce -- no session id required for command line requests
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
disable_ca_nonce(){
	local ca_server_root=$1
	local rc=0
	rlLog "Configuring ca.enableNonces=false ..."
        ca_config_file="$ca_server_root/conf/CS.cfg"
        temp_file="$ca_config_file.temp"
        search_string="ca.enableNonces=true"
        replace_string="ca.enableNonces=false"
        rlRun "sed 's/$search_string/$replace_string/g' $ca_config_file > $temp_file"
        cp $temp_file $ca_config_file
        chown pkiuser:pkiuser $ca_config_file
        cat $ca_config_file | grep $replace_string
        if [ $? -eq 0 ] ; then
		rhcs_stop_instance
                rhcs_start_instance
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
        local ca_server_root=$1
	local rc=0
        rlLog "Configuring ca.enableNonces=true ..."
        ca_config_file="$ca_server_root/conf/CS.cfg"
        temp_file="$ca_config_file.temp"
        search_string="ca.enableNonces=false"
        replace_string="ca.enableNonces=true"
        rlRun "sed 's/$search_string/$replace_string/g' $ca_config_file > $temp_file"
        cp $temp_file $ca_config_file
        chown pkiuser:pkiuser $ca_config_file
        cat $ca_config_file | grep $replace_string
        if [ $? -eq 0 ] ; then
		rhcs_stop_instance
                rhcs_start_instance
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
        rlRun "certutil -d $nssdb_dir -N -f $nssdb_dir/passwd_certdb"
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
