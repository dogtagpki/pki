#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/bugzilla/pki-core-bug
#   Description: CS-backup-bug verification
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Roshni Pattath <rpattath@redhat.com> 
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2013 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include rhts environment
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/env.sh

########################################################################
#pki-user-cli-user-ca.sh should be first executed prior to bug verification
########################################################################

########################################################################
# Test Suite Globals
########################################################################

run_CS-backup-bug-verification(){
 
     rlPhaseStartTest "bug_1061442: CS backup bug"

        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1061442"

	#Checking if the CS.cfg.bak file exists and restart fails if the file is moved to a file with a different name

	rlLog "Checking if the CS.cfg.bak file exists and restart fails if the file is moved to a file with a different name"
	ca_config_file="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ca/conf/CS.cfg"
	ca_config_backup_file="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ca/conf/CS.cfg.bak"
	rlAssertExists "$ca_config_file"
	rlAssertExists "$ca_config_backup_file"	
	num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
	rlRun "mv $ca_config_backup_file /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ca/conf/CS.cfg.bak.saved"
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart fails"
	rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_ca_instance_restart.out 2>&1" 3 "The subsystem instance has a failed status"
	warning_msg1="WARNING:  Since the file '/var/lib/pki/pki-ca-bug/conf/ca/CS.cfg.bak.saved' exists, a"
	warning_msg2="previous backup attempt has failed!  CA backups"
	warning_msg3= "will be discontinued until this issue has been resolved!"
	rlAssertGrep "$warning_msg1" "/tmp/bug_ca_instance_restart.out"
	rlAssertGrep "$warning_msg2" "/tmp/bug_ca_instance_restart.out"
	rlAssertGrep "$warning_msg3" "/tmp/bug_ca_instance_restart.out"
	num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_new = $num_files_orig ]; then
        	rlPass "No backup file created when service restart fails"
        fi
	rlRun "mv /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ca/conf/CS.cfg.bak.saved $ca_config_backup_file"
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
	rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_ca_instance_restart_1.out 2>&1"
	rlAssertGrep "active (running)" "/tmp/bug_ca_instance_restart_1.out"

	#restart of ca subsystem should fail when CS.cfg.bak.saved file exsists in the conf directory	

	rlLog "restart of ca subsystem should fail when CS.cfg.bak.saved file exsists in the conf directory"
	rlRun "cp $ca_config_backup_file /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ca/conf/CS.cfg.bak.saved"
	num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart fails"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_ca_instance_restart_2.out 2>&1" 3 "The subsystem instance has a failed status"
        warning_msg1="WARNING:  Since the file '/var/lib/pki/pki-ca-bug/conf/ca/CS.cfg.bak.saved' exists, a"
        warning_msg2="previous backup attempt has failed!  CA backups"
        warning_msg3= "will be discontinued until this issue has been resolved!"
	rlAssertGrep "$warning_msg1" "/tmp/bug_ca_instance_restart_2.out"
        rlAssertGrep "$warning_msg2" "/tmp/bug_ca_instance_restart_2.out"
        rlAssertGrep "$warning_msg3" "/tmp/bug_ca_instance_restart_2.out"
	num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_new = $num_files_orig ]; then
                rlPass "No backup file created when service restart fails"
        fi
	rlRun "rm -rf /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ca/conf/CS.cfg.bak.saved"
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_ca_instance_restart_1.out 2>&1"
        rlAssertGrep "active (running)" "/tmp/bug_ca_instance_restart_1.out"

	#Toggling between true and false value for the parameter "archive.configuration_file" in CS.cfg

	rlLog "Toggling between true and false value for the parameter \"archive.configuration_file\" in CS.cfg"
	temp_file="$ca_config_file.temp"
	cat $ca_config_file | grep "archive.configuration_file=true"
	if [ $? -eq 0 ]; then
		orig_archive_conf="archive.configuration_file=true"
		new_archive_conf="archive.configuration_file=false"
		num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
		let num_files_orig=$num_files_orig-1
		rlRun "sed 's/$orig_archive_conf/$new_archive_conf/g' $ca_config_file > $temp_file"
		rlRun "sleep 5"
	        rlRun "mv $temp_file $ca_config_file"
		rlRun "sleep 5"
		rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
		num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
		let num_files_new=$num_files_new-1
		if [ $num_files_new = $num_files_orig ]; then
			rlPass "Test success"
		fi
		rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ca/conf/ > /tmp/conf_files.out"
		rlAssertGrep "CS.cfg.bak" "/tmp/conf_files.out"
		rlAssertNotGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ca/archives/CS.cfg.bak." "/tmp/conf_files.out"
		rlRun "sed 's/$new_archive_conf/$orig_archive_conf/g' $ca_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $ca_config_file"
                rlRun "sleep 5"
		rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
		num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
		if [ $num_files_orig -lt $num_files_new ]; then
                        rlPass "Test success"
                fi
		rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ca/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ca/archives/CS.cfg.bak." "/tmp/conf_files.out"
	else
		orig_archive_conf="archive.configuration_file=false"
                new_archive_conf="archive.configuration_file=true"
		num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
                let num_files_orig=$num_files_orig-1
                rlRun "sed 's/$orig_archive_conf/$new_archive_conf/g' $ca_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $ca_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
		num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
		let num_files_new=$num_files_new-1
		if [ $num_files_orig -lt $num_files_new ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ca/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ca/archives/CS.cfg.bak." "/tmp/conf_files.out"
		rlRun "sed 's/$new_archive_conf/$orig_archive_conf/g' $ca_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $ca_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
		if [ $num_files_new = $num_files_orig ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ca/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak" "/tmp/conf_files.out"
                rlAssertNotGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ca/archives/CS.cfg.bak." "/tmp/conf_files.out"
	fi

	# Dangling symlink test

	rlLog "Dangling symlink test - CA CS.cfg.bak"
	if [ $(ls -alrt /var/lib/pki/pki-ca-bug/ca/conf/CS.cfg.bak | cut -f 11 -d ' ') = '->' ]; then
		symlink_target=$(ls -alrt /var/lib/pki/pki-ca-bug/ca/conf/CS.cfg.bak | cut -f 12 -d ' ')
	else
		symlink_target=$(ls -alrt /var/lib/pki/pki-ca-bug/ca/conf/CS.cfg.bak | cut -f 11 -d ' ')
	fi
	num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
	rlRun "rm -rf /var/lib/pki/pki-ca-bug/ca/conf/CS.cfg.bak"
	rlRun "sleep 5"
	rlRun "ln -s /var/lib/pki/pki-ca-bug/ca/conf/archives/CS.cfg.bak.saved /var/lib/pki/pki-ca-bug/ca/conf/CS.cfg.bak"
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart should fail with dangling symlink error"
	rlRun "sleep 5"
	rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ca_restart.out" 3 "subsystem service fails to restart"
	rlAssertGrep "WARNING:  The file '/var/lib/pki/pki-ca-bug/conf/ca/CS.cfg.bak' is a dangling symlink" "/tmp/ca_restart.out"
	rlAssertGrep "which suggests that the previous backup file has" "/tmp/ca_restart.out"
	rlAssertGrep "been removed!  CA backups will be discontinued" "/tmp/ca_restart.out"
	rlAssertGrep "until this issue has been resolved!" "/tmp/ca_restart.out"
	num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
	rlRun "rm -rf /var/lib/pki/pki-ca-bug/ca/conf/CS.cfg.bak"
	rlRun "sleep 5"
        rlRun "ln -s $symlink_target /var/lib/pki/pki-ca-bug/ca/conf/CS.cfg.bak"
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
	rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ca_restart1.out"
	rlAssertGrep "active (running)" "/tmp/ca_restart1.out"

	# Remove archive.configuration_file from CS.cfg

	rlLog "Remove archive.configuration_file from CS.cfg"
	archive_conf="archive.configuration_file=true"
	num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
	rlRun "sed '/$archive_conf/d' $ca_config_file > $temp_file"
	rlRun "sleep 5"
        rlRun "mv $temp_file $ca_config_file"
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
	num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
	rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ca/conf/ > /tmp/conf_files.out"
        rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ca/archives/CS.cfg.bak." "/tmp/conf_files.out"
	num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
	echo "archive.configuration_file=true" >> $ca_config_file
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
	num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ca/conf/ > /tmp/conf_files.out"
        rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ca/archives/CS.cfg.bak." "/tmp/conf_files.out"

	# Move CS.cfg file aside and touch CS.cfg
	
	rlLog "Move CS.cfg file aside and touch CS.cfg"
	saved_ca_config_file=$ca_config_file.saved
	num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
	rlRun "mv $ca_config_file $saved_ca_config_file"
	rlRun "touch $ca_config_file"
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart should fail with corrupted CS.cfg"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ca_restart.out" 3 "subsystem service fails to restart"
        rlAssertGrep "WARNING:  The '/var/lib/pki/pki-ca-bug/conf/ca/CS.cfg' is empty!" "/tmp/ca_restart.out"
        rlAssertGrep "CA backups will be discontinued until this" "/tmp/ca_restart.out"
        rlAssertGrep "issue has been resolved!" "/tmp/ca_restart.out"
	num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_new = $num_files_orig ]; then
                rlPass "Test success"
        fi
	num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
	rlRun "rm -rf $ca_config_file"
	rlRun "mv $saved_ca_config_file $ca_config_file"
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ca_restart1.out"
        rlAssertGrep "active (running)" "/tmp/ca_restart1.out"
	num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi

	# Move CS.cfg file aside and create CS.cfg with 8192 bytes

	rlLog "Move CS.cfg file aside and create CS.cfg with 8192 bytes"
	saved_ca_config_file=$ca_config_file.saved
	num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
        rlRun "mv $ca_config_file $saved_ca_config_file"
        rlRun "dd if=$saved_ca_config_file of=$ca_config_file bs=8192 count=1"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ca_restart.out"
        rlAssertGrep "active (running)" "/tmp/ca_restart.out"
	num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
	num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
	rlRun "rm -rf $ca_config_file"
	rlRun "mv $saved_ca_config_file $ca_config_file"
	rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
	rlRun "sleep 5"
	rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ca_restart1.out"
        rlAssertGrep "active (running)" "/tmp/ca_restart1.out"
	num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ca/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi


	#Checking if the KRA's CS.cfg.bak file exists and restart failes if the file is moved to a file with a different name

	rlLog "Checking if the KRA's CS.cfg.bak file exists and restart failes if the file is moved to a file with a different name"
        kra_config_file="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/kra/conf/CS.cfg"
        kra_config_backup_file="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/kra/conf/CS.cfg.bak"
        rlAssertExists "$kra_config_file"
        rlAssertExists "$kra_config_backup_file"
        rlRun "mv $kra_config_backup_file /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/kra/conf/CS.cfg.bak.saved"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart fails"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_kra_instance_restart.out 2>&1" 3 "The subsystem instance has a failed status"
        warning_msg1="WARNING:  Since the file '/var/lib/pki/pki-ca-bug/conf/kra/CS.cfg.bak.saved' exists, a"
        warning_msg2="previous backup attempt has failed!  KRA backups"
        warning_msg3= "will be discontinued until this issue has been resolved!"
        rlAssertGrep "$warning_msg1" "/tmp/bug_kra_instance_restart.out"
        rlAssertGrep "$warning_msg2" "/tmp/bug_kra_instance_restart.out"
        rlAssertGrep "$warning_msg3" "/tmp/bug_kra_instance_restart.out"
        rlRun "mv /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/kra/conf/CS.cfg.bak.saved $kra_config_backup_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_kra_instance_restart_1.out 2>&1"
        rlAssertGrep "active (running)" "/tmp/bug_kra_instance_restart_1.out"

	#restart of kra subsystem should fail when CS.cfg.bak.saved file exsists in the conf directory   

	rlLog "restart of kra subsystem should fail when CS.cfg.bak.saved file exsists in the conf directory"
        rlRun "cp $kra_config_backup_file /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/kra/conf/CS.cfg.bak.saved"
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart fails"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_kra_instance_restart_2.out 2>&1" 3 "The subsystem instance has a failed status"
        warning_msg1="WARNING:  Since the file '/var/lib/pki/pki-ca-bug/conf/kra/CS.cfg.bak.saved' exists, a"
        warning_msg2="previous backup attempt has failed!  KRA backups"
        warning_msg3= "will be discontinued until this issue has been resolved!"
        rlAssertGrep "$warning_msg1" "/tmp/bug_kra_instance_restart_2.out"
        rlAssertGrep "$warning_msg2" "/tmp/bug_kra_instance_restart_2.out"
        rlAssertGrep "$warning_msg3" "/tmp/bug_kra_instance_restart_2.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_new = $num_files_orig ]; then
                rlPass "No backup file created when service restart fails"
        fi
        rlRun "rm -rf /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/kra/conf/CS.cfg.bak.saved"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_kra_instance_restart_1.out 2>&1"
        rlAssertGrep "active (running)" "/tmp/bug_kra_instance_restart_1.out"

	#Toggling between true and false value for the parameter "archive.configuration_file" in KRA's CS.cfg

	rlLog "Toggling between true and false value for the parameter \"archive.configuration_file\" in KRA's CS.cfg"
        temp_file="$kra_config_file.temp"
        cat $kra_config_file | grep "archive.configuration_file=true"
        if [ $? -eq 0 ]; then
                orig_archive_conf="archive.configuration_file=true"
                new_archive_conf="archive.configuration_file=false"
                num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
                let num_files_orig=$num_files_orig-1
                rlRun "sed 's/$orig_archive_conf/$new_archive_conf/g' $kra_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $kra_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_new = $num_files_orig ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/kra/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak" "/tmp/conf_files.out"
                rlAssertNotGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ca/archives/CS.cfg.bak." "/tmp/conf_files.out"
                rlRun "sed 's/$new_archive_conf/$orig_archive_conf/g' $kra_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $kra_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_orig -lt $num_files_new ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/kra/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/kra/archives/CS.cfg.bak." "/tmp/conf_files.out"
        else
                orig_archive_conf="archive.configuration_file=false"
                new_archive_conf="archive.configuration_file=true"
                num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
                let num_files_orig=$num_files_orig-1
                rlRun "sed 's/$orig_archive_conf/$new_archive_conf/g' $kra_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $kra_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_orig -lt $num_files_new ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/kra/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/kra/archives/CS.cfg.bak." "/tmp/conf_files.out"
                rlRun "sed 's/$new_archive_conf/$orig_archive_conf/g' $kra_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $kra_config_file"
		rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_new = $num_files_orig ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/kra/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak" "/tmp/conf_files.out"
                rlAssertNotGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/kra/archives/CS.cfg.bak." "/tmp/conf_files.out"
        fi

	# Dangling symlink test

	rlLog "Dangling symlink test - KRA CS.cfg.bak"
        if [ $(ls -alrt /var/lib/pki/pki-ca-bug/kra/conf/CS.cfg.bak | cut -f 11 -d ' ') = '->' ]; then
                symlink_target=$(ls -alrt /var/lib/pki/pki-ca-bug/kra/conf/CS.cfg.bak | cut -f 12 -d ' ')
        else
                symlink_target=$(ls -alrt /var/lib/pki/pki-ca-bug/kra/conf/CS.cfg.bak | cut -f 11 -d ' ')
        fi
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        rlRun "rm -rf /var/lib/pki/pki-ca-bug/kra/conf/CS.cfg.bak"
        rlRun "sleep 5"
        rlRun "ln -s /var/lib/pki/pki-ca-bug/kra/conf/archives/CS.cfg.bak.saved /var/lib/pki/pki-ca-bug/kra/conf/CS.cfg.bak"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart should fail with dangling symlink error"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/kra_restart.out" 3 "subsystem service fails to restart"
        rlAssertGrep "WARNING:  The file '/var/lib/pki/pki-ca-bug/conf/kra/CS.cfg.bak' is a dangling symlink" "/tmp/kra_restart.out"
        rlAssertGrep "which suggests that the previous backup file has" "/tmp/kra_restart.out"
        rlAssertGrep "been removed!  KRA backups will be discontinued" "/tmp/kra_restart.out"
        rlAssertGrep "until this issue has been resolved!" "/tmp/kra_restart.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        rlRun "rm -rf /var/lib/pki/pki-ca-bug/kra/conf/CS.cfg.bak"
        rlRun "sleep 5"
        rlRun "ln -s $symlink_target /var/lib/pki/pki-ca-bug/kra/conf/CS.cfg.bak"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/kra_restart1.out"
        rlAssertGrep "active (running)" "/tmp/kra_restart1.out"

	# Remove archive.configuration_file from KRA's CS.cfg

	rlLog "Remove archive.configuration_file from KRA's CS.cfg"
        archive_conf="archive.configuration_file=true"
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        rlRun "sed '/$archive_conf/d' $kra_config_file > $temp_file"
        rlRun "sleep 5"
        rlRun "mv $temp_file $kra_config_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        rlRun "ls -alrt /var/lib/pki/pki-ca-bug/kra/conf/ > /tmp/conf_files.out"
        rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/kra/archives/CS.cfg.bak." "/tmp/conf_files.out"
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        echo "archive.configuration_file=true" >> $kra_config_file
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        rlRun "ls -alrt /var/lib/pki/pki-ca-bug/kra/conf/ > /tmp/conf_files.out"
        rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/kra/archives/CS.cfg.bak." "/tmp/conf_files.out"

	# Move KRA's CS.cfg file aside and touch CS.cfg

	rlLog "Move KRA's CS.cfg file aside and touch CS.cfg"
        saved_kra_config_file=$kra_config_file.saved
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        rlRun "mv $kra_config_file $saved_kra_config_file"
        rlRun "touch $kra_config_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart should fail with corrupted CS.cfg"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/kra_restart.out" 3 "subsystem service fails to restart"
        rlAssertGrep "WARNING:  The '/var/lib/pki/pki-ca-bug/conf/kra/CS.cfg' is empty!" "/tmp/kra_restart.out"
        rlAssertGrep "KRA backups will be discontinued until this" "/tmp/kra_restart.out"
        rlAssertGrep "issue has been resolved!" "/tmp/kra_restart.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_new = $num_files_orig ]; then
                rlPass "Test success"
        fi
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        rlRun "rm -rf $kra_config_file"
        rlRun "mv $saved_kra_config_file $kra_config_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/kra_restart1.out"
        rlAssertGrep "active (running)" "/tmp/kra_restart1.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi

	# Move KRA's CS.cfg file aside and create CS.cfg with 8192 bytes

	rlLog "Move KRA's CS.cfg file aside and create CS.cfg with 8192 bytes"
        saved_kra_config_file=$kra_config_file.saved
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        rlRun "mv $kra_config_file $saved_kra_config_file"
        rlRun "dd if=$saved_kra_config_file of=$kra_config_file bs=8192 count=1"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/kra_restart.out"
        rlAssertGrep "active (running)" "/tmp/kra_restart.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        rlRun "rm -rf $kra_config_file"
        rlRun "mv $saved_kra_config_file $kra_config_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/kra_restart1.out"
        rlAssertGrep "active (running)" "/tmp/kra_restart1.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/kra/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi	

	#Checking if the OCSP's CS.cfg.bak file exists and restart failes if the file is moved to a file with a different name
	
	rlLog "Checking if the OCSP's CS.cfg.bak file exists and restart failes if the file is moved to a file with a different name"
        ocsp_config_file="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ocsp/conf/CS.cfg"
        ocsp_config_backup_file="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ocsp/conf/CS.cfg.bak"
        rlAssertExists "$ocsp_config_file"
        rlAssertExists "$ocsp_config_backup_file"
        rlRun "mv $ocsp_config_backup_file /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ocsp/conf/CS.cfg.bak.saved"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart fails"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_ocsp_instance_restart.out 2>&1" 3 "The subsystem instance has a failed status"
        warning_msg1="WARNING:  Since the file '/var/lib/pki/pki-ca-bug/conf/ocsp/CS.cfg.bak.saved' exists, a"
        warning_msg2="previous backup attempt has failed!  OCSP backups"
        warning_msg3= "will be discontinued until this issue has been resolved!"
        rlAssertGrep "$warning_msg1" "/tmp/bug_ocsp_instance_restart.out"
        rlAssertGrep "$warning_msg2" "/tmp/bug_ocsp_instance_restart.out"
        rlAssertGrep "$warning_msg3" "/tmp/bug_ocsp_instance_restart.out"
        rlRun "mv /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ocsp/conf/CS.cfg.bak.saved $ocsp_config_backup_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_ocsp_instance_restart_1.out 2>&1"
        rlAssertGrep "active (running)" "/tmp/bug_ocsp_instance_restart_1.out"

        #restart of ocsp subsystem should fail when CS.cfg.bak.saved file exsists in the conf directory   

	rlLog "restart of ocsp subsystem should fail when CS.cfg.bak.saved file exsists in the conf directory"
        rlRun "cp $ocsp_config_backup_file /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ocsp/conf/CS.cfg.bak.saved"
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart fails"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_ocsp_instance_restart_2.out 2>&1" 3 "The subsystem instance has a failed status"
        warning_msg1="WARNING:  Since the file '/var/lib/pki/pki-ca-bug/conf/ocsp/CS.cfg.bak.saved' exists, a"
        warning_msg2="previous backup attempt has failed!  OCSP backups"
        warning_msg3= "will be discontinued until this issue has been resolved!"
        rlAssertGrep "$warning_msg1" "/tmp/bug_ocsp_instance_restart_2.out"
        rlAssertGrep "$warning_msg2" "/tmp/bug_ocsp_instance_restart_2.out"
        rlAssertGrep "$warning_msg3" "/tmp/bug_ocsp_instance_restart_2.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_new = $num_files_orig ]; then
                rlPass "No backup file created when service restart fails"
        fi
        rlRun "rm -rf /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ocsp/conf/CS.cfg.bak.saved"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_ocsp_instance_restart_1.out 2>&1"
        rlAssertGrep "active (running)" "/tmp/bug_ocsp_instance_restart_1.out"

	#Toggling between true and false value for the parameter "archive.configuration_file" in OCSP's CS.cfg

        rlLog "Toggling between true and false value for the parameter \"archive.configuration_file\" in CS.cfg"
        temp_file="$ocsp_config_file.temp"
        cat $ocsp_config_file | grep "archive.configuration_file=true"
        if [ $? -eq 0 ]; then
                orig_archive_conf="archive.configuration_file=true"
                new_archive_conf="archive.configuration_file=false"
                num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
                let num_files_orig=$num_files_orig-1
                rlRun "sed 's/$orig_archive_conf/$new_archive_conf/g' $ocsp_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $ocsp_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_new = $num_files_orig ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ocsp/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak" "/tmp/conf_files.out"
                rlAssertNotGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ocsp/archives/CS.cfg.bak." "/tmp/conf_files.out"
                rlRun "sed 's/$new_archive_conf/$orig_archive_conf/g' $ocsp_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $ocsp_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_orig -lt $num_files_new ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ocsp/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ocsp/archives/CS.cfg.bak." "/tmp/conf_files.out"
        else
                orig_archive_conf="archive.configuration_file=false"
                new_archive_conf="archive.configuration_file=true"
                num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
                let num_files_orig=$num_files_orig-1
                rlRun "sed 's/$orig_archive_conf/$new_archive_conf/g' $ocsp_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $ocsp_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_orig -lt $num_files_new ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ocsp/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ocsp/archives/CS.cfg.bak." "/tmp/conf_files.out"
                rlRun "sed 's/$new_archive_conf/$orig_archive_conf/g' $ocsp_config_file > $temp_file"
		rlRun "sleep 5"
                rlRun "mv $temp_file $ocsp_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_new = $num_files_orig ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ocsp/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak" "/tmp/conf_files.out"
                rlAssertNotGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ocsp/archives/CS.cfg.bak." "/tmp/conf_files.out"
        fi

	# Dangling symlink test

        rlLog "Dangling symlink test - OCSP CS.cfg.bak"
        if [ $(ls -alrt /var/lib/pki/pki-ca-bug/ocsp/conf/CS.cfg.bak | cut -f 11 -d ' ') = '->' ]; then
                symlink_target=$(ls -alrt /var/lib/pki/pki-ca-bug/ocsp/conf/CS.cfg.bak | cut -f 12 -d ' ')
        else
                symlink_target=$(ls -alrt /var/lib/pki/pki-ca-bug/ocsp/conf/CS.cfg.bak | cut -f 11 -d ' ')
        fi
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        rlRun "rm -rf /var/lib/pki/pki-ca-bug/ocsp/conf/CS.cfg.bak"
        rlRun "sleep 5"
        rlRun "ln -s /var/lib/pki/pki-ca-bug/ocsp/conf/archives/CS.cfg.bak.saved /var/lib/pki/pki-ca-bug/ocsp/conf/CS.cfg.bak"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart should fail with dangling symlink error"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ocsp_restart.out" 3 "subsystem service fails to restart"
        rlAssertGrep "WARNING:  The file '/var/lib/pki/pki-ca-bug/conf/ocsp/CS.cfg.bak' is a dangling symlink" "/tmp/ocsp_restart.out"
        rlAssertGrep "which suggests that the previous backup file has" "/tmp/ocsp_restart.out"
        rlAssertGrep "been removed!  OCSP backups will be discontinued" "/tmp/ocsp_restart.out"
        rlAssertGrep "until this issue has been resolved!" "/tmp/ocsp_restart.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        rlRun "rm -rf /var/lib/pki/pki-ca-bug/ocsp/conf/CS.cfg.bak"
        rlRun "sleep 5"
        rlRun "ln -s $symlink_target /var/lib/pki/pki-ca-bug/ocsp/conf/CS.cfg.bak"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ocsp_restart1.out"
        rlAssertGrep "active (running)" "/tmp/ocsp_restart1.out"
	
	# Remove archive.configuration_file from OCSP's CS.cfg

        rlLog "Remove archive.configuration_file from CS.cfg"
        archive_conf="archive.configuration_file=true"
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        rlRun "sed '/$archive_conf/d' $ocsp_config_file > $temp_file"
        rlRun "sleep 5"
        rlRun "mv $temp_file $ocsp_config_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ocsp/conf/ > /tmp/conf_files.out"
        rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ocsp/archives/CS.cfg.bak." "/tmp/conf_files.out"
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        echo "archive.configuration_file=true" >> $ocsp_config_file
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        rlRun "ls -alrt /var/lib/pki/pki-ca-bug/ocsp/conf/ > /tmp/conf_files.out"
        rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/ocsp/archives/CS.cfg.bak." "/tmp/conf_files.out"

        # Move OCSP's CS.cfg file aside and touch CS.cfg

        rlLog "Move OCSP's CS.cfg file aside and touch CS.cfg"
        saved_ocsp_config_file=$ocsp_config_file.saved
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        rlRun "mv $ocsp_config_file $saved_ocsp_config_file"
        rlRun "touch $ocsp_config_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart should fail with corrupted CS.cfg"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ocsp_restart.out" 3 "subsystem service fails to restart"
        rlAssertGrep "WARNING:  The '/var/lib/pki/pki-ca-bug/conf/ocsp/CS.cfg' is empty!" "/tmp/ocsp_restart.out"
        rlAssertGrep "OCSP backups will be discontinued until this" "/tmp/ocsp_restart.out"
        rlAssertGrep "issue has been resolved!" "/tmp/ocsp_restart.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_new = $num_files_orig ]; then
                rlPass "Test success"
        fi
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        rlRun "rm -rf $ocsp_config_file"
        rlRun "mv $saved_ocsp_config_file $ocsp_config_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ocsp_restart1.out"
	rlAssertGrep "active (running)" "/tmp/ocsp_restart1.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi

        # Move OCSP's CS.cfg file aside and create CS.cfg with 8192 bytes

        rlLog "Move OCSP's CS.cfg file aside and create CS.cfg with 8192 bytes"
        saved_ocsp_config_file=$ocsp_config_file.saved
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        rlRun "mv $ocsp_config_file $saved_ocsp_config_file"
        rlRun "dd if=$saved_ocsp_config_file of=$ocsp_config_file bs=8192 count=1"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ocsp_restart.out"
        rlAssertGrep "active (running)" "/tmp/ocsp_restart.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        rlRun "rm -rf $ocsp_config_file"
        rlRun "mv $saved_ocsp_config_file $ocsp_config_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/ocsp_restart1.out"
        rlAssertGrep "active (running)" "/tmp/ocsp_restart1.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/ocsp/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi

	#Checking if the TKS's CS.cfg.bak file exists and restart fails if the file is moved to a file with a different name

        rlLog "Checking if the TKS's CS.cfg.bak file exists and restart fails if the file is moved to a file with a different name"
        tks_config_file="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/tks/conf/CS.cfg"
        tks_config_backup_file="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/tks/conf/CS.cfg.bak"
        rlAssertExists "$tks_config_file"
        rlAssertExists "$tks_config_backup_file"
        rlRun "mv $tks_config_backup_file /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/tks/conf/CS.cfg.bak.saved"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart fails"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_tks_instance_restart.out 2>&1" 3 "The subsystem instance has a failed status"
        warning_msg1="WARNING:  Since the file '/var/lib/pki/pki-ca-bug/conf/tks/CS.cfg.bak.saved' exists, a"
        warning_msg2="previous backup attempt has failed!  TKS backups"
        warning_msg3= "will be discontinued until this issue has been resolved!"
        rlAssertGrep "$warning_msg1" "/tmp/bug_tks_instance_restart.out"
        rlAssertGrep "$warning_msg2" "/tmp/bug_tks_instance_restart.out"
        rlAssertGrep "$warning_msg3" "/tmp/bug_tks_instance_restart.out"
        rlRun "mv /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/tks/conf/CS.cfg.bak.saved $tks_config_backup_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_tks_instance_restart_1.out 2>&1"
        rlAssertGrep "active (running)" "/tmp/bug_tks_instance_restart_1.out"

        #restart of tks subsystem should fail when CS.cfg.bak.saved file exsists in the conf directory   

        rlLog "restart of tks subsystem should fail when CS.cfg.bak.saved file exsists in the conf directory"
        rlRun "cp $tks_config_backup_file /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/tks/conf/CS.cfg.bak.saved"
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart fails"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_tks_instance_restart_2.out 2>&1" 3 "The subsystem instance has a failed status"
        warning_msg1="WARNING:  Since the file '/var/lib/pki/pki-ca-bug/conf/tks/CS.cfg.bak.saved' exists, a"
        warning_msg2="previous backup attempt has failed!  TKS backups"
        warning_msg3= "will be discontinued until this issue has been resolved!"
        rlAssertGrep "$warning_msg1" "/tmp/bug_tks_instance_restart_2.out"
        rlAssertGrep "$warning_msg2" "/tmp/bug_tks_instance_restart_2.out"
        rlAssertGrep "$warning_msg3" "/tmp/bug_tks_instance_restart_2.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_new = $num_files_orig ]; then
                rlPass "No backup file created when service restart fails"
        fi
        rlRun "rm -rf /var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/tks/conf/CS.cfg.bak.saved"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/bug_tks_instance_restart_1.out 2>&1"
        rlAssertGrep "active (running)" "/tmp/bug_tks_instance_restart_1.out"

	#Toggling between true and false value for the parameter "archive.configuration_file" in TKS's CS.cfg

        rlLog "Toggling between true and false value for the parameter \"archive.configuration_file\" in TKS's CS.cfg"
        temp_file="$tks_config_file.temp"
        cat $tks_config_file | grep "archive.configuration_file=true"
        if [ $? -eq 0 ]; then
                orig_archive_conf="archive.configuration_file=true"
                new_archive_conf="archive.configuration_file=false"
                num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
                let num_files_orig=$num_files_orig-1
                rlRun "sed 's/$orig_archive_conf/$new_archive_conf/g' $tks_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $tks_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_new = $num_files_orig ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/tks/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak" "/tmp/conf_files.out"
                rlAssertNotGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/tks/archives/CS.cfg.bak." "/tmp/conf_files.out"
                rlRun "sed 's/$new_archive_conf/$orig_archive_conf/g' $tks_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $tks_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_orig -lt $num_files_new ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/tks/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/tks/archives/CS.cfg.bak." "/tmp/conf_files.out"
        else
                orig_archive_conf="archive.configuration_file=false"
                new_archive_conf="archive.configuration_file=true"
                num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
                let num_files_orig=$num_files_orig-1
                rlRun "sed 's/$orig_archive_conf/$new_archive_conf/g' $tks_config_file > $temp_file"
                rlRun "sleep 5"
                rlRun "mv $temp_file $tks_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_orig -lt $num_files_new ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/tks/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/tks/archives/CS.cfg.bak." "/tmp/conf_files.out"
                rlRun "sed 's/$new_archive_conf/$orig_archive_conf/g' $tks_config_file > $temp_file"
                rlRun "sleep 5"	
		rlRun "mv $temp_file $tks_config_file"
                rlRun "sleep 5"
                rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
                let num_files_new=$num_files_new-1
                if [ $num_files_new = $num_files_orig ]; then
                        rlPass "Test success"
                fi
                rlRun "ls -alrt /var/lib/pki/pki-ca-bug/tks/conf/ > /tmp/conf_files.out"
                rlAssertGrep "CS.cfg.bak" "/tmp/conf_files.out"
                rlAssertNotGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/tks/archives/CS.cfg.bak." "/tmp/conf_files.out"
        fi

	# Dangling symlink test

        rlLog "Dangling symlink test - TKS CS.cfg.bak"
        if [ $(ls -alrt /var/lib/pki/pki-ca-bug/tks/conf/CS.cfg.bak | cut -f 11 -d ' ') = '->' ]; then
                symlink_target=$(ls -alrt /var/lib/pki/pki-ca-bug/tks/conf/CS.cfg.bak | cut -f 12 -d ' ')
        else
                symlink_target=$(ls -alrt /var/lib/pki/pki-ca-bug/tks/conf/CS.cfg.bak | cut -f 11 -d ' ')
        fi
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        rlRun "rm -rf /var/lib/pki/pki-ca-bug/tks/conf/CS.cfg.bak"
        rlRun "sleep 5"
        rlRun "ln -s /var/lib/pki/pki-ca-bug/tks/conf/archives/CS.cfg.bak.saved /var/lib/pki/pki-ca-bug/tks/conf/CS.cfg.bak"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service" 1 "subsystem restart should fail with dangling symlink error"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/tks_restart.out" 3 "subsystem service fails to restart"
        rlAssertGrep "WARNING:  The file '/var/lib/pki/pki-ca-bug/conf/tks/CS.cfg.bak' is a dangling symlink" "/tmp/tks_restart.out"
        rlAssertGrep "which suggests that the previous backup file has" "/tmp/tks_restart.out"
        rlAssertGrep "been removed!  TKS backups will be discontinued" "/tmp/tks_restart.out"
        rlAssertGrep "until this issue has been resolved!" "/tmp/tks_restart.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        rlRun "rm -rf /var/lib/pki/pki-ca-bug/tks/conf/CS.cfg.bak"
        rlRun "sleep 5"
        rlRun "ln -s $symlink_target /var/lib/pki/pki-ca-bug/tks/conf/CS.cfg.bak"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/tks_restart1.out"
        rlAssertGrep "active (running)" "/tmp/tks_restart1.out"

        # Remove archive.configuration_file from TKS's CS.cfg

        rlLog "Remove archive.configuration_file from CS.cfg"
        archive_conf="archive.configuration_file=true"
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        rlRun "sed '/$archive_conf/d' $tks_config_file > $temp_file"
        rlRun "sleep 5"
        rlRun "mv $temp_file $tks_config_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        rlRun "ls -alrt /var/lib/pki/pki-ca-bug/tks/conf/ > /tmp/conf_files.out"
        rlAssertGrep "CS.cfg.bak -> /var/lib/pki/pki-ca-bug/conf/tks/archives/CS.cfg.bak." "/tmp/conf_files.out"
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        echo "archive.configuration_file=true" >> $tks_config_file
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
	let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi

        # Move TKS's CS.cfg file aside and create CS.cfg with 8192 bytes

        rlLog "Move TKS's CS.cfg file aside and create CS.cfg with 8192 bytes"
        saved_tks_config_file=$tks_config_file.saved
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        rlRun "mv $tks_config_file $saved_tks_config_file"
        rlRun "dd if=$saved_tks_config_file of=$tks_config_file bs=8192 count=1"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/tks_restart.out"
        rlAssertGrep "active (running)" "/tmp/tks_restart.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi
        num_files_orig=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        rlRun "rm -rf $tks_config_file"
        rlRun "mv $saved_tks_config_file $tks_config_file"
        rlRun "systemctl restart pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
        rlRun "sleep 5"
        rlRun "systemctl status pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service > /tmp/tks_restart1.out"
        rlAssertGrep "active (running)" "/tmp/tks_restart1.out"
        num_files_new=$(ls -l /var/lib/pki/pki-ca-bug/tks/conf/archives/ | grep -v ^l | wc -l)
        let num_files_new=$num_files_new-1
        if [ $num_files_orig -lt $num_files_new ]; then
                rlPass "Test success"
        fi

     rlPhaseEnd

}
