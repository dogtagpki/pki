#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/bugzilla/
#   Description: pki-core bug verification
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
run_pki-core-bug-verification(){
 
     rlPhaseStartTest "bug_1055080: Giant /var/log/pki-ca/debug"

        rlLog "Bug 1055080"
        ca_config_file="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ca/conf/CS.cfg"
        ca_debug_log_file="/var/lib/pki/$BUGCA_TOMCAT_INSTANCE_NAME/ca/logs/debug"
        local debug_level=$(cat $ca_config_file| grep debug.level | cut -d "=" -f2)
        temp_file="$ca_config_file.temp"
        if [ $debug_level = 0 ] || [ $debug_level = 1 ] || [ $debug_level = 2 ] || [ $debug_level = 3 ] || [ $debug_level = 4 ] || [ $debug_level = 5 ] ; then
		local debug_log_size=$(wc -c "$ca_debug_log_file" | cut -f 1 -d ' ')
		rlAssertGreater "Debug log file size will be greater than 300 bytes when debug.level=$debug_level" "$debug_log_size" "300"
                rlAssertGrep "DEBUG SUBSYSTEM INITIALIZED" "$ca_debug_log_file"
                rlAssertGrep "CMSEngine:" "$ca_debug_log_file"
                rlAssertGrep "LogFile:" "$ca_debug_log_file"
                rlAssertGrep "LdapAuthInfo:" "$ca_debug_log_file"
                rlAssertGrep "RegistrySubsystem:" "$ca_debug_log_file"
                search_string="debug.level=$debug_level"
                replace_string="debug.level=10"
                rlRun "sed 's/$search_string/$replace_string/g' $ca_config_file > $temp_file"
                cp $temp_file $ca_config_file
                chown pkiuser:pkiuser $ca_config_file
                cat $ca_config_file | grep $replace_string
                if [ $? -eq 0 ] ; then
			rlRun "systemctl stop pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                        rlRun "cat /dev/null > $ca_debug_log_file"
			rlRun "systemctl start pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
			rlRun "sleep 30"
			debug_log_size=$(wc -c "$ca_debug_log_file" | cut -f 1 -d ' ')
			rlAssertGreater "Debug log file size will be less than 300 bytes when debug.level=10" "300" "$debug_log_size"
                        rlAssertGrep "DEBUG SUBSYSTEM INITIALIZED" "$ca_debug_log_file"
                        rlAssertNotGrep "CMSEngine:" "$ca_debug_log_file"
                        rlAssertNotGrep "LogFile:" "$ca_debug_log_file"
                        rlAssertNotGrep "LdapAuthInfo:" "$ca_debug_log_file"
                        rlAssertNotGrep "RegistrySubsystem:" "$ca_debug_log_file"
                else
                        rlLog "Config file modification failed"
                fi
        else 
		if [ $debug_level = 6 ] || [ $debug_level = 7 ] || [ $debug_level = 8 ] || [ $debug_level = 9 ] || [ $debug_level = 10 ] ; then
		debug_log_size=$(wc -c "$ca_debug_log_file" | cut -f 1 -d ' ')
		rlAssertGreater "Debug log file size will be less than 300 bytes when debug.level=$debug_level" "300" "$debug_log_size"
                rlAssertGrep "DEBUG SUBSYSTEM INITIALIZED" "$ca_debug_log_file"
                rlAssertNotGrep "CMSEngine:" "$ca_debug_log_file"
                rlAssertNotGrep "LogFile:" "$ca_debug_log_file"
                rlAssertNotGrep "RegistrySubsystem:" "$ca_debug_log_file"
                search_string="debug.level=$debug_level"
                replace_string="debug.level=1"
                rlRun "sed 's/$search_string/$replace_string/g' $ca_config_file > $temp_file"
                cp $temp_file $ca_config_file
                chown pkiuser:pkiuser $ca_config_file
                cat $ca_config_file | grep $replace_string
                if [ $? -eq 0 ] ; then
			rlRun "systemctl stop pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
                        rlRun "cat /dev/null > $ca_debug_log_file"
			rlRun "systemctl start pki-tomcatd@$BUGCA_TOMCAT_INSTANCE_NAME.service"
			rlRun "sleep 20"
			debug_log_size=$(wc -c "$ca_debug_log_file" | cut -f 1 -d ' ')
			rlAssertGreater "Debug log file size will be greater than 300 bytes when debug.level=1" "$debug_log_size" "300"
                        rlAssertGrep "DEBUG SUBSYSTEM INITIALIZED" "$ca_debug_log_file"
                        rlAssertGrep "CMSEngine:" "$ca_debug_log_file"
                        rlAssertGrep "LogFile:" "$ca_debug_log_file"
                        rlAssertGrep "LdapAuthInfo:" "$ca_debug_log_file"
                        rlAssertGrep "RegistrySubsystem:" "$ca_debug_log_file"
                else
                        rlLog "Config file modification failed"
                fi
		fi
        fi

     rlPhaseEnd

}
