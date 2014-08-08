#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/PKI_TEST_USER_ID
#   Description: Dogtag-10/CS-9 testing
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/rhcs-install-shared.sh
. /opt/rhqa_pki/pki-user-cli-lib.sh
. /opt/rhqa_pki/env.sh

# Include tests
. ./acceptance/quickinstall/rhcs-install.sh

run_rhcs_install_topo_1()
{
    rlPhaseStartTest "run_rhcs_install_topo_1 - install ROOTCA on Host1"
        if [ "$(hostname)" = "$BEAKERMASTER" ]; then
 	    local number=3
            local CA=ROOTCA
	    local TKS_number=1
            run_rhcs_install_packages
	    run_install_subsystem_RootCA
            run_install_subsystem_kra $number $BEAKERMASTER $CA
            run_install_subsystem_ocsp $number $BEAKERMASTER $CA
	    run_install_subsystem_tks $TKS_number $BEAKERMASTER $CA
            pushd $CLIENT_PKCS12_DIR
	    if [ $(python --version 2>&1|awk '{print $2}'|cut -f1 -d.) -eq 2 ]; then
	        WEBMOD=SimpleHTTPServer;
    	    else
        	WEBMOD=http.server;
    	    fi
    	    python -m $WEBMOD 8901 > /var/log/python_web_server.log 2>&1 &
    	    KEYPID=$(ps -ef|grep "py[t]hon.*8901"|awk '{print $2}')
	    #run_test
	    rlLog "rhts-sync-set -s 'Master instances installed'"  
	    rlRun "rhts-sync-set -s 'Master instances installed' -m $BEAKERMASTER"
            run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
        fi
    rlPhaseEnd
    
    rlPhaseStartTest "run_rhcs_install_topo_1 - install CLONE1 on Host2"
	if [ "$(hostname)" = "$BEAKERCLONE1" ]; then
                rlRun "rhts-sync-block -s 'Master instances installed' $BEAKERMASTER"
		local CA=ROOTCA
		local number=1
		local MASTER_KRA=KRA3
		local MASTER_OCSP=OCSP3
 		if [ ! -d $CLIENT_PKCS12_DIR ]; then
        		mkdir -p $CLIENT_PKCS12_DIR
	        	chmod 755 $CLIENT_PKCS12_DIR
    		fi
 
    		pushd $CLIENT_PKCS12_DIR
	    	wget -q http://$BEAKERMASTER:8901/ca_backup_keys.p12
		wget -q http://$BEAKERMASTER:8901/kra_backup_keys.p12
    		wget -q http://$BEAKERMASTER:8901/ocsp_backup_keys.p12
	    	wget -q http://$BEAKERMASTER:8901/tks_backup_keys.p12
		rlRun "chmod 644 ca_backup_keys.p12 kra_backup_keys.p12 tks_backup_keys.p12 ocsp_backup_keys.p12"
		rlRun "chcon 'system_u:object_r:pki_tomcat_cert_t:s0' ca_backup_keys.p12 kra_backup_keys.p12 tks_backup_keys.p12 ocsp_backup_keys.p12"
    		popd
		rlLog "rhts-sync-set -s 'Files downloaded'"
		rlRun "rhts-sync-set -s 'Files downloaded' -m $BEAKERCLONE1"
		run_rhcs_install_packages
		run_install_subsystem_cloneCA $number $BEAKERMASTER $CA
		run_install_subsystem_cloneKRA $number $BEAKERMASTER $CA $MASTER_KRA
		run_install_subsystem_cloneOCSP $number $BEAKERMASTER $CA $MASTER_OCSP
		run_install_subsystem_cloneTKS $number $BEAKERMASTER $CA
		fi
    rlPhaseEnd

    rlPhaseStartTest "run_rhcs_install_topo_1 - install Subca1 on Host3"
	if [ "$(hostname)" = "$BEAKERSUBCA1" ]; then		
		rlRun "rhts-sync-block -s 'Master instances installed' $BEAKERMASTER"
		local CA=ROOTCA
		local number=1
		run_rhcs_install_packages
                run_install_subsystem_subca $number $BEAKERMASTER $CA
            	run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$SUBCA1_CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd

    rlPhaseStartTest "cleanup"
        if [ "$(hostname)" = "$BEAKERMASTER" ]; then
                rlRun "rhts-sync-block -s 'Files downloaded' $BEAKERCLONE1"
                kill -9 $KEYPID
		popd

        fi
    rlPhaseEnd
}

run_rhcs_install_envcleanup()
{
    rlPhaseStartSetup "Envcleanup"
    	for i in $(seq 1 10); do
        	unset ${!BEAKERMASTER}
        	unset ${!BEAKERCLONE*}
       		unset ${!BEAKERSUBCA*}
        	unset ${!MASTER*}
		unset ${!CLONE*}
		unset ${!SUBCA*}
        	unset ${!MYROLE*}
        	unset ${!MYENV*}
        	unset ${!TOPO*}
	done
    	rlLog "In func envcleanup"
    rlPhaseEnd
}

run_rhcs_add_to_env()
{
    local VAR1=$1
    local VAL1=$2
    if [ -z "$VAR1" ]; then
        echo "CANNOT run $FUNCNAME with no VAR name provided."
        echo "Usage: $FUNCNAME VARNAME VALUE"
        return 1
    fi
    sed -i "/^export $VAR1=/d" /opt/rhqa_pki/env.sh
    echo "export $VAR1=\"$VAL1\"" >> /opt/rhqa_pki/env.sh
    . /opt/rhqa_pki/env.sh
}

run_rhcs_install_set_vars()
{
    # Initialize Global TESTCOUNT variable
    # TESTCOUNT=1
    rlPhaseStartSetup "Inside install set vars"
	rlLog "run_rhcs_install_set_vars saili"
    	# First let's normalize the data to use <ROLE>_env<NUM> variables:
    	[ -n "$MASTER"  -a -z "$BEAKERMASTER"  ] && export BEAKERMASTER="$MASTER"
    	[ -n "$CLONE1"   -a -z "$BEAKERCLONE1" ] && export BEAKERCLONE1="$CLONE1"
    	[ -n "$CLONE2"   -a -z "$BEAKERCLONE2" ] && export BEAKERCLONE2="$CLONE2"
    	[ -n "$SUBCA1"   -a -z "$BEAKERSUBCA1" ] && export BEAKERSUBCA1="$SUBCA1"
    	[ -n "$SUBCA2"   -a -z "$BEAKERSUBCA2" ] && export BEAKERSUBCA2="$SUBCA2"
    	env > $IPATMP/dump-of-env.txt 
    
    	#if [ "$IPv6SETUP" = "TRUE" ]; then 
        	#rrtype="AAAA"
        	#run_rhcs_add_to_env "DNSFORWARD" "$DNSFORWARDIP6"
    	#else    
        	#rrtype="A"
    	#fi

    	# backwards compatibility with older tests.  This means no
    	# _env<NUM> suffix.
    	#run_rhcs_add_to_env "MYENV" "${MYENV}"
    	rlLog "Adding environment variables to /opt/rhqa_pki/env.sh"
    	run_rhcs_add_to_env "MYROLE" "$MYROLE"
    	run_rhcs_add_to_env "MASTER" "$BEAKERMASTER"
    	run_rhcs_add_to_env "CLONE1" "$BEAKERCLONE1"
    	run_rhcs_add_to_env "CLONE2" "$BEAKERCLONE2"
    	run_rhcs_add_to_env "SUBCA1" "$BEAKERSUBCA1"
    	run_rhcs_add_to_env "SUBCA2" "$BEAKERSUBCA2"
    	. /opt/rhqa_pki/env.sh
 
    	rlLog "===================== env|sort =========================="
    	env|sort 
    	rlLog "===================== env.sh   =========================="
    	cat /opt/rhqa_pki/env.sh
    	rlLog "==============================================="
    rlPhaseEnd
}

run_rhcs_install_quickinstall()
{   
    rlPhaseStartTest "run_rhcs_install_quickinstall - Install Master, Clone and SUBCA"
	rlLog "QuickInstall - run_rhcs_install_quickinstall"
	local BEAKERMASTER=$MASTER
	local number=3
	local TKS_number=1
	local CA=ROOTCA
        local CLONE_number=1
	local SUBCA_number=1
	local MASTER_KRA=KRA3
	local MASTER_OCSP=OCSP3
	run_rhcs_install_packages
        run_install_subsystem_RootCA
        run_install_subsystem_kra $number $BEAKERMASTER $CA
        run_install_subsystem_ocsp $number $BEAKERMASTER $CA
        run_install_subsystem_tks $TKS_number $BEAKERMASTER $CA
        run_install_subsystem_cloneCA $CLONE_number $BEAKERMASTER $CA
        run_install_subsystem_cloneKRA $CLONE_number $BEAKERMASTER $CA $MASTER_KRA
        #run_install_subsystem_cloneOCSP $CLONE_number $BEAKERMASTER $CA $MASTER_OCSP
        run_install_subsystem_cloneTKS $CLONE_number $BEAKERMASTER $CA
	run_install_subsystem_subca $SUBCA_number $BEAKERMASTER $CA
	run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$SUBCA1_CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"

    rlPhaseEnd 
}

run_rhcs_install_topo_6()
{
    rlPhaseStartTest "run_rhcs_install_topo_6 - Install ROOTCA on Host 1"
	rlLog "Topo_6 - run_rhcs_install_topo_6"
	local CA=ROOTCA
	local number=3
	if [ "$(hostname)" = "$BEAKERMASTER" ]; then
            	run_rhcs_install_packages
		run_install_subsystem_RootCA
	        run_install_subsystem_ocsp $number $BEAKERMASTER $CA
            	rlLog "rhts-sync-set -s 'Master instances installed'"
            	rlRun "rhts-sync-set -s 'Master instances installed' -m $BEAKERMASTER"
            	run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
        fi
    rlPhaseEnd

    rlPhaseStartTest "run_rhcs_install_topo_6 - install SUBCA1 on Host2"
    	rlLog "In default topo function"
	if [ "$(hostname)" = "$BEAKERSUBCA1" ]; then
        	rlRun "rhts-sync-block -s 'Master instances installed' $BEAKERMASTER"
                local CA=ROOTCA
                local number=1
		local KRA_CA=SUBCA1
		local OCSP_CA=SUBCA1
                run_rhcs_install_packages
                run_install_subsystem_subca $number $BEAKERMASTER $CA
                run_install_subsystem_kra $number $BEAKERSUBCA1 $KRA_CA
                run_install_subsystem_ocsp $number $BEAKERSUBCA1 $OCSP_CA
		rlLog "rhts-syncs-set -s 'SUBCA1 instances installed'"
		rlRun "rhts-syncs-set -s 'SUBCA1 instances installed' -m $BEAKERSUBCA1"
            	run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$SUBCA1_CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd

    rlPhaseStartTest "run_rhcs_install_topo_6 - install SUBCA2 on Host3"
	if [ "$(hostname)" = "$BEAKERSUBCA2" ]; then
        	rlRun "rhts-sync-block -s 'SUBCA1 instances installed' $BEAKERSUBCA1"
                local CA=SUBCA1
	        local number=2
		local KRA_CA=SUBCA2
                run_rhcs_install_packages
	        run_install_subsystem_subca $number $BEAKERSUBCA1 $CA
		run_install_subsystem_kra $number $BEAKERSUBCA2 $KRA_CA
            	run_rhcs_add_to_env "SUBCA2_ADMIN_CERT_LOCATION" "$SUBCA2_CLIENT_DIR/$SUBCA2_ADMIN_CERT_NICKNAME.p12"
        fi
    rlPhaseEnd

}

run_rhcs_install_topo_7()
{
    rlPhaseStartTest "install_topo_7 - Install RootCA on Host1"
	rlLog "In topo 6 function"
        if [ "$(hostname)" = "$BEAKERMASTER" ]; then
		local CA=ROOTCA
        	local number=3
            	run_rhcs_install_packages
            	run_install_subsystem_RootCA
            	run_install_subsystem_ocsp $number $BEAKERMASTER $CA
            	rlLog "rhts-sync-set -s 'Master instances installed'"
            	rlRun "rhts-sync-set -s 'Master instances installed' -m $BEAKERMASTER"
            	run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
        fi
    rlPhaseEnd
    rlPhaseStartTest "run_rhcs_install_topo_7 - install SUBCA1 on Host2"
    	if [ "$(hostname)" = "$BEAKERSUBCA1" ]; then
        	rlRun "rhts-sync-block -s 'Master instances installed' $BEAKERMASTER"
                local CA=ROOTCA
                local number=1
                run_rhcs_install_packages
                run_install_subsystem_subca $number $BEAKERMASTER $CA
		pushd $CLIENT_PKCS12_DIR
            	if [ $(python --version 2>&1|awk '{print $2}'|cut -f1 -d.) -eq 2 ]; then
                	WEBMOD=SimpleHTTPServer;
            	else
                	WEBMOD=http.server;
            	fi
         	python -m $WEBMOD 8901 > /var/log/python_web_server.log 2>&1 &
            	KEYPID=$(ps -ef|grep "py[t]hon.*8901"|awk '{print $2}')
                rlLog "rhts-syncs-set -s 'SUBCA1 instances installed'"
                rlRun "rhts-syncs-set -s 'SUBCA1 instances installed' -m $BEAKERSUBCA1"
            	run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$SUBCA1_CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd
    rlPhaseStartTest "run_rhcs_install_topo_7 - install CLONE1 on Host3"
        if [ "$(hostname)" = "$BEAKERCLONE1" ]; then
                rlRun "rhts-sync-block -s 'SUBCA1 instances installed' $BEAKERSUBCA1"
                local CA=SUBCA1
                local number=1
		if [ ! -d $CLIENT_PKCS12_DIR ]; then
                	mkdir -p $CLIENT_PKCS12_DIR
                        chmod 755 $CLIENT_PKCS12_DIR
                fi
                pushd $CLIENT_PKCS12_DIR
                wget -q http://$BEAKERMASTER:8901/ca_backup_keys.p12
		rlRun "chmod 644 ca_backup_keys.p12"
                rlRun "chcon 'system_u:object_r:pki_tomcat_cert_t:s0' ca_backup_keys.p12"
                run_rhcs_install_packages
                run_install_subsystem_cloneCA $number $BEAKERSUBCA1 $CA
		rlLog "rhts-sync-set -s 'Files downloaded'"
                rlRun "rhts-sync-set -s 'Files downloaded' -m $BEAKERCLONE1"
		popd
        fi
    rlPhaseEnd

    rlPhaseStartTest "cleanup"
        if [ "$(hostname)" = "$BEAKERSUBCA1" ]; then
                rlRun "rhts-sync-block -s 'Files downloaded' $BEAKERCLONE1"
	        kill -9 $KEYPID
        	popd
        fi
    rlPhaseEnd


}
run_rhcs_install_topo_8()
{
    rlPhaseStartTest "run_rhcs_install_topo_8 - Install Master, Subca and Clone"
	rlLog "In topo 7 function"
        if [ "$(hostname)" = "$BEAKERMASTER" ]; then
                local CA=ROOTCA
                local number=3
                run_rhcs_install_packages
                run_install_subsystem_RootCA
                run_install_subsystem_ocsp $number $BEAKERMASTER $CA
                rlLog "rhts-sync-set -s 'Master instances installed'"
                rlRun "rhts-sync-set -s 'Master instances installed' -m $BEAKERMASTER"
                run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi

    rlPhaseEnd
    rlPhaseStartTest "run_rhcs_install_topo_8 - Install SUbCA1 on Host 2"
	rlLog "In topo7 function"
	if [ "$(hostname)" = "$BEAKERSUBCA1" ]; then
		rlRun "rhts-sync-block -s 'Master instances installed' $BEAKERMASTER"
                local CA=ROOTCA
		local number=1
                local KRA_CA=SUBCA1
                local OCSP_CA=SUBCA1
                run_rhcs_install_packages
                run_install_subsystem_subca $number $BEAKERMASTER $CA
                run_install_subsystem_kra $number $BEAKERSUBCA1 $KRA_CA
                run_install_subsystem_ocsp $number $BEAKERSUBCA1 $OCSP_CA
                pushd $CLIENT_PKCS12_DIR
                if [ $(python --version 2>&1|awk '{print $2}'|cut -f1 -d.) -eq 2 ]; then
                	WEBMOD=SimpleHTTPServer;
                else
                        WEBMOD=http.server;
                fi
                python -m $WEBMOD 8901 > /var/log/python_web_server.log 2>&1 &
                KEYPID=$(ps -ef|grep "py[t]hon.*8901"|awk '{print $2}')
                rlLog "rhts-syncs-set -s 'SUBCA1 instances installed'"
                rlRun "rhts-syncs-set -s 'SUBCA1 instances installed' -m $BEAKERSUBCA1"
            	run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$SUBCA1_CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd
    rlPhaseStartTest "run_rhcs_install_topo_8 - install Host3 in Default Topology"
    	if [ "$(hostname)" = "$BEAKERCLONE1" ]; then
        	rlRun "rhts-sync-block -s 'SUBCA1 instances installed' $BEAKERSUBCA1"
                local CA=SUBCA1
                local number=1
		local MASTER_KRA=KRA1
		local MASTER_OCSP=OCSP1
                if [ ! -d $CLIENT_PKCS12_DIR ]; then
                	mkdir -p $CLIENT_PKCS12_DIR
                        chmod 755 $CLIENT_PKCS12_DIR
                fi
                pushd $CLIENT_PKCS12_DIR
                wget -q http://$BEAKERMASTER:8901/ca_backup_keys.p12
                rlRun "chmod 644 ca_backup_keys.p12 kra_backup_keys.p12 ocsp_backup_keys.p12"
                rlRun "chcon 'system_u:object_r:pki_tomcat_cert_t:s0' ca_backup_keys.p12 kra_backup_keys.p12 ocsp_backup_keys.p12"
                run_rhcs_install_packages
                run_install_subsystem_cloneCA $number $BEAKERSUBCA1 $CA
		run_install_subsystem_cloneKRA $number $BEAKERSUBCA1 $CA $MASTER_KRA
		run_install_subsystem_cloneOCSP $number $BEAKERSUBCA1 $CA $MASTER_OCSP
                rlLog "rhts-sync-set -s 'Files downloaded'"
                rlRun "rhts-sync-set -s 'Files downloaded' -m $BEAKERCLONE1"
                popd
	fi
    rlPhaseEnd

    rlPhaseStartTest "cleanup"
        if [ "$(hostname)" = "$BEAKERSUBCA1" ]; then
        	rlRun "rhts-sync-block -s 'Files downloaded' $BEAKERCLONE1"
                kill -9 $KEYPID
                popd

        fi
    rlPhaseEnd
		
}

run_rhcs_install_topo_2()
{
    rlPhaseStartTest "run_rhcs_install_topo_2 - Install RootCA on Host1"
	if [ "$(hostname)" = "$BEAKERMASTER" ]; then
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		rlRun "rhts-sync-set -s 'Master Instances Installed' -m $BEAKERMASTER"
            	run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi

    rlPhaseEnd 
    rlPhaseStartTest "run_rhcs_install_topo_2 - Install SubCA1 on Host2"
	if [ "$(hostname)" = "$BEAKERSUBCA1" ]; then
		rlRun "rhts-sync-block -s 'Master Instances Installed' $BEAKERMASTER"
		local number=1
		local CA=ROOTCA
		local KRA_CA=SUBCA1
		local OCSP_CA=SUBCA1
		run_rhcs_install_packages
		run_install_subsystem_subca $number $BEAKERMASTER $CA
		run_install_subsystem_kra $number $BEAKERSUBCA1 $KRA_CA
		run_install_subsystem_ocsp $number $BEAKERSUBCA1 $OCSP_CA
            	run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$SUBCA1_CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd
}

run_rhcs_install_topo_3()
{
    rlPhaseStartTest "run_rhcs_install_topo_3 - Install RootCA on host 1"
	if [ "$(hostname)" = "$BEAKERMASTER" ]; then
		local number=3
		local CA=ROOTCA
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_install_subsystem_ocsp $number $BEAKERMASTER $CA
		rlRun "rhts-sync-set -s 'Master Instances Installed' -m $BEAKERMASTER"
      		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd
    rlPhaseStartTest "run_rhcs_install_topo_3 - Install SUBCA1 on Host 2"
	if [ "$(hostname)" = "$BEAKERSUBCA1" ]; then
		local CA=ROOTCA
		local number=1
		local KRA_CA=SUBCA1
		local OCSP_CA=SUBCA1
		rlRun "rhts-sync-block -s 'Master Instances Installed' $BEAKERMASTER"
		run_rhcs_install_packages
		run_install_subsystem_subca $number $BEAKERMASTER $CA 
		run_install_subsystem_kra $number $BEAKERSUBCA1 $KRA_CA
		run_install_subsystem_ocsp $number $BEAKERSUBCA1 $OCSP_CA
          	run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$SUBCA1_CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd
    rlPhaseStartTest "run_rhcs_install_topo2 - Install SUBCA2 on Host 3"
	if [ "$(hostname)" = "$BEAKERSUBCA2" ]; then
		local CA=ROOTCA
		local number=2
		rlRun "rhts-sync-block -s 'Master Instances Installed' -m $BEAKERMASTER"
		run_rhcs_install_packages
		run_install_subsystem_subca $number $BEAKERMASTER $CA
          	run_rhcs_add_to_env "SUBCA2_ADMIN_CERT_LOCATION" "$SUBCA2_CLIENT_DIR/$SUBCA2_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd
}
run_rhcs_install_topo_4()
{
    rlPhaseStartTest "run_rhcs_install_topo_4 - Install ROOTCA on Host 1"
	if [ "$(hostname)" = "$BEAKERMASTER" ]; then
		run_rhcs_install_packages 
		run_install_subsystem_RootCA 
		rlRun "rhts-syncs-set -s 'Master Instances Installed' -m $BEAKERMASTER"
           	run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd
    rlPhaseStartTest "run_rhcs_install_topo_4 - Install SUBCA1 on Host 2"
	if [ "$(hostname)" = $BEAKERSUBCA1" ]; then
		rlRun "rhts-syncs-block -s 'Master Instances Installed' $BEAKERMASTER"
		local CA=ROOTCA
		local number=1
		local KRA_CA=SUBCA1
		local OCSP_CA=SUBCA1
		run_rhcs_install_packages 
		run_install_subsystem_subca $number $BEAKERMASTER $CA
		run_install_subsystem_kra $number $BEAKERSUBCA1 $KRA_CA
		run_install_subsystem_ocsp $number $BEAKERSUBCA1 $OCSP_CA
		rlRun "rhts-sync-set -s 'SUBCA1 Instances Installed' -m $BEAKERSUBCA1"
           	run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$SUBCA1_CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"
	fi

    rlPhaseEnd
    rlPhaseStartTest "run_rhcs_install_topo_4 - Install SUBCA2 on Host 3"
	if [ "$(hostname)" = $BEAKERSUBCA2" ]; then
        	rlRun "rhts-syncs-block -s 'SUBCA1 Instances Installed' $BEAKERSUBCA1"
                local CA=ROOTCA
                local number=2
                run_rhcs_install_packages 
                run_install_subsystem_subca $number $BEAKERMASTER $CA
            	run_rhcs_add_to_env "SUBCA2_ADMIN_CERT_LOCATION" "$SUBCA2_CLIENT_DIR/$SUBCA2_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd
}

run_rhcs_install_topo_5()
{
    rlPhaseStartTest "run_rhcs_install_topo_5 - Install ROOTCA Host 1"
 	if [ "$(hostname)" = "$BEAKERMASTER" ]; then
        	local CA=ROOTCA
		local number=3
		run_rhcs_install_packages
                run_install_subsystem_RootCA
		run_install_subsystem_ocsp $number $BEAKERMASTER $CA
                rlRun "rhts-syncs-set -s 'Master Instances Installed' -m $BEAKERMASTER"
            	run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd
    rlPhaseStartTest "run_rhcs_install_topo_5 - Install Subca1 on host 2"
	if [ "$(hostname)" = $BEAKERSUBCA1" ]; then
        	rlRun "rhts-syncs-block -s 'Master Instances Installed' $BEAKERMASTER"
                local CA=ROOTCA
                local number=1
                local KRA_CA=SUBCA1
                local OCSP_CA=SUBCA1
                run_rhcs_install_packages
                run_install_subsystem_subca $number $BEAKERMASTER $CA
                run_install_subsystem_kra $number $BEAKERSUBCA1 $KRA_CA
                run_install_subsystem_ocsp $number $BEAKERSUBCA1 $OCSP_CA
            	run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$SUBCA1_CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd

    rlPhaseStartTest "run_rhcs_install_topo_5 - Install Subca2 on host 3"
	if [ "$(hostname)" = $BEAKERSUBCA2" ]; then
               rlRun "rhts-syncs-block -s 'Master Instances Installed' $BEAKERMASTER"
               local CA=ROOTCA
               local number=2
               local KRA_CA=SUBCA2
               local OCSP_CA=SUBCA2
               run_rhcs_install_packages
               run_install_subsystem_subca $number $BEAKERMASTER $CA
               run_install_subsystem_KRA $number $BEAKERSUBCA2 $KRA_CA
               run_install_subsystem_OCSP $number $BEAKERSUBCA2 $OCSP_CA
               run_rhcs_add_to_env "SUBCA2_ADMIN_CERT_LOCATION" "$SUBCA2_CLIENT_DIR/$SUBCA2_ADMIN_CERT_NICKNAME.p12"
	fi
    rlPhaseEnd
}

run_rhcs_install_topo_9()
{
    rlPhaseStartTest "run_rhcs_install_quickinstall - Install Master, Clone and SUBCA"
        rlLog "QuickInstall - run_rhcs_install_quickinstall"
        local BEAKERMASTER=$MASTER
        local number=3
        local TKS_number=1
        local CA=ROOTCA
        local CLONE_number=1
        local SUBCA_number=1
        local MASTER_KRA=KRA3
        local MASTER_OCSP=OCSP3
        run_rhcs_install_packages
        run_install_subsystem_RootCA
        run_install_subsystem_kra $number $BEAKERMASTER $CA
        run_install_subsystem_ocsp $number $BEAKERMASTER $CA
        run_install_subsystem_tks $TKS_number $BEAKERMASTER $CA
        run_install_subsystem_cloneCA $CLONE_number $BEAKERMASTER $CA
        run_install_subsystem_cloneKRA $CLONE_number $BEAKERMASTER $CA $MASTER_KRA
        #run_install_subsystem_cloneOCSP $CLONE_number $BEAKERMASTER $CA $MASTER_OCSP
        run_install_subsystem_cloneTKS $CLONE_number $BEAKERMASTER $CA
        run_install_subsystem_subca $SUBCA_number $BEAKERMASTER $CA
        run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
        run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$SUBCA1_CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"

    rlPhaseEnd
}

