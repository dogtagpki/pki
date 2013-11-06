#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   rhcs_install.sh of /CoreOS/rhcs/acceptance/quickinstall
#   Description: CS quickinstall acceptance tests for new install
#                functions.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following rhcs will be tested:
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
#   Date  : Feb 18, 2013
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

# ROLE=MASTER, CLONE, SUBCA, EXTERNAL
# SUBSYSTEMS=CA, KRA, OCSP, RA, TKS, TPS

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/env.sh

# Include tests
. ./acceptance/quickinstall/rhds-install.sh
. ./acceptance/quickinstall/rhcs-install-lib.sh

run_rhcs_install_subsystems() {
	rlPhaseStartSetup "rhcs_install_subsystems: Default install"
	# Initialize Global TESTCOUNT variable
        #TESTCOUNT=1

	myhostname=`hostname`
        rlLog "HOSTNAME: $myhostname"
        rlLog "MASTER: $MASTER"
        rlLog "MASTER_CA: $MASTER_CA"
        rlLog "MASTER3: $MASTER3"
        rlLog "MASTER4: $MASTER4"
        rlLog "MASTER5: $MASTER5"
        rlLog "MASTER6: $MASTER6"
        rlLog "CLONE: $CLONE"
        rlLog "CLONE2: $CLONE2"
        rlLog "CLONE3: $CLONE3"
        rlLog "CLONE4: $CLONE4"
        rlLog "CLONE5: $CLONE5"

        echo "export BEAKERMASTER=$MASTER" >> /opt/rhqa_pki/env.sh
        echo "export BEAKERMASTER_CA=$MASTER_CA" >> /opt/rhqa_pki/env.sh
        echo "export BEAKERMASTER3=$MASTER3" >> /opt/rhqa_pki/env.sh
        echo "export BEAKERMASTER4=$MASTER4" >> /opt/rhqa_pki/env.sh
        echo "export BEAKERMASTER5=$MASTER5" >> /opt/rhqa_pki/env.sh
        echo "export BEAKERMASTER6=$MASTER6" >> /opt/rhqa_pki/env.sh
        echo "export BEAKERCLONE=$CLONE" >> /opt/rhqa_pki/env.sh
        echo "export BEAKERCLONE2=$CLONE2" >> /opt/rhqa_pki/env.sh
        echo "export BEAKERCLONE3=$CLONE3" >> /opt/rhqa_pki/env.sh
        echo "export BEAKERCLONE4=$CLONE4" >> /opt/rhqa_pki/env.sh
        echo "export BEAKERCLONE5=$CLONE5" >> /opt/rhqa_pki/env.sh
        echo "export HOSTNAME=$HOSTNAME" >> /opt/rhqa_pki/env.sh


        COMMON_SERVER_PACKAGES="bind expect pki-console xmlstarlet dos2unix"
        CA_SERVER_PACKAGES="pki-ca"
        KRA_SERVER_PACKAGES="pki-kra"
        OCSP_SERVER_PACKAGES="pki-ocsp"
        RA_SERVER_PACKAGES="pki-ra"
        TKS_SERVER_PACKAGES="pki-tks"
        TPS_SERVER_PACKAGES="pki-tps"
        RHELRHCS_PACKAGES="nuxwdog symkey mod-nss pki-native-tools redhat-pki-ca-ui redhat-pki-common-ui redhat-pki-console-ui redhat-pki-kra-ui redhat-pki-ocsp-ui redhat-pki-ra-ui redhat-pki-tks-ui redhat-pki-tps-ui"
        DOGTAG_PACKAGES="pki-tools pki-symkey dogtag-pki dogtag-pki-console-theme dogtag-pki-server-theme"


        cat /etc/redhat-release | grep "Fedora"
        if [ $? -eq 0 ] ; then
               FLAVOR="Fedora"
               rlLog "Automation is running against Fedora"
        else
               FLAVOR="RedHat"
               rlLog "Automation is running against RedHat"
        fi
	echo "export FLAVOR=$FLAVOR" >> /opt/rhqa_pki/env.sh


	#####################################################################
	# 		IS THIS MACHINE A MASTER?                           #
	#####################################################################
	echo $MASTER | grep $HOSTNAME
	if [ $? -eq 0 ] ; then
		yum clean all
		#CA install
		rc=0
		rlLog "CA instance will be installed on $HOSTNAME"
		yum -y install $COMMON_SERVER_PACKAGES
		yum -y install $CA_SERVER_PACKAGES

		echo "export CA_SERVER_CERT_SUBJECT_NAME= CN=$HOSTNAME,O=redhat" >> /opt/rhqa_pki/env.sh

		if [ "$FLAVOR" == "Fedora" ] ; then
			#yum -y install $DOGTAG_PACKAGES
			yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $CA_SERVER_PACKAGES"
			for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
				if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
				else
					rlLog "ERROR: $item package is NOT installed"
					rc=1
				fi
			done
		else
			yum -y install $RHELRHCS_SERVER_PACKAGES
			yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $CA_SERVER_PACKAGES $RHELRHCS_SERVER_PACKAGES"
			for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
				if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
				else
					rlLog "ERROR: $item package is NOT installed"
					rc=1
				fi
			done
		fi
		if [ $rc -eq 0 ] ; then
			rhcs_install_ca
		fi

		#KRA install
		rlLog "KRA instance will be installed on $HOSTNAME"
		rc=0
                yum -y install $COMMON_SERVER_PACKAGES
                yum -y install $KRA_SERVER_PACKAGES

                if [ "$FLAVOR" == "Fedora" ] ; then
			#yum -y install $DOGTAG_PACKAGES
	                yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $KRA_SERVER_PACKAGES"
			for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
				if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
	                        else
					rlLog "ERROR: $item package is NOT installed"
					rc=1
				fi
			done
                 else
                        yum -y install $RHELRHCS_SERVER_PACKAGES
                        yum -y update

			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $KRA_SERVER_PACKAGES $RHELRHCS_SERVER_PACKAGES"
			for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
	                        if [ $? -eq 0 ] ; then
					lLog "$item package is installed"
			        else
					rlLog "ERROR: $item package is NOT installed"
					rc=1
				fi
                         done
                fi
		if [ $rc -eq 0 ] ; then
			rhcs_install_kra
		fi

		#OCSP install
		rlLog "OCSP instance will be installed on $HOSTNAME"
		rc=0
                yum -y install $COMMON_SERVER_PACKAGES
                yum -y install $OCSP_SERVER_PACKAGES

                if [ "$FLAVOR" == "Fedora" ] ; then
			#yum -y install $DOGTAG_PACKAGES
			yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $OCSP_SERVER_PACKAGES"
			for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
				if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
                                else
					rlLog "ERROR: $item package is NOT installed"
					rc=1
			        fi
			done
                 else
                        yum -y install $RHELRHCS_SERVER_PACKAGES
                        yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $OCSP_SERVER_PACKAGES $RHELRHCS_SERVER_PACKAGES"
			for item in $ALL_PACKAGES ; do
			       rpm -qa | grep $item
                               if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
                                else
                                        rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                         done
                fi
		if [ $rc -eq 0 ] ; then
			rhcs_install_ocsp
		fi

		#RA install
		rlLog "RA instance will be installed on $HOSTNAME"
		rc=0
                yum -y install $COMMON_SERVER_PACKAGES
                yum -y install $RA_SERVER_PACKAGES

                if [ "$FLAVOR" == "Fedora" ] ; then
			#yum -y install $DOGTAG_PACKAGES
                        yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $RA_SERVER_PACKAGES"
			for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
                                if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
                                else
					rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                         done
                else
                         yum -y install $RHELRHCS_SERVER_PACKAGES
                         yum -y update
			 ALL_PACKAGES="$COMMON_SERVER_PACKAGES $RA_SERVER_PACKAGES $RHELRHCS_SERVER_PACKAGES"
			 for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
                                if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
                                else
					rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                          done
                fi
		if [ $rc -eq 0 ] ; then
			rlLog "Installing RA"
			#rhcs_install_ra
		fi

		#TKS install
		rlLog "TKS instance will be installed on $HOSTNAME"
		rc=0
                yum -y install $COMMON_SERVER_PACKAGES
                yum -y install $TKS_SERVER_PACKAGES

                if [ "$FLAVOR" == "Fedora" ] ; then
			#yum -y install $DOGTAG_PACKAGES
                        yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $TKS_SERVER_PACKAGES"
                        for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
                                if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
                                else
                                        rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                        done
                else
			yum -y install $RHELRHCS_SERVER_PACKAGES
                        yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $TKS_SERVER_PACKAGES $RHELRHCS_SERVER_PACKAGES"
                        for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
                                if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
                                else
                                        rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                         done
                fi
		if [ $rc -eq 0 ] ; then
			rlLog "Installing TKS"
			rhcs_install_tks
		fi

		#TPS install
		rlLog "TPS instance will be installed on $HOSTNAME"
		rc=0
                yum -y install $COMMON_SERVER_PACKAGES
                yum -y install $TPS_SERVER_PACKAGES

                if [ "$FLAVOR" == "Fedora" ] ; then
			#yum -y install $DOGTAG_PACKAGES
                        yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $TPS_SERVER_PACKAGES $DOGTAG_PACKAGES"
                        for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
                                if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
                                else
					rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                        done
                else
			yum -y install $RHELRHCS_SERVER_PACKAGES
                        yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $TPS_SERVER_PACKAGES $RHELRHCS_SERVER_PACKAGES"
                        for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
                                if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
                                else
					rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                        done
                fi
		if [ $rc -eq 0 ] ; then
			rlLog "Installing TPS"
			#rhcs_install_tps
		fi
	else
		rlLog "Machine in recipe is not a MASTER"
	fi

	#####################################################################
        #               IS THIS MACHINE A MASTER_CA?                        #
        #####################################################################
        echo $MASTER_CA | grep $HOSTNAME
        if [ $? -eq 0 ] ; then
                yum clean all
                rlLog "CA instance will be installed on $HOSTNAME"
		rc=0
                yum -y install $COMMON_SERVER_PACKAGES
                yum -y install $CA_SERVER_PACKAGES

                echo "export CA_SERVER_CERT_SUBJECT_NAME= CN=$HOSTNAME,O=redhat" >> /opt/rhqa_pki/env.sh

                if [ "$FLAVOR" == "Fedora" ] ; then
                        #yum -y install $DOGTAG_PACKAGES
                        yum -y update
                        ALL_PACKAGES="$COMMON_SERVER_PACKAGES $CA_SERVER_PACKAGES"
                        for item in $ALL_PACKAGES ; do
                                rpm -qa | grep $item
                                if [ $? -eq 0 ] ; then
                                        rlLog "$item package is installed"
                                else
                                        rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                        done
                else
                        yum -y install $RHELRHCS_SERVER_PACKAGES
                        yum -y update
                        ALL_PACKAGES="$COMMON_SERVER_PACKAGES $CA_SERVER_PACKAGES $RHELRHCS_SERVER_PACKAGES"
                        for item in $ALL_PACKAGES ; do
                                rpm -qa | grep $item
                                if [ $? -eq 0 ] ; then
                                        rlLog "$item package is installed"
                                else
                                        rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                        done
                fi

		if [ $rc -eq 0 ] ; then
			rhcs_install_ca_only
		fi
	else

		rlLog "Machine in recipe is not a MASTER_CA"
	fi
	#####################################################################
	# 		IS THIS MACHINE A CLONE?                            #
	#####################################################################
        echo $CLONE | grep $HOSTNAME
        if [ $? -eq 0 ] ; then
		yum clean all
		#Clone CA install
		rlLog "Clone CA instance will be installed on $HOSTNAME"
		rc=0
                yum -y install $COMMON_SERVER_PACKAGES
                yum -y install $CA_SERVER_PACKAGES

                if [ "$FLAVOR" == "Fedora" ] ; then
			#yum -y install $DOGTAG_PACKAGES
                        yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $CA_SERVER_PACKAGES"
                        for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
                                if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
                                else
					rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                         done
                else
			yum -y install $RHELRHCS_SERVER_PACKAGES
                        yum -y update
			ALL_PACKAGES="$COMMON_SERVER_PACKAGES $CA_SERVER_PACKAGES $RHELRHCS_SERVER_PACKAGES"
                        for item in $ALL_PACKAGES ; do
				rpm -qa | grep $item
                                if [ $? -eq 0 ] ; then
					rlLog "$item package is installed"
                                else
                                        rlLog "ERROR: $item package is NOT installed"
					rc=1
                                fi
                         done
                fi
		if [ $rc -eq 0 ] ; then
			rlLog "Installing Clone CA"
			#rhcs_install_cloneCA
		fi

		### ADD scripts for KRA,OCSP,TKS,TPS clone here

        else
                rlLog "Machine in recipe in not a CLONE"
        fi

	rlPhaseEnd

	rlPhaseStartCleanup "pki_user_cli_user_add-cleanup: pki install cleanup"
		rlLog "pki install clean-up"
	rlPhaseEnd

   #rlJournalPrintText
   #report=/tmp/rhts.report.$RANDOM.txt
   #makereport $report
   #rhts-submit-log -l $report
  #rlPhaseEnd
}
