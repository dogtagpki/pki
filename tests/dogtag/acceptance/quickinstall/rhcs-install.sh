#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   rhcs_install.sh of /CoreOS/dogtag/acceptance/quickinstall
#   Description: CS quickinstall acceptance tests for new install
#                functions.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following rhcs will be tested:
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Asha Akkiangady <aakkiang@redhat.com>
#   	     Saili Pandit <saipandi@redhat.com>
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
##global variables##
ALT_XMLSTARLET_PATH="https://dl.fedoraproject.org/pub/epel/7/x86_64/x/xmlstarlet-1.6.1-1.el7.x86_64.rpm"
####################

run_rhcs_install_packages() {
	rlPhaseStartSetup "rhcs_install_packages: Default install"
	# Initialize Global TESTCOUNT variable
        #TESTCOUNT=1

        COMMON_SERVER_PACKAGES="bind expect pki-console xmlstarlet dos2unix bc"
	NTPDATE_PACKAGE="ntpdate"
	DEPENDENT_PACKAGES="idm-console-framework pki-base pki-ca pki-console pki-kra pki-ocsp pki-server pki-symkey pki-tks pki-tools pki-tps tomcat resteasy-base-jackson-provider resteasy-base-jaxb-provider resteasy-base-jaxrs resteasy-base-jaxrs-api"
	#rlRun "setenforce 0"
        cat /etc/redhat-release | grep "Fedora"
        if [ $? -eq 0 ] ; then
               FLAVOR="Fedora"
		OS_SPECIFIC_PACKAGES="pki-tools pki-symkey dogtag-pki dogtag-pki-console-theme dogtag-pki-server-theme 389-ds-base"
               rlLog "Automation is running against Fedora"
	else
		FLAVOR="RHEL"
		OS_SPECIFIC_PACKAGES="pki-tools pki-symkey redhat-pki redhat-pki-console-theme redhat-pki-server-theme redhat-ds"
		rlLog "Automation is running against RHEL"
	fi
	
	#####################################################################
	# 		IS THIS MACHINE A MASTER?                           #
	#####################################################################
		yum clean all
		yum -y update
		yum -y install wget
		#CA install
		rc=0
		rlLog "CA instance will be installed on $HOSTNAME"
		rlLog "yum -y install $COMMON_SERVER_PACKAGES"
		yum -y install $COMMON_SERVER_PACKAGES
		rlLog "yum -y install $OS_SPECIFIC_PACKAGES"
		yum -y install $OS_SPECIFIC_PACKAGES
                rpm -qa | grep xmlstarlet
                if [ $? -eq 0 ]; then
                        rlLog "xmlstarlet installed"
                else
                        wget $XMLSTARLET_PATH
			RETVAL=$?
			if (( $RETVAL == 0)); then
	                        rpm -ivh xmlstarlet*
			else
				wget $ALT_XMLSTARLET_PATH
				rpm -ivh xmlstarlet*
			fi
                fi
		rlLog "yum -y install $NTPDATE_PACKAGE"
                yum -y install $NTPDATE_PACKAGE
		#codecoverage setup
		CODE_COVERAGE_UPPERCASE=$(echo $CODE_COVERAGE | tr [a-z] [A-Z])
                if [ "$CODE_COVERAGE_UPPERCASE" = "TRUE" ] ; then	
			rlLog "Setup for codecoverage"
			yum -y install jacoco wget objectweb-asm4 screen
                        rpm -qa | grep jacoco
                        if [ $? -eq 0];
                        then
                                rlLog "Jacoco packages installed"
                        else
                                rlLog "Jacoco not installed, installing it"
                                echo "[rhel-source-beta]" >> /etc/yum.repos.d/jacoco.repo
                                echo "jaccocorepo" >> /etc/yum.repos.d/jacoco.repo
                                echo "baseurl=$JACOCO_PATH" >> /etc/yum.repos.d/jacoco.repo
                                echo "enabled=0" >> /etc/yum.repos.d/jacoco.repo
                                echo "gpgcheck=1" >> /etc/yum.repos.d/jacoco.repo

                                yum -y install jacoco objectweb-asm4
                                rm /etc/yum.repos.d/fedorarepojacoco.repo
                        fi
			#get jacocoant.jar file
                        rlRun "cp  /usr/share/java/jacoco/org.jacoco.agent.rt.jar /usr/lib/jvm/java/jre/lib/."

                        # Adding JAVA_OPTS to configfile /usr/share/pki/server/conf/tomcat.conf for the jacoco javaagent
                       rlLog "Adding JAVA_OPTS to configfile /usr/share/pki/server/conf/tomcat.conf for the jacoco javaagent"
                       local configfile="/usr/share/pki/server/conf/tomcat.conf"
                       rlRun "sed -e 's/JAVA\_OPTS\=\\\"\-DRESTEASY\_LIB\=\[PKI_RESTEASY_LIB\]\\\"/JAVA\_OPTS\=\\\"\-DRESTEASY\_LIB\=\[PKI_RESTEASY_LIB\] -javaagent:\/usr\/lib\/jvm\/java\/jre\/lib\/org.jacoco.agent.rt.jar=destfile=\/tmp\/jacoco.exec,output=file\\\"/g' -i $configfile"
                       rlLog "Check if the javaagent added to /usr/share/pki/server/conf/tomcat.conf"
                       rlRun "cat $configfile"
                       rlRun "sleep 20"
		fi
	rlPhaseEnd
}

run_install_subsystem_RootCA()
{	
	rlPhaseStartSetup "rhcs_install_subsystem_RootCA: Default install"
		ALL_PACKAGES="$COMMON_SERVER_PACKAGES $OS_SPECIFIC_PACKAGES $DEPENDENT_PACKAGES $NTPDATE_PACKAGE"
                for item in $ALL_PACKAGES ; do
                	rpm -qa | grep $item
                        if [ $? -eq 0 ] ; then
                               rlLog "$item package is installed"
                        else
                               rlLog "ERROR: $item package is NOT installed"
                               rc=1
			       rlDie "$item is not installed"
                        fi
                done
		if [ $rc -eq 0 ] ; then
			rhcs_install_RootCA
		fi
	rlPhaseEnd
}

#KRA Install

run_install_subsystem_kra() {
        rlPhaseStartSetup "rhcs_install_subsystem_kra: Default install"
                rlLog "KRA instance will be installed on $HOSTNAME"
                rc=0
                number=$1
                master_hostname=$2
                CA=$3
                rpm -qa | grep pki-kra
                if [ $? -eq 0 ] ; then
                        rlLog "pki-kra package is installed"
                else
                        rlLog "ERROR: $item package is NOT installed"
                        rc=1
                fi
                if [ $rc -eq 0 ] && [ $(eval echo \$${CA}_INSTANCE_CREATED_STATUS) = "TRUE" ]; then
                        rhcs_install_kra $number $master_hostname $CA
                fi
        rlPhaseEnd
}

#OCSP install

run_install_subsystem_ocsp() {
        rlPhaseStartSetup "rhcs_install_subsystem_ocsp: Default install"
                rlLog "OCSP instance will be installed on $HOSTNAME"
                rc=0
                number=$1
                master_hostname=$2
                CA=$3
                rpm -qa | grep pki-ocsp
                if [ $? -eq 0 ] ; then
                        rlLog "pki-ocsp package is installed"
                else
                        rlLog "ERROR: $item package is NOT installed"
                        rc=1
                fi

                if [ $rc -eq 0 ] && [ $(eval echo \$${CA}_INSTANCE_CREATED_STATUS) = "TRUE" ]; then
                        rhcs_install_ocsp $number $master_hostname $CA
                fi
        rlPhaseEnd
}

		
#RA install
#rlLog "RA instance will be installed on $HOSTNAME"
		#rc=0
                #yum -y install $COMMON_SERVER_PACKAGES
                #yum -y install $OS_SPECIFIC_PACKAGES
                #if [ "$FLAVOR" == "Fedora" ] ; then
			#ALL_PACKAGES="$COMMON_SERVER_PACKAGES $OS_SPECIFIC_PACKAGES"
			#for item in $ALL_PACKAGES ; do
				#rpm -qa | grep $item
                                #if [ $? -eq 0 ] ; then
					#rlLog "$item package is installed"
                                #else
					#rlLog "ERROR: $item package is NOT installed"
					#rc=1
                                #fi
                         #done
             
                #fi

		#if [ $rc -eq 0 ] ; then
			#rlLog "Installing RA"
			#rhcs_install_ra
		#fi

#TKS install
run_install_subsystem_tks() {
        rlPhaseStartSetup "rhcs_install_subsystem_tks: Default install"
                rlLog "TKS instance will be installed on $HOSTNAME"
                rc=0
                number=$1
                master_hostname=$2
                CA=$3
		KRA=$4
                rpm -qa | grep pki-tks
                if [ $? -eq 0 ] ; then
                        rlLog "pki-tks package is installed"
                else
                        rlLog "ERROR: $item package is NOT installed"
                        rc=1
                fi
                if [ $rc -eq 0 ] && [ $(eval echo \$${CA}_INSTANCE_CREATED_STATUS) = "TRUE" ] && [ $(eval echo \$${KRA}_INSTANCE_CREATED_STATUS) = "TRUE" ]; then
                        rlLog "Installing TKS"
                        rhcs_install_tks $number $master_hostname $CA
                fi
        rlPhaseEnd
}

#TPS install
run_install_subsystem_tps() {
        rlPhaseStartSetup "rhcs_install_subsystem_tps: Default install"
                rlLog "TPS instance will be installed on $HOSTNAME"
                rc=0
                number=$1
                master_hostname=$2
                CA=$3
                KRA=$4
                TKS=$5
                rpm -qa | grep pki-tks
                if [ $? -eq 0 ] ; then
                        rlLog "$item package is installed"
                else
                        rlLog "ERROR: $item package is NOT installed"
                        rc=1
                fi
                if [ $rc -eq 0 ] && [ $(eval echo \$${CA}_INSTANCE_CREATED_STATUS) = "TRUE" ] && [ $(eval echo \$${KRA}_INSTANCE_CREATED_STATUS) = "TRUE" ] && [ $(eval echo \$${TKS}_INSTANCE_CREATED_STATUS) = "TRUE" ]; then
                        rlLog "Installing TPS"
                        rhcs_install_tps $number $master_hostname $CA $KRA $TKS
                fi
        rlPhaseEnd
}

#####################SUBCA######################
################################################
run_install_subsystem_subca(){
	rlPhaseStartSetup "rhcs_install_subsystem_subca: Default install"
		number=$1
		master_hostname=$2
		CA=$3
		yum clean all
                yum -y update

                #Sub CA install
                rlLog "Sub CA instance will be installed on $HOSTNAME"
                rc=0
                yum -y install $COMMON_SERVER_PACKAGES
                yum -y install $OS_SPECIFIC_PACKAGES

                ALL_PACKAGES="$COMMON_SERVER_PACKAGES $OS_SPECIFIC_PACKAGES"
                for item in $ALL_PACKAGES ; do
                rpm -qa | grep $item
                 	if [ $? -eq 0 ] ; then
          	        	rlLog "$item package is installed"
                        else
                        	rlLog "ERROR: $item package is NOT installed"
                                rc=1
				break
                        fi
                done
                if [ $rc -eq 0 ] ; then
                        rlLog "Installing Sub CA"
                        rhcs_install_SubCA $number $master_hostname $CA
                fi
	rlPhaseEnd 
}

	#####################################################################
	# 		IS THIS MACHINE A CLONE?                            #
	#####################################################################
	
run_install_subsystem_cloneCA() {
	rlPhaseStartSetup "rhcs_install_subsystem_cloneca: Default install"
		number=$1
                master_hostname=$2
                CA=$3
		yum clean all
		yum -y update
		#Clone CA install
		rlLog "Clone CA instance will be installed on $HOSTNAME"
		rc=0
                yum -y install $COMMON_SERVER_PACKAGES
                yum -y install $
		ALL_PACKAGES="$COMMON_SERVER_PACKAGES $OS_SPECIFIC_PACKAGES"
                for item in $ALL_PACKAGES ; do
	        	rpm -qa | grep $item
                        if [ $? -eq 0 ] ; then
				rlLog "$item package is installed"
                        else
				rlLog "ERROR: $item package is NOT installed"
				rc=1
                        fi
		done

		if [ $rc -eq 0 ] ; then
			rlLog "Installing Clone CA"
			rhcs_install_cloneCA $number $master_hostname $CA
		fi
	rlPhaseEnd
}

###CLONE KRA Install#############
run_install_subsystem_cloneKRA() {
        rlPhaseStartSetup "rhcs_install_subsystem_clonekra: Default install"
		number=$1
                master_hostname=$2
                CA=$3
		MASTER_KRA=$4
	     	rlLog "Clone KRA instance will be installed on $HOSTNAME"
		rc=0
                rpm -qa | grep pki-kra
                if [ $? -eq 0 ] ; then
                	rlLog "pki-kra package is installed"
                else
                        rlLog "ERROR: $item package is NOT installed"
                        rc=1
                fi

                if [ $rc -eq 0 ] ; then
                        rlLog "Installing Clone KRA"
                        rhcs_install_cloneKRA $number $master_hostname $CA $MASTER_KRA
                fi
	rlPhaseEnd
}

#CLONE OCSP install
run_install_subsystem_cloneOCSP() {
	rlPhaseStartSetup "rhcs_install_subsystem_cloneocsp: Default install"
		rlLog "Clone OCSP instance will be installed on $HOSTNAME"
                number=$1
                master_hostname=$2
                CA=$3
		rc=0
                rpm -qa | grep pki-ocsp
                if [ $? -eq 0 ] ; then
                	rlLog "pki-ocsp package is installed"
                else
                        rlLog "ERROR: $item package is NOT installed"
                        rc=1
                fi

                #if [ $rc -eq 0 ] ; then
                        #rlLog "Installing Clone OCSP"
                        #rhcs_install_cloneOCSP $number $master_hostname $CA
                #fi
	rlPhaseEnd
}

#CLONE TKS install
run_install_subsystem_cloneTKS(){
	rlPhaseStartSetup "rhcs_install_subsystem_clonetks: Default install"
		rlLog "Clone TKS instance will be installed on $HOSTNAME"
                rc=0
		number=$1
                master_hostname=$2
                CA=$3
		rpm -qa | grep pki-tks
                if [ $? -eq 0 ] ; then
                	rlLog "pki-tks package is installed"
                else
                        rlLog "ERROR: pki-tks package is NOT installed"
                        rc=1
                fi

                if [ $rc -eq 0 ] ; then
                        rlLog "Installing TKS"
                        rhcs_install_cloneTKS $number $master_hostname $CA
                fi
	rlPhaseEnd
}
#CLONE TPS install
run_install_subsystem_cloneTPS(){
        rlPhaseStartSetup "rhcs_install_subsystem_clonetps: Default install"
                rlLog "Clone TPS instance will be installed on $HOSTNAME"
                rc=0
                number=$1
                master_hostname=$2
                CA=$3
                KRA=$4
                TKS=$5
                rpm -qa | grep pki-tps
                if [ $? -eq 0 ] ; then
                        rlLog "pki-tps package is installed"
                else
                        rlLog "ERROR: pki-tps package is NOT installed"
                        rc=1
                fi

                if [ $rc -eq 0 ] ; then
                        rlLog "Installing TPS"
                        rhcs_install_cloneTPS $number $master_hostname $CA $KRA $TKS
                fi
        rlPhaseEnd
}
