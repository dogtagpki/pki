#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/codecoverage
#   Description: Archiving Jacoco code coverage results
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
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

backupCodeCoverageResults() 
{
	local codecoverage_results_base=$1
	local wiki_archive_location=""
	if [-n $codecoverage_results_base ]; then
		rlLog "$codecoverage_results_base is not a valid directory"
		return 1
	else
		rlLog "Archiving source $codecoverage_results_base"
		QALIBDIR=/opt/rhqa_pki
		export QALIBDIR
		if [ -x $ARCHIVELOCATIONSERVER ]; then
			rlLog "ARCHIVELOCATIONSERVER not provided. Assuming result should be stored local."
			return 1
		else
			if [ -x $ARCHIVELOCATIONSCPUSER ]; then
				export ARCHIVELOCATIONSCPUSER="beaker_archive"
			fi
			if [ -x $ARCHIVELOCATIONDESTINATION ]; then
				echo $ARCHIVELOCATIONSERVER | grep wiki
				if [ $? -eq 0 ]; then
        				export ARCHIVELOCATIONDESTINATION="/qa/archive/beaker/RHCS/dogtag10/codecoverage_results"
					wiki_archive_location="/dirsec/archives-mp1/archives/beaker/RHCS/dogtag10/codecoverage_results"
					rlLog "Archiving destination $ARCHIVELOCATIONDESTINATION"
				fi
			fi
			if [ -x $ARCHIVELOCATIONSCPUSERKEYFILE ]; then
				export ARCHIVELOCATIONSCPUSERKEYFILE="$QALIBDIR/id_rsa-host-beaker_archive"
			fi
			if [ -x $ARCHIVELOCATIONSCPKNOWNHOSTS ]; then
				export ARCHIVELOCATIONSCPKNOWNHOSTS="$QALIBDIR/known_hosts_archivehost"
			fi
			if [ -x $ARCHIVERIDENTITYPUBLICKEY]; then
				export ARCHIVERIDENTITYPUBLICKEY="$QALIBDIR/id_rsa-host-beaker_archive.pub"
			fi
			if [ -x $ARCHIVERUSERUID ]; then
				export ARCHIVERUSERUID="8819"
			fi

			#Get ssh on this machine ready to send files to the destination machine
			rlLog "Get ssh on this machine ready to send files to the destination machine"
			mkdir -p ~/.ssh
			if [ -f ~/.ssh/identity ]; then
				mv ~/.ssh/identity ~/.ssh/identity_backup_$(date +%s)
			fi
			cp $ARCHIVELOCATIONSCPUSERKEYFILE ~/.ssh/identity
			chmod 600 ~/.ssh/identity
			if [ -f ~/.ssh/known_hosts ]; then
				mv ~/.ssh/known_hosts ~/.ssh/known_hosts_backup_$(date +%s)
			fi
			cat $ARCHIVELOCATIONSCPKNOWNHOSTS >> ~/.ssh/known_hosts
			chmod 644 ~/.ssh/known_hosts
			if [ ! -d /root/.ssh ]; then 
				mkdir /root/.ssh;
				chmod 700 /root/.ssh;
			fi
			if [ -f /root/.ssh/authorized_keys ]; then
				mv /root/.ssh/authorized_keys /root/.ssh/authorized_keys_backup
			fi
			cat $ARCHIVERIDENTITYPUBLICKEY > /root/.ssh/authorized_keys
			chmod 600 /root/.ssh/authorized_keys
			sed -i s/^Protocol/#Protocol/g /etc/ssh/sshd_config
			echo "Protocol 2,1" >> /etc/ssh/sshd_config
			/etc/init.d/sshd restart
			systemctl restart sshd.service

			#Archive the results 
			rlLog "Archive the results"
			rlRun "yum -y install tar"
			rlRun "cd $codecoverage_results_base -Rf 755 *" 0 "Setting backup directory to world writable"
			rlRun "cd $codecoverage_results_base $ARCHIVERUSERUID:$ARCHIVERUSERUID *" 0 "setting uid and gid on results folder to $ARCHIVERUSERUID"
			bfilename="$HOSTNAME-$(date +%s).tar.gz"
			bfiledir="$HOSTNAME-$(date +%s)"
			codecoveragedirname=`echo $codecoverage_results_base | awk -F '/' '{ print $NF}'`
			rlLog "cd $codecoverage_results_base/..;tar cvfz $bfilename $codecoveragedirname;mv $bfilename $codecoverage_results_base" 
			rlRun "cd $codecoverage_results_base/..;tar cvfz $bfilename $codecoveragedirname;mv $bfilename $codecoverage_results_base" 0 "Backing up the results dir to $bfilename"
			rlLog "Running scp -1 $codecoverage_results_base/$bfilename $ARCHIVELOCATIONSCPUSER@$ARCHIVELOCATIONSERVER:$ARCHIVELOCATIONDESTINATION/."
			rlRun "scp -1 $codecoverage_results_base/$bfilename $ARCHIVELOCATIONSCPUSER@$ARCHIVELOCATIONSERVER:$ARCHIVELOCATIONDESTINATION/." 0 "copy the results tarball to $ARCHIVELOCATIONSCPUSER@$ARCHIVELOCATIONSERVER:$ARCHIVELOCATIONDESTINATION/."
			rlLog "Running: ssh -1 $ARCHIVELOCATIONSCPUSER@$ARCHIVELOCATIONSERVER 'cd $ARCHIVELOCATIONDESTINATION;mkdir $bfiledir;mv $bfilename $bfiledir;cd $bfiledir;tar xvfz $bfilename;rm -f $bfilename'"
			rlRun "ssh -1 $ARCHIVELOCATIONSCPUSER@$ARCHIVELOCATIONSERVER 'cd $ARCHIVELOCATIONDESTINATION;mkdir $bfiledir;mv $bfilename $bfiledir;cd $bfiledir;tar xvfz $bfilename;rm -f $bfilename'" 0 "Decompress the results tarball in the archive location"
			echo $ARCHIVELOCATIONSERVER | grep wiki
			if [ $? -eq 0 ]; then
			
				rlLog "Archived code coverage results can be viewed at http://$ARCHIVELOCATIONSERVER$wiki_archive_location/$bfiledir"
			fi
		fi
	fi
	return 0
 }
