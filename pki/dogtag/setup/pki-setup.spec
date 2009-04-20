# BEGIN COPYRIGHT BLOCK
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (C) 2007 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK

###############################################################################
###                          D E F I N I T I O N S                          ###
###############################################################################

## Entity Definitions
%define base_entity       Dogtag
%define base_prefix       pki

## Product Definitions
%define base_system       Certificate System
%define base_product      PKI Instance Creation and Removal Scripts
%define base_component    setup
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_prefix}-%{base_component}
%define base_version      1.1.0
%define base_release      3
%define base_group        System Environment/Shells
%define base_vendor       Red Hat, Inc.
%define base_license      GPLv2 with exceptions
%define base_packager     %{base_vendor} <http://bugzilla.redhat.com/bugzilla>
%define base_summary      %{base_pki} - %{base_product}
%define base_url          http://pki.fedoraproject.org/wiki/PKI_Documentation

## Helper Definitions
%define pki_ca            %{base_entity} Certificate Authority
%define pki_drm           %{base_entity} Data Recovery Manager
%define pki_ds            Fedora Directory Server
%define pki_ocsp          %{base_entity} Online Certificate Status Protocol Manager
%define pki_ra            %{base_entity} Registration Authority
%define pki_tks           %{base_entity} Token Key Service
%define pki_tps           %{base_entity} Token Processing System

## Don't build the debug packages
%define debug_package     %{nil}


##===================##
## Linux Definitions ##
##===================##
%ifos Linux
## A distribution model is required on certain Linux operating systems!
##
## check for a pre-defined distribution model
%define undefined_distro  %(test "%{dist}" = "" && echo 1 || echo 0)
%if %{undefined_distro}
%define is_fedora         %(test -e /etc/fedora-release && echo 1 || echo 0)
%if %{is_fedora}
## define a default distribution model on Fedora Linux
%define dist_prefix       .fc
%define dist_version      %(echo `rpm -qf --qf='%{VERSION}' /etc/fedora-release` | tr -d [A-Za-z])
%define dist              %{dist_prefix}%{dist_version}
%else
%define is_redhat         %(test -e /etc/redhat-release && echo 1 || echo 0)
%if %{is_redhat}
## define a default distribution model on Red Hat Linux
%define dist_prefix       .el
%define dist_version      %(echo `rpm -qf --qf='%{VERSION}' /etc/redhat-release` | tr -d [A-Za-z])
%define dist              %{dist_prefix}%{dist_version}
%endif
%endif
%endif
%endif



###############################################################################
###                       P A C K A G E   H E A D E R                       ###
###############################################################################

Name:           %{base_name}
Version:        %{base_version}
Release:        %{base_release}%{?dist}
Summary:        %{base_summary}
Vendor:         %{base_vendor}
URL:            %{base_url}
License:        %{base_license}
Packager:       %{base_packager}
Group:          %{base_group}


## Without AutoReqProv: no, rpmbuild finds all sorts of crazy
## dependencies that we don't care about, and refuses to install
AutoReqProv:    no

BuildArch:      noarch
BuildRoot:      %{_builddir}/%{base_name}-root


## NOTE:  This spec file may require a specific JDK, "gcc", and/or "gcc-c++"
##        packages as well as the "rpm" and "rpm-build" packages.
##
##        Technically, "ant" should not need to be in "BuildRequires" since
##        it is the Java equivalent of "make" (and/or "Autotools").
##
BuildRequires:  ant >= 1.6.2

## Without Requires something, rpmbuild will abort!
Requires:       %{base_prefix}-native-tools >= 1.0.0, perl >= 5.8.0, perl-XML-LibXML, perl-libwww-perl >= 5.8.0, policycoreutils, perl-Crypt-SSLeay, perl-XML-SAX >= 0.12


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
Public Key Infrastructure (PKI) setup scripts used to create and remove
instances from %{base_entity} PKI deployments.



###############################################################################
###                  P R E P A R A T I O N   &   S E T U P                  ###
###############################################################################

## On Linux systems, prep and setup expect there to be a Source file
## in the /usr/src/redhat/SOURCES directory - it will be unpacked
## in the _builddir (not BuildRoot)
%prep


%setup -q


## This package currently contains no patches!
#%patch0
# patches



###############################################################################
###                        B U I L D   P R O C E S S                        ###
###############################################################################

%build
ant -Dspecfile=%{base_name}.spec



###############################################################################
###                 I N S T A L L A T I O N   P R O C E S S                 ###
###############################################################################

%install
cd dist/binary
unzip %{name}-%{version}.zip -d ${RPM_BUILD_ROOT}



###############################################################################
###                      C L E A N U P   P R O C E S S                      ###
###############################################################################

%clean
rm -rf ${RPM_BUILD_ROOT}



###############################################################################
###  P R E  &  P O S T   I N S T A L L / U N I N S T A L L   S C R I P T S  ###
###############################################################################

## This package currently contains no pre-installation process!
#%pre


## This package currently contains no post-installation process!
#%post


## This package currently contains no pre-uninstallation process!
#%preun


## This package currently contains no post-uninstallation process!
#%postun



###############################################################################
###   I N V E N T O R Y   O F   F I L E S   A N D   D I R E C T O R I E S   ### 
###############################################################################

%files
%attr(00755,root,root) %{_bindir}/*
%attr(-,root,root)     %{_datadir}/doc/%{base_name}-%{base_version}/*
%attr(-,root,root)     %{_datadir}/%{base_prefix}/scripts/*



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Mon Apr 20 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-3
- Bugzilla Bug #472832 -  pkicreate/ pkiremove have incorrect path
  for Perl for Solaris.
* Thu Apr 16 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-2
- Bugzilla Bug #495959 -  pkiremove requires "perl-XML-SAX" as a runtime
  dependency
* Sat Apr 4 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-1
- Version update to Dogtag 1.1.0.
* Sat Mar 28 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-21
- Bugzilla Bug #492180 -  Security officer: token recovery for a security
  officer throws error 28 'connection to server lost'.
- Bugzilla Bug #492503 -  Integrate "mod_revocator" as a runtime dependency
  for RA and TPS  
* Fri Mar 20 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-20
- Bugzilla Bug #490489 -  Configuration modifications are not replicated
  between admins, agents, and end entities
- Bugzilla Bug #490483 -  Unable to configure CA using "Shared Ports"
* Wed Mar 18 2009 Christina Fu <cfu@redhat.com> 1.0.0-19
- Bugzilla Bug # 485166 - Signed Audit Feature for TPS
* Wed Mar 11 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-18
- Bugzilla Bug #488338 -  start/stop scripts should list all the
  available port numbers with their functionality
- Bugzilla Bug #440164 -  Dogtag subsystems should show up in
  Fedora8 administrator Services window
* Tue Mar 10 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-17
- Bugzilla Bug #489404 -  fixed non-secure port
* Tue Mar 10 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-16
- Bugzilla Bug #440350 -  Removed unnecessary creation/deletion of kill scripts
* Fri Mar 6 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-15
- Bugzilla Bug #440350 -  Dogtag stop/start scripts should be chkconfig aware
- Bugzilla Bug #488162 -  Fix permissions on "pwcache.conf" file . . .
* Wed Mar 4 2009 Ade Lee <alee@redhat.com> 1.0.0-14
- Bugzilla Bug 487871, 488561 - pkiremove cleanup and remove all selinux ports
* Wed Mar 4 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-13
- Bugzilla Bug #440344 -  Installation page should tell admins to use
  "service", not "/etc/init.d" on Linux
* Tue Feb 24 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-12
- Bugzilla Bug #485859 -  port separation for RA and TPS
* Wed Feb 11 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-11
- Bugzilla Bug #467155 - Change "renameTo" to "cp -p "
* Mon Feb 9 2009 Ade Lee <alee@redhat.com> 1.0.0-10
- Bugzilla Bugs #480418, 480419, 479891
* Thu Jan 22 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-9
- Bugzilla Bug #480952 - added "perl-XML-Simple" and "perl-libwww-perl"
  runtime dependencies
* Fri Nov 28 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-8
- Bugzilla Bug #445402 - changed "linux"/"fedora" to "dogtag"; changed
                         "pki-svn.fedora.redhat.com" to "pki.fedoraproject.org"
* Mon Nov 24 2008 Ade Lee  <alee@redhat.com> 1.0.0-7
- Add selinux changes bugzilla #237727.
* Sat Nov 22 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-6
- Bugzilla Bug #472305 - "equality" tests in all spec files need to be fixed
- Bumped "java" and "java-devel" 1.4.2 and 1.5.0 dependencies to 1.6.0
- Changed "java-sdk" to "java-devel" for consistency
* Thu Oct 9  2008 Jack Magne  <jmagne@redhat.com> 1.0.0-5
- Fix for port separation bug #466188.
* Fri Oct 9 2008 Ade Lee  <alee@redhat.com> 1.0.0-4
- Fix for bug #223361 and #224864. Security Domain in ldap.
* Thu Jul 10 2008 Jack Magne  <jmagne@redhat.com> 1.0.0-3
- Fix for bug #458337.
* Tue Apr  1 2008 Jack Magne <jmagne@redhat.com>  1.0.0-2
- Fix for Bug# 440084 - Installation Error Messages Need Improvement.
* Tue Feb 19 2008 PKI Team <pki-devel@redhat.com> 1.0.0-1
- Initial open source version based upon proprietary
  Red Hat Certificate System (RHCS) 7.3.


