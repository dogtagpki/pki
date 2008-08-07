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
%define base_product      PKI Common Framework
%define base_component    common
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_prefix}-%{base_component}
%define base_version      1.0.0
%define base_release      14
%define base_group        System Environment/Base
%define base_vendor       Red Hat, Inc.
%define base_license      GPLv2 with exceptions
%define base_packager     %{base_vendor} <http://bugzilla.redhat.com/bugzilla>
%define base_summary      %{base_pki} - %{base_product}
%define base_url          http://pki-svn.fedora.redhat.com/wiki/PKI_Documentation

## Subpackage Header Definitions
%define javadoc_summary   %{base_summary} Javadocs
%define javadoc_group     Development/Documentation

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
## check for presence of UI packages
%define linux_ui          %(echo `rpm -q --quiet %{base_name}-ui; echo $?`)
%define fedora_ui         %(echo `rpm -q --quiet %{base_flavor}-%{base_name}-ui; echo $?`)

%if !%{linux_ui}
## if the Linux UI package is present, default to using it first
%define base_ui           %{base_name}-ui
%else
%if !%{fedora_ui}
## otherwise, if the Fedora UI package is present, use it instead
%define base_ui           %{base_flavor}-%{base_name}-ui
%else
## finally, if neither the Linux nor the Fedora UI packages are present,
## set base_ui to be equal to the Linux UI package to ALWAYS produce a
## "BuildRequires" dependency failure of "%{base_name}-ui"
%define base_ui           %{base_name}-ui
%endif
%endif

## A distribution model is required on certain Linux operating systems!
##
## check for a pre-defined distribution model
%define undefined_distro  %(test "%{dist}"="" && echo 1 || echo 0)
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
BuildRequires:  ant >= 1.6.2, %{base_prefix}-util >= 1.0.0, %{base_ui} >= 1.0.0, java-devel >= 1.4.2, jpackage-utils >= 1.6.0, jss >= 4.2.4, ldapjdk >= 4.17, osutil >= 1.0.0, symkey >= 1.0.0, velocity >= 1.4

## Without Requires something, rpmbuild will abort!
Requires:       %{base_name}-ui, %{base_prefix}-java-tools >= 1.0.0, %{base_prefix}-setup >= 1.0.0, java >= 1.4.2, osutil >= 1.0.0, rhgb >= 0.14.1, symkey >= 1.0.0, tomcatjss >= 1.1.0, velocity >= 1.4


## This package conflicts with the following packages!
Conflicts:      tomcat-native


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
%{base_pki} is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The %{base_entity} %{base_product} is required by the following four
%{base_entity} PKI subsystems:

    the %{pki_ca},
    the %{pki_drm},
    the %{pki_ocsp}, and
    the %{pki_tks}.



###############################################################################
###                    S U B P A C K A G E   H E A D E R                    ###
###############################################################################

%package javadoc
Summary:    %{javadoc_summary}
Group:      %{javadoc_group}


## Subpackages should always use package = version-release
Requires:   %{base_name} = %{version}-%{release}


%description javadoc
%{javadoc_summary}

This documentation pertains exclusively to version %{version} of
the %{base_entity} %{base_product}.



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
cd ${RPM_BUILD_ROOT}/usr/share/java/%{base_prefix}
mv certsrv.jar certsrv-%{version}.jar
ln -s certsrv-%{version}.jar certsrv.jar
mv cms.jar cms-%{version}.jar
ln -s cms-%{version}.jar cms.jar
mv cmsbundle.jar cmsbundle-%{version}.jar
ln -s cmsbundle-%{version}.jar cmsbundle.jar
mv cmscore.jar cmscore-%{version}.jar
ln -s cmscore-%{version}.jar cmscore.jar
mkdir -p ${RPM_BUILD_ROOT}/var/lib/tomcat5/common/lib
cd ${RPM_BUILD_ROOT}/var/lib/tomcat5/common/lib
ln -s /usr/share/java/ldapjdk.jar ldapjdk.jar
ln -s /usr/share/java/velocity.jar velocity.jar
ln -s /usr/share/java/xalan-j2.jar xalan-j2.jar
ln -s /usr/share/java/xerces-j2.jar xerces-j2.jar
ln -s /usr/share/java/%{base_prefix}/cmsutil.jar cmsutil.jar
ln -s /usr/share/java/%{base_prefix}/nsutil.jar nsutil.jar



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


%post
chmod 00755 %{_datadir}/%{base_prefix}/setup/postinstall
%{_datadir}/%{base_prefix}/setup/postinstall %{base_prefix}


## This package currently contains no pre-uninstallation process!
#%preun


## This package currently contains no post-uninstallation process!
#%postun



###############################################################################
###   I N V E N T O R Y   O F   F I L E S   A N D   D I R E C T O R I E S   ### 
###############################################################################

%files
%attr(-,root,root)     %{_datadir}/doc/%{base_name}-%{base_version}/*
%attr(-,root,root)     %{_datadir}/java/%{base_prefix}
%attr(-,root,root)     %{_datadir}/%{base_prefix}/*
%attr(-,root,root)     %{_var}/lib/tomcat5/common/lib/*


%files javadoc
%defattr(0644,root,root,0755)
%dir %{_javadocdir}/%{name}-%{version}
%{_javadocdir}/%{name}-%{version}/*



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Thu Aug 7 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-14
- Fix for Bug 453834.
* Mon Jul 21 2008 Ade Lee <alee@redhat.com> 1.0.0-13
- Fix for Bug 455331.
* Fri Jul 11 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-12
- Fix for bug #243804.
* Wed Jul 9 2008 Christina Fu <cfu@redhat.com> 1.0.0-11
- Fix for Bugzilla Bug #446685: LDAP publisher doesn't store the bind password properly
* Tue Jul 8 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-10
- Fix for Bugzilla Bug #454559:  OCSP returns a nullpointer exception
  if the request is not provided as a parameter in the GET operation
* Wed Jun 25 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-9
- Fix for bug #443687.
* Fri May 16 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-8
- Fix for bug #445470.
* Tue May 7 2008 Jack Magne <jmagne@redhat.com> 1.0.0-7
- Fix for Bug#440079.
* Tue May 6 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-6
- Provided CRL page size as configurable parameter - bug #445400. 
- Fixed typo - bugzilla bug #304668
* Fri Apr 18 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-5
- Fixed bug #441974 - Added "Conflicts: tomcat-native" statement to spec file.
* Thu Apr 17 2008 Christina Fu <cfu@redhat.com> 1.0.0-4
- Implemented bug #442800 - support UUID in Subject Alternative Name extension.  Version 4 only, for now.
* Fri Apr 4 2008 Christina Fu <cfu@redhat.com> 1.0.0-3
- Fixed bug #440989 - [SECURITY] CMC authorization check not done by default
* Fri Apr 4 2008 Christina Fu <cfu@redhat.com> 1.0.0-2
- Fixed bug #439052 - CMC CRMF requests cause exception in logging: Unmatched braces in the pattern
* Tue Feb 19 2008 PKI Team <pki-devel@redhat.com> 1.0.0-1
- Initial open source version based upon proprietary
  Red Hat Certificate System (RHCS) 7.3.

