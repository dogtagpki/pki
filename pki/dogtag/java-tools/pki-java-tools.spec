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
%define base_product      PKI Java-Based Tools
%define base_component    java-tools
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_prefix}-%{base_component}
%define base_version      1.0.0
%define base_release      9
%define base_group        System Environment/Shells
%define base_vendor       Red Hat, Inc.
%define base_license      GPLv2 with exceptions
%define base_packager     %{base_vendor} <http://bugzilla.redhat.com/bugzilla>
%define base_summary      %{base_pki} - %{base_product}
%define base_url          http://pki.fedoraproject.org/wiki/PKI_Documentation

## Subpackage Header Definitions
%define javadoc_summary   %{base_summary} Javadocs
%define javadoc_group     Development/Documentation

## Helper Definitions
%define pki_jdk           java-devel >= 1:1.6.0
%define pki_jre           java >= 1:1.6.0
# Override the default 'pki_jdk' and 'pki_jre' on Fedora 8 platforms
%{?fc8:%define pki_jdk    java-devel >= 1.7.0}
%{?fc8:%define pki_jre    java >= 1.7.0}
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
BuildRequires:  ant >= 1.6.2, %{base_prefix}-util >= 1.0.0, %{pki_jdk}, jpackage-utils >= 1.6.0, jss >= 4.2.5, osutil >= 1.0.0

## Without Requires something, rpmbuild will abort!
Requires:       %{base_prefix}-native-tools >= 1.0.0, %{base_prefix}-util >= 1.0.0, %{pki_jre}


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
%{base_pki} is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

These platform-independent PKI executables are used to help make
%{base_pki} into a more complete and robust PKI solution.



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
mv cstools.jar cstools-%{version}.jar
ln -s cstools-%{version}.jar cstools.jar



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
%attr(-,root,root)     %{_datadir}/java/%{base_prefix}
%attr(-,root,root)     %{_datadir}/%{base_prefix}


%files javadoc
%defattr(0644,root,root,0755)
%dir %{_javadocdir}/%{name}-%{version}
%{_javadocdir}/%{name}-%{version}/*



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Thu Mar 26 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-9
- Bugzilla Bug #490947 -  PrettyPrintCrl throws exceptions
* Sat Feb 14 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-8
- Bugzilla Bug #485522 -  Need rpm spec file to require osutil
* Sat Feb 14 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-7
- Bugzilla Bug #250874 -Change spec file dependencies to rely on latest
  versions of components (NSPR, NSS, JSS, MOD_NSS)
* Thu Feb 12 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-6
- Bugzilla Bug #483699 -  problem with the epoch in the spec file causes
  build to fail
* Wed Feb 11 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-5
- Bugzilla Bug #467155 - Change "renameTo" to "cp -p "
- cleaned up some javadoc warnings
* Thu Jan 22 2009 Christina Fu <cfu@redhat.com> 1.0.0-4
- Bugzilla Bug 481237 - Audit Log signing framework
* Fri Nov 28 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-3
- Bugzilla Bug #445402 - changed "linux"/"fedora" to "dogtag"; changed
                         "pki-svn.fedora.redhat.com" to "pki.fedoraproject.org"
* Sat Nov 22 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-2
- Bugzilla Bug #472305 - "equality" tests in all spec files need to be fixed
- Bumped "java" and "java-devel" 1.4.2 and 1.5.0 dependencies to 1.6.0
- Changed "java-sdk" to "java-devel" for consistency
* Tue Feb 19 2008 PKI Team <pki-devel@redhat.com> 1.0.0-1
- Initial open source version based upon proprietary
  Red Hat Certificate System (RHCS) 7.3.

