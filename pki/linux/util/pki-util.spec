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
%define base_product      PKI Utility Framework
%define base_component    util
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_prefix}-%{base_component}
%define base_version      1.0.0
%define base_release      2
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
%define pki_jdk           java-1.5.0-ibm-devel >= 1.5.0.3
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
## Bugzilla Bug #246173:  The following section is necessary due to
## Bugzilla Bug #232224 and is related to using the IBM JDK with a
## specific version of glibc on specific platforms on specific architectures
%ifarch x86_64
#export LD_PRELOAD=/usr/lib/jvm/java-1.5.0-ibm-1.5.0.3.x86_64/jre/bin/libj9vm23.so:/usr/lib/jvm/java-1.5.0-ibm-1.5.0.3.x86_64/jre/bin/libj9thr23.so:/usr/lib/jvm/java-1.5.0-ibm-1.5.0.3.x86_64/jre/bin/libjsig.so
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
%define openjdk           %(test %{dist_version} -ge 9 && echo 1 || echo 0)
%if %{openjdk}
## redefine the JDK used to build on Fedora 9 Linux
%define pki_jdk           java-sdk >= 1.6.0
%endif
%define openjdk           %(test %{dist_version} -eq 8 && echo 1 || echo 0)
%if %{openjdk}
## redefine the JDK used to build on Fedora 8 Linux
%define pki_jdk           java-sdk >= 1.7.0
%endif
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
BuildRequires:  ant >= 1.6.2, %{pki_jdk}, jpackage-utils >= 1.6.0, jss >= 4.2.4, ldapjdk >= 4.17, osutil >= 1.0.0

## Without Requires something, rpmbuild will abort!
Requires:       jpackage-utils >= 1.6.0, jss >= 4.2.4, ldapjdk >= 4.17


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
mv cmsutil.jar cmsutil-%{version}.jar
mv nsutil.jar nsutil-%{version}.jar
ln -s cmsutil-%{version}.jar cmsutil.jar
ln -s nsutil-%{version}.jar nsutil.jar



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
%attr(-,root,root)     %{_datadir}/doc/%{base_name}-%{base_version}/*
%attr(-,root,root)     %{_datadir}/java/%{base_prefix}


%files javadoc
%defattr(0644,root,root,0755)
%dir %{_javadocdir}/%{name}-%{version}
%{_javadocdir}/%{name}-%{version}/*



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Mon Jun 9 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-2
- Bugzilla Bug #450345:  Port Dogtag 1.0.0 to
  Fedora 9 (32-bit i386 & 64-bit x86_64).
* Tue Feb 19 2008 PKI Team <pki-devel@redhat.com> 1.0.0-1
- Initial open source version based upon proprietary
  Red Hat Certificate System (RHCS) 7.3.

