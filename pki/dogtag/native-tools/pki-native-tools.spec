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
%define base_product      Native Tools
%define base_component    native-tools
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_prefix}-%{base_component}
%define base_version      1.2.0
%define base_release      1
%define base_group        System Environment/Shells
%define base_vendor       Red Hat, Inc.
%define base_license      GPLv2 with exceptions
%define base_packager     %{base_vendor} <http://bugzilla.redhat.com/bugzilla>
%define base_summary      %{base_pki} - %{base_product}
%define base_url          http://pki.fedoraproject.org/wiki/PKI_Documentation

## Build Definitions
%define base_build_dir    blds
%define base_staging_dir  STAGING

## Installation Definitions
%define base_install_dir  /opt/%{base_component}
%define setup_package     setup_package

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
## 32-bit Definitions
%ifarch i386
%define architecture      intel
%define configure_cmd     ../configure
%endif

## 64-bit Definitions
%ifarch x86_64
%define architecture      intel
%define configure_cmd     ../configure --enable-64bit --libdir=%{base_install_dir}/lib64
%endif

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

BuildRoot:      %{_builddir}/%{name}-root


## NOTE:  This spec file may require a specific JDK, "gcc", and/or "gcc-c++"
##        packages as well as the "rpm" and "rpm-build" packages.
##
##        Technically, "ant" should not need to be in "BuildRequires" since
##        it is the Java equivalent of "make" (and/or "Autotools").
##
BuildRequires:  bash >= 3.0, cyrus-sasl-devel >= 2.1.19, mozldap-devel >= 6.0.2, nspr-devel >= 4.6.99, nss-devel >= 3.12.3.99, svrcore-devel >= 4.0.3.01

## Without Requires something, rpmbuild will abort!
Requires:       mozldap-tools >= 6.0.2, nss >= 3.12.3.99, nss-tools >= 3.12.3.99, perl >= 5.8.0


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
%{base_pki} is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

These platform-dependent PKI executables are used to help make
%{base_pki} into a more complete and robust PKI solution.



###############################################################################
###                  P R E P A R A T I O N   &   S E T U P                  ###
###############################################################################

## On Linux systems, prep and setup expect there to be a Source file
## in the /usr/src/redhat/SOURCES directory - it will be unpacked
## in the _builddir (not BuildRoot)
%prep


%setup -q -n %{base_name}-%{base_version}


## This package currently contains no patches!
#%patch0
# patches



###############################################################################
###                        B U I L D   P R O C E S S                        ###
###############################################################################

%build
%{?pkg_config_cmd}
mkdir %{base_build_dir}
cd %{base_build_dir}
mkdir %{base_staging_dir}
%{configure_cmd}
make



###############################################################################
###                 I N S T A L L A T I O N   P R O C E S S                 ###
###############################################################################

%install
%{?pkg_config_cmd}
rm -rf ${RPM_BUILD_ROOT}
cd %{base_build_dir}
make install DESTDIR="`pwd`/%{base_staging_dir}"

## rearrange files to be in the desired native packaging layout
../%{setup_package} ${RPM_BUILD_ROOT} %{base_prefix} %{base_component} %{version} %{base_release} %{architecture} `pwd`/%{base_staging_dir}/%{base_install_dir}



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
%attr(-,root,root)     %{_libdir}/%{base_prefix}
%attr(-,root,root)     %{_datadir}/%{base_prefix}



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Tue Jul 28 2009 Matthew Harmsen <mharmsen@redhat.com> 1.2.0-1
- Version update to Dogtag 1.2.0.
* Thu Jul 16 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-5
- Bugzilla Bug #512134 -  strip symbols from libraries, modules,
  and executables
* Mon Jul 6 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-4
- bugzilla Bug #509183 -  update nss dependency >= 3.12.3.99
* Wed Jun 24 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-3
- Bugzilla Bug #507746 -  Configure TPS/RA to listen on Ipv4 and Ipv6
  on Ipv4 and Ipv6
* Wed Jun 24 2009 Ade Lee <alee@redhat.com> 1.1.0-2
- Bugzilla Bug 505788 - RA agent list certificates and view a user certificate throws 500 internal server error
* Sat Apr 4 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-1
- Version update to Dogtag 1.1.0.
* Wed Feb 11 2009 Ade Lee <alee@redhat.com> 1.0.0-5
- Bugzilla # 484826 -selinux policy required for TPS and RA subsystems
* Thu Dec 4 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-4
- Bugzilla Bug #474369 - Remove NSS dependency on "pkcs11-devel" and
                         upgrade NSS/NSPR version dependencies  
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

