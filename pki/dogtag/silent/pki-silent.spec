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
%define base_product      Silent Installer
%define base_component    silent
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_prefix}-%{base_component}
%define base_version      1.1.0
%define base_release      7
%define base_group        System Environment/Shells
%define base_vendor       Red Hat, Inc.
%define base_license      GPLv2 with exceptions
%define base_packager     %{base_vendor} <http://bugzilla.redhat.com/bugzilla>
%define base_summary      %{base_pki} - %{base_product}
%define base_url          http://pki.fedoraproject.org/wiki/PKI_Documentation

## Helper Definitions
%define pki_jdk           java-devel >= 1:1.6.0
# Override the default 'pki_jdk' on Fedora 8 platforms
%{?fc8:%define pki_jdk    java-devel >= 1.7.0}
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
BuildRequires:  ant >= 1.6.2, %{base_prefix}-common >= 1.0.0, %{base_prefix}-util >= 1.0.0, %{pki_jdk}, jpackage-utils >= 1.6.0, jss >= 4.2.5

## Without Requires something, rpmbuild will abort!
Requires:       %{base_prefix}-common >= 1.0.0


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
%{base_pki} is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The %{base_entity} %{base_product} may be used to "automatically" configure
the following %{base_entity} PKI subsystems in a non-graphical (batch) fashion
including:

    the %{pki_ca},
    the %{pki_drm},
    the %{pki_ocsp},
    the %{pki_ra},
    the %{pki_tks}, and/or
    the %{pki_tps}.



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
cd ${RPM_BUILD_ROOT}/usr/share/java
mv %{base_component}.jar %{base_component}-%{base_version}.jar
ln -s %{base_component}-%{base_version}.jar %{base_component}.jar



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
%attr(00755,root,root) %{_bindir}/*
%attr(-,root,root)     %{_datadir}/java



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Fri Jun 12 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-7
- Bugzilla Bug #503829 -  pkisilent ConfigureSubca fails to import admin cert
* Fri May 29 2009 Ade Lee <alee@redhat.com> 1.1.0-6
- Bugzilla Bug #502947 - pkisilent using wrong parameter name for clone CA PKCS#12 file
* Wed May 20 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-5
- Bugzilla Bug #491517 -  pkisilent Configure RA and TPS fail
* Sat May 16 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-4
- Bugzilla Bug #491517 -  pkisilent Configure RA and TPS fail
  (port separation changes only)
- Bugzilla Bug #495676 -  pkisilent ConfigureCA failure on AdminCertImportPanel
- Bugzilla Bug #500748 -  pki-silent : issues due to port separation changes
  (only addressed CA, KRA, OCSP, and TKS)
* Tue May 5 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-3
- Bugzilla Bug #492735 -  Configuration wizard stores certain incorrect
  port values within TPS "CS.cfg" . . .
- Bugzilla Bug #495597 -  Unable to access Agent page using a configured
  CA/KRA containing an HSM
* Tue Apr 28 2009 Ade Lee <alee@redhat.com> 1.1.0-2
- Bugzilla Bug #493418 silent install -save_p12 option creates file mode 644
* Sat Apr 4 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-1
- Version update to Dogtag 1.1.0.
* Fri Apr 3 2009 Ade Lee <alee@redhat.com> 1.0.0-11
- Bugzilla Bug #491517 and #492648 - subca and TPS fail to configure - audit signing
* Tue Mar 17 2009 Ade Lee <alee@redhat.com> 1.0.0-10
- Bugzilla Bug #490645 - DRM fails to configure
* Tue Mar 10 2009 Ade Lee <alee@redhat.com> 1.0.0-9
- Bugzilla Bug #489057 - Add audit_signing cert to drm, ocsp, tks 
* Fri Feb 20 2009 Ade Lee <alee@redhat.com> 1.0.0-8
- Bugzilla Bug #486028 - Add audit_signing cert 
* Sat Feb 14 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-7
- Bugzilla Bug #250874 -Change spec file dependencies to rely on latest
  versions of components (NSPR, NSS, JSS, MOD_NSS)
* Thu Feb 12 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-6
- Bugzilla Bug #483699 -  problem with the epoch in the spec file causes
  build to fail
* Tue Dec 16 2008 Ade Lee <alee@redhat.com> 1.0.0-5
- Add support for installing cloned CA - bz 472006
* Fri Nov 28 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-4
- Bugzilla Bug #445402 - changed "linux"/"fedora" to "dogtag"; changed
                         "pki-svn.fedora.redhat.com" to "pki.fedoraproject.org"
* Sat Nov 22 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-3
- Bugzilla Bug #472305 - "equality" tests in all spec files need to be fixed
- Bumped "java" and "java-devel" 1.4.2 and 1.5.0 dependencies to 1.6.0
- Changed "java-sdk" to "java-devel" for consistency
* Thu Oct 9 2008 Ade Lee <alee@redhat.com> 1.0.0-2
- Fix for 462035
* Tue Feb 19 2008 PKI Team <pki-devel@redhat.com> 1.0.0-1
- Initial open source version based upon proprietary
  Red Hat Certificate System (RHCS) 7.3.

