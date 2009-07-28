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
%define base_product      PKI Selinux Policies
%define base_component    selinux
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
BuildRequires: ant >= 1.6.2,  m4, make, policycoreutils, selinux-policy-devel
# While 'selinux-policy-devel' is always required on Fedora 12 or later,
# certain earlier Fedora distributions require at least a minimum version
%{?fc8:BuildRequires: selinux-policy-devel >= 3.0.8-127}
%{?fc9:BuildRequires: selinux-policy-devel >= 3.3.1-118}
%{?fc10:BuildRequires: selinux-policy-devel >= 3.5.13-41}
%{?fc11:BuildRequires: selinux-policy-devel >= 3.6.3-10}

Requires: policycoreutils, libsemanage, selinux-policy-targeted
# While 'selinux-policy-targeted' is always required on Fedora 12 or later,
# certain earlier Fedora distributions require at least a minimum version
%{?fc8:Requires: selinux-policy-targeted >= 3.0.8-127}
%{?fc9:Requires: selinux-policy-targeted >= 3.3.1-118}
%{?fc10:Requires: selinux-policy-targeted >= 3.5.13-41}
%{?fc11:Requires: selinux-policy-targeted >= 3.6.3-10}


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
Selinux policies for the Pubic Key Infrastructure (PKI) components.



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
cd src
make



###############################################################################
###                 I N S T A L L A T I O N   P R O C E S S                 ###
###############################################################################

%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/doc/%{base_name}-%{base_version}
cp -p LICENSE ${RPM_BUILD_ROOT}%{_datadir}/doc/%{base_name}-%{base_version}
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/selinux/modules
cp -p src/pki.pp ${RPM_BUILD_ROOT}%{_datadir}/selinux/modules



###############################################################################
###                      C L E A N U P   P R O C E S S                      ###
###############################################################################

%clean
rm -rf ${RPM_BUILD_ROOT}



###############################################################################
###  P R E  &  P O S T   I N S T A L L / U N I N S T A L L   S C R I P T S  ###
###############################################################################

%define saveFileContext() \
if [ -s /etc/selinux/config ]; then \
        . %{_sysconfdir}/selinux/config; \
        FILE_CONTEXT=%{_sysconfdir}/selinux/%1/contexts/files/file_contexts; \
        if [ "${SELINUXTYPE}" == %1 -a -f ${FILE_CONTEXT} ]; then \
                cp -f ${FILE_CONTEXT} ${FILE_CONTEXT}.%{name}; \
        fi \
fi;

%define relabel() \
. %{_sysconfdir}/selinux/config; \
FILE_CONTEXT=%{_sysconfdir}/selinux/%1/contexts/files/file_contexts; \
selinuxenabled; \
if [ $? == 0  -a "${SELINUXTYPE}" == %1 -a -f ${FILE_CONTEXT}.%{name} ]; then \
        fixfiles -C ${FILE_CONTEXT}.%{name} restore; \
        rm -f ${FILE_CONTEXT}.%name; \
fi;

%pre
%saveFileContext targeted

%post
semodule -s targeted -i /usr/share/selinux/modules/pki.pp 
%relabel targeted

%preun
if [ $1 = 0 ]; then
%saveFileContext targeted
fi

%postun
if [ $1 = 0 ]; then
semodule -s targeted -r pki
%relabel targeted
fi

###############################################################################
###   I N V E N T O R Y   O F   F I L E S   A N D   D I R E C T O R I E S   ### 
###############################################################################

%files
%attr(-,root,root)     %{_datadir}/doc/%{base_name}-%{base_version}/*
%attr(-,root,root)     %{_datadir}/selinux/modules/pki.pp



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Tue Jul 28 2009 Matthew Harmsen <mharmsen@redhat.com> 1.2.0-1
- Version update to Dogtag 1.2.0.
* Wed Jul 6 2009 Ade Lee <alee@redhat.com> 1.1.0-10
- Bugzilla Bug 509917 - RA fails to start with SElinux enforcing (lunasa)
* Wed Jun 17 2009 Ade Lee <alee@redhat.com> 1.1.0-9
- Bugzilla Bug 506387 and 506133 - ECC and messages for tps
* Mon Jun 15 2009 Ade Lee <alee@redhat.com> 1.1.0-8
- Bugzilla Bug 504765 - more selinux messages when restarting RA
* Tue Jun 9 2009 Ade Lee <alee@redhat.com> 1.1.0-7
- Bugzilla Bug 504765 - selinux messages when restarting RA
* Fri May 29 2009 Ade Lee <alee@redhat.com> 1.1.0-6
- Bugzilla Bug 495212 - selinux messages from startup/ install
* Mon May 25 2009 Ade Lee <alee@redhat.com> 1.1.0-5
- Bugzilla Bug 499242 -  selinux policy updates needed to ensure that CS works with lunasa hsm
* Fri May 1 2009 Ade Lee <alee@redhat.com> 1.1.0-4
- Bugzilla Bug 495157 - SELinux prevents CA from using nethsm pkcs11 module
* Fri Apr 24 2009 Ade Lee <alee@redhat.com> 1.1.0-3
- Bugzilla Bug 496175 - pkiremove of tps instance throws error message when 
  tps log location is changed.  
* Wed Apr 15 2009 Ade Lee <alee@redhat.com> 1.1.0-2
- Bugzilla Bug #492799 - MasterCRL.bin file is not published to the specified directory
* Sat Apr 4 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-1
- Version update to Dogtag 1.1.0.
* Wed Feb 11 2009 Ade Lee <alee@redhat.com> 1.0.0-7
- Bugzilla # 484826 -selinux policy required for TPS and RA subsystems
* Mon Feb 9 2009 Ade Lee <alee@redhat.com> 1.0.0.6
- Bugzilla Bug #483742 - add version check to spec file for fedora
* Thu Feb 5 2009 Ade Lee <alee@redhat.com> 1.0.0.5
- Bugzilla Bug #483716: changes for TKS installation
* Thu Jan 29 2009 Ade Lee <alee@redhat.com> 1.0.0.4
- Bugzilla Bug #483134 Moved selinux to /usr/share/selinux/modules
* Tue Jan 27 2009 Ade Lee <alee@redhat.com> 1.0.0-3
- Bugzilla Bug #482738 - selinux changes required for cloning
* Tue Jan 20 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-2
- Bugzilla Bug #480679 - integrate latest selinux code with the rest
  of the build infrastructure 

* Mon Jan 19 2009 Ade Lee <alee@redhat.com> 1.0.0-1
- Initial release

