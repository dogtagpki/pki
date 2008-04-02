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
%define base_product      Registration Authority
%define base_component    ra
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_prefix}-%{base_component}
%define base_version      1.0.0
%define base_release      2
%define base_group        System Environment/Daemons
%define base_vendor       Red Hat, Inc.
%define base_license      GPLv2 with exceptions
%define base_packager     %{base_vendor} <http://bugzilla.redhat.com/bugzilla>
%define base_summary      %{base_pki} - %{base_product}
%define base_url          http://pki-svn.fedora.redhat.com/wiki/PKI_Documentation

## Pre & Post Install/Uninstall Scripts Definitions
%define base_user         pkiuser

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
BuildRequires:  ant >= 1.6.2, %{base_ui} >= 1.0.0

## Without Requires something, rpmbuild will abort!
Requires:       %{base_name}-ui, %{base_prefix}-setup >= 1.0.0, mod_nss >= 1.0.3, mod_perl >= 1.99_16, mozldap >= 6.0.2, perl-DBD-SQLite >= 1.11, perl-HTML-Parser >= 3.35, perl-HTML-Tagset >= 3.03, perl-Parse-RecDescent >= 1.94, perl-URI >= 1.30, perl-XML-NamespaceSupport >= 1.08, perl-XML-Parser >= 2.34, perl-XML-SAX >= 0.12, perl-XML-Simple >= 2.14, perl-libwww-perl >= 5.79, sendmail >= 8.13.1, sqlite >= 3.3.3


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
%{base_pki} is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The %{pki_ra} is an optional PKI subsystem that
acts as a front-end for authenticating and processing
enrollment requests, PIN reset requests, and formatting requests.

%{pki_ra} communicates over SSL with the
%{pki_ca} to fulfill the user's requests.



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

%pre
if [ `grep -c %{base_user} /etc/group` -eq 0 ] ; then
	groupadd %{base_user}
fi
if [ `grep -c %{base_user} /etc/passwd` -eq 0 ] ; then
	# SELinux policy requires a shell of /sbin/nologin
	useradd -g %{base_user} -d %{_datadir}/%{base_prefix} -s /sbin/nologin -c "%{base_pki}" -m %{base_user}
fi


%post
chmod 00755 %{_datadir}/%{base_prefix}/%{base_component}/setup/postinstall
%{_datadir}/%{base_prefix}/%{base_component}/setup/postinstall %{base_prefix} %{base_component} %{base_version} %{base_release}
echo ""
echo "Install finished."


%preun
if [ -x /etc/init.d/%{base_name} ] ; then
	/etc/init.d/%{base_name} stop
fi


## This package currently contains no post-uninstallation process!
#%postun



###############################################################################
###   I N V E N T O R Y   O F   F I L E S   A N D   D I R E C T O R I E S   ### 
###############################################################################

%files
%attr(-,root,root)     %{_datadir}/doc/%{base_name}-%{base_version}/*
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/alias
%attr(00660,root,root) %{_datadir}/%{base_prefix}/%{base_component}/conf/CS.cfg
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/conf/[a-z]*
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/docroot
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/etc
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/lib
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/logs
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/scripts
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/setup



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Tue Apr 1 2008 Jack Magne <jmagne@redhat.com> 1.0.0-2
- Fix for bug#440084 - Subsystem Installation Error Message Needs Improvement.
* Tue Feb 19 2008 PKI Team <pki-devel@redhat.com> 1.0.0-1
- Initial open source version based upon proprietary
  Red Hat Certificate System (RHCS) 7.3.

