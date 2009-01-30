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
%define base_product      PKI Migration Scripts
%define base_component    migrate
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_prefix}-%{base_component}
%define base_version      1.0.0
%define base_release      5
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
#BuildRequires:  ant >= 1.6.2, java-devel, jpackage-utils >= 1.6.0

## Without Requires something, rpmbuild will abort!
Requires:       java


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
%{base_pki} is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

%{base_entity} PKI Migration Scripts are used to export data from previous
versions of Netscape Certificate Management Systems, iPlanet Certificate
Management Systems, and %{base_entity} Certificate Systems into a flat-file
which may then be imported into this release of %{base_pki}.

Note that since this utility is platform-independent, it is generally possible
to migrate data from previous PKI deployments originally stored on other
hardware platforms as well as earlier versions of this operating system.



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
rm -rf ${RPM_BUILD_ROOT}/usr/share/%{base_prefix}/%{base_component}/*/src



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
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/41ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/41ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/41ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/42SP2ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/42SP2ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/42SP2ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/42ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/42ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/42ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/45ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/45ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/45ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/47ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/47ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/47ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/60ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/60ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/60ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/61ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/61ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/61ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/62ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/62ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/62ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/63ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/63ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/63ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/70ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/70ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/70ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/71ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/71ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/71ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/72ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/72ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/72ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/73ToTxt/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/73ToTxt/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/73ToTxt/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/TxtTo60/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo60/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo60/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/TxtTo61/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo61/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo61/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/TxtTo62/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo62/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo62/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/TxtTo70/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo70/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo70/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/TxtTo71/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo71/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo71/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/TxtTo72/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo72/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo72/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/TxtTo73/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo73/run.bat
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo73/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/TxtTo80/classes/*
%attr(00755,root,root) %{_datadir}/%{base_prefix}/%{base_component}/TxtTo80/run.sh
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/80/*


###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Fri Jan 30 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-5
- Bugzilla Bug #253615 - RFE: migration tool needs to be written for the
  serialization changes
- Allowed 63ToTxt binaries to be published
* Fri Nov 28 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-4
- Bugzilla Bug #445402 - changed "linux"/"fedora" to "dogtag"; changed
                         "pki-svn.fedora.redhat.com" to "pki.fedoraproject.org"
* Sat Nov 22 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-3
- Bugzilla Bug #472305 - "equality" tests in all spec files need to be fixed
- Bumped "java" and "java-devel" 1.4.2 and 1.5.0 dependencies to 1.6.0
- Changed "java-sdk" to "java-devel" for consistency
* Fri Oct 10 2008 Ade Lee <alee@redhat.com> 1.0.0-2
- Migration scripts for 8.0 Security Domain #223361
* Tue Feb 19 2008 PKI Team <pki-devel@redhat.com> 1.0.0-1
- Initial open source version based upon proprietary
  Red Hat Certificate System (RHCS) 7.3.

