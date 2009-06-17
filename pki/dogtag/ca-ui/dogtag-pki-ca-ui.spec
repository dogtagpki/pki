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
%define base_ui_prefix    dogtag

## Product Definitions
%define base_system       Certificate System
%define base_product      Certificate Authority User Interface
%define base_component    ca-ui
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_ui_prefix}-%{base_prefix}-%{base_component}
%define base_version      1.1.0
%define base_release      11
%define base_group        System Environment/Base
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
Requires:       bash >= 3.0
Provides:       %{base_prefix}-%{base_component}
Obsoletes:      %{base_prefix}-%{base_component}


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
%{base_pki} is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The %{base_entity} %{base_product} contains the graphical
user interface for the %{pki_ca}.



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
%attr(-,root,root)     %{_datadir}/doc/%{base_name}-%{base_version}/*
%attr(-,root,root)     %{_datadir}/%{base_prefix}/*



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Mon Jun 15 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-11
- Bugzilla Bug #502908 -  Current page not found handling is a Cat 2 finding
  with the Tomcat STIG
* Fri Jun 12 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-10
- Bugzilla Bug #502694 - adding random nonces
* Sat May 30 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-9
- Bugzilla Bug #482935 - Adding search limits
* Wed May 20 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-8
- Bugzilla Bug #491185 - added new revocation reasons to comply with RFC 5280
* Wed May 13 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-7
- Bugzilla Bug #490551 - Use profile key constraints to control enrollment key sizes on IE
* Wed May 13 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-6
- Bugzilla Bug #500498 -  CA installation wizard doesn't install
  administrator cert into browser on Firefox 3
* Tue May 12 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-5
- Bugzilla Bug #500489 -  CA installation wizard doesn't prompt to
  download/install CA chain on Firefox 3
* Sun May 10 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-4
- Bugzilla Bug #490551 - Use profile key constraints to control enrollment key sizes
* Tue May 5 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-3
- Bugzilla Bug #492735 -  Configuration wizard stores certain incorrect
  port values within TPS "CS.cfg" . . .
- Bugzilla Bug #495597 -  Unable to access Agent page using a configured
  CA/KRA containing an HSM
* Fri Apr 10 2009 Ade Lee <alee@redhat.com> 1.1.0-2
- Bugzilla Bug #223353 - Values entered through web ui are not checked/escaped
* Sat Apr 4 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-1
- Version update to Dogtag 1.1.0.
* Tue Mar 31 2009 Andrew Wnuk <awnuk@redhat.com> 1.0.0-13
- Bugzilla Bug #490551 - 1024-bit and 2048-bit issuance configuration
* Mon Mar 30 2009 Andrew Wnuk <awnuk@redhat.com> 1.0.0-12
- Bugzilla Bug #492952 - better handling of enrollment objects for IE
* Fri Mar 27 2009 Andrew Wnuk <awnuk@redhat.com> 1.0.0-11
- Bugzilla Bug #224827 - new default cryptographic provider
* Tue Mar 24 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-10
- Bugzilla Bug #488388 -  copyright notices - remove from UI
- Bugzilla Bug #440543 -  CA's web-services page needs improvements
* Fri Jan 30 2009 Ade Lee <alee@redhat.com> 1.0.0-9
- Bugzilla Bug #460582 - add UTF-8 support
* Wed Jan 28 2009 Christina Fu <cfu@redhat.com> 1.0.0-8
- Bugzilla Bug #482733 - make outputXML available via profiles; add request id in response for deferred
* Fri Nov 28 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-7
- Bugzilla Bug #445402 - changed "linux"/"fedora" to "dogtag"; changed
                         "pki-svn.fedora.redhat.com" to "pki.fedoraproject.org"
* Sat Nov 22 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-6
- Bugzilla Bug #472305 - "equality" tests in all spec files need to be fixed
- Bumped "java" and "java-devel" 1.4.2 and 1.5.0 dependencies to 1.6.0
- Changed "java-sdk" to "java-devel" for consistency
* Tue Nov 18 2008 Christina Fu <cfu@redhat.com> 1.0.0-5
- Bugzilla Bug #471622 - Need Renewal feature via enrollment profile Framework (phase 1)
* Wed Oct 15 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-4
- Fix for Bug 466064: Search filters built by CA servlets are not always correct
* Wed Oct 8 2008 Jack Magne  <jmagne@redhat.com> 1.0.0-3
- Bugzilla bug #405451, Vista client support.
* Tue Oct 7 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-2
- Bugzilla bug #445436 - Bad search filter is reported by Revoke Certificates in Agent Interface
* Tue Feb 19 2008 PKI Team <pki-devel@redhat.com> 1.0.0-1
- Initial open source version based upon proprietary
  Red Hat Certificate System (RHCS) 7.3.

