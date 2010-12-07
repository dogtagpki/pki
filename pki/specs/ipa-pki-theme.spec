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
# (C) 2010 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK


###############################################################################
###                       P A C K A G E   H E A D E R                       ###
###############################################################################

Name:             ipa-pki-theme
Version:          9.0.0
Release:          1%{?dist}
Summary:          Certificate System - Null PKI Theme Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%define overview                                                       \
==================================                                     \
||  ABOUT "CERTIFICATE SYSTEM"  ||                                     \
==================================                                     \
                                                                       \
Certificate System (CS) is an enterprise software system designed      \
to manage enterprise Public Key Infrastructure (PKI) deployments.      \
                                                                       \
The IPA PKI Suite is comprised of the following subsystems:            \
                                                                       \
  * Certificate Authority (CA)                                         \
                                                                       \
Additionally, it provides javadocs on portions of the API, as well as  \
various command-line tools used to assist with an IPA deployment.      \
                                                                       \
To successfully deploy instances of a CA,                              \
a Tomcat Web Server must be up and running locally on this machine.    \
                                                                       \
To meet the database storage requirements of each CA                   \
instance, a 389 Directory Server must be up and running either locally \
on this machine, or remotely over the attached network connection.     \
                                                                       \
IPA utilizes the 'pkicreate' utility to install a PKI subsystem, and   \
the 'pkisilent' utility to perform a batch configuration of this PKI   \
subsystem.                                                             \
                                                                       \
After installation of this package, IPA utilizes the 'pkicreate' and   \
'pkiremove' utilities to respectively create and remove PKI instances. \
                                                                       \
For deployment purposes, IPA PKI requires ALL of the subpackages       \
defined by the "pki-core" package.                                     \
                                                                       \
%{nil}

%description %{overview}


###############################################################################
###                   S U B P A C K A G E   H E A D E R S                   ###
###############################################################################

##############################
##  null-pki-common-theme   ##
##############################

%package -n       null-pki-common-theme
Summary:          Certificate System - PKI Common Framework User Interface
Group:            System Environment/Base

# NOTE:  Several PKI packages require a "virtual" Theme component.  These
#        "virtual" Theme components are "Provided" by various Theme "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" Theme components MUST be
#        mutually exclusive!
Conflicts:        dogtag-pki-common-theme
Conflicts:        dogtag-pki-common-ui
Conflicts:        redhat-pki-common-theme
Conflicts:        redhat-pki-common-ui

Obsoletes:        null-pki-common-theme < %{version}-%{release}
Obsoletes:        null-pki-common-ui

Provides:         pki-common-theme = %{version}-%{release}
Provides:         pki-common-ui = %{version}-%{release}

%description -n   null-pki-common-theme
This PKI Common Framework User Interface contains
NO textual or graphical user interface for the PKI Common Framework.

This package is used by the Certificate System utilized by IPA.

%{overview}


##############################
##    null-pki-ca-theme     ##
##############################

%package -n       null-pki-ca-theme
Summary:          Certificate System - Certificate Authority User Interface
Group:            System Environment/Base

# NOTE:  Several PKI packages require a "virtual" Theme component.  These
#        "virtual" Theme components are "Provided" by various Theme "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" Theme components MUST be
#        mutually exclusive!
Conflicts:        dogtag-pki-ca-theme
Conflicts:        dogtag-pki-ca-ui
Conflicts:        redhat-pki-ca-theme
Conflicts:        redhat-pki-ca-ui

Obsoletes:        null-pki-ca-theme < %{version}-%{release}
Obsoletes:        null-pki-ca-ui

Provides:         pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-ui = %{version}-%{release}

%description -n   null-pki-ca-theme
This Certificate Authority (CA) User Interface contains
NO textual or graphical user interface for the CA.

This package is used by the Certificate System utilized by IPA.

%{overview}


###############################################################################
###                   P A C K A G E   P R O C E S S I N G                   ###
###############################################################################

%prep


%setup -q


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DBUILD_NULL_THEME:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


###############################################################################
###                 P A C K A G E   I N S T A L L A T I O N                 ###
###############################################################################

%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot}


###############################################################################
###              S U B P A C K A G E   I N S T A L L A T I O N              ###
###############################################################################

##############################
##  null-pki-common-theme   ##
##############################


##############################
##    null-pki-ca-theme     ##
##############################


###############################################################################
###  P R E  &  P O S T   I N S T A L L / U N I N S T A L L   S C R I P T S  ###
###############################################################################

##############################
##  null-pki-common-theme   ##
##############################


##############################
##    null-pki-ca-theme     ##
##############################


###############################################################################
###   I N V E N T O R Y   O F   F I L E S   A N D   D I R E C T O R I E S   ### 
###############################################################################

##############################
##  null-pki-common-theme   ##
##############################

%files -n null-pki-common-theme
%defattr(-,root,root,-)
%doc dogtag/common-ui/LICENSE
%dir %{_datadir}/pki
%dir %{_datadir}/pki/common-ui
%{_datadir}/pki/common-ui/*


##############################
##    null-pki-ca-theme     ##
##############################

%files -n null-pki-ca-theme
%defattr(-,root,root,-)
%doc dogtag/ca-ui/LICENSE
%dir %{_datadir}/pki/ca-ui
%{_datadir}/pki/ca-ui/*


###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

