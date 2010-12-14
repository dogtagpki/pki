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

Name:             dogtag-pki-theme
Version:          9.0.0
Release:          1%{?dist}
Summary:          Certificate System - Dogtag PKI Theme Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%global overview                                                          \
=========================================                                 \
||  ABOUT "DOGTAG CERTIFICATE SYSTEM"  ||                                 \
=========================================                                 \
                                                                          \
Dogtag Certificate System (DCS) is an enterprise software system designed \
to manage enterprise Public Key Infrastructure (PKI) deployments.         \
                                                                          \
The Dogtag PKI Suite is comprised of the following six subsystems         \
and a client (for use by a Token Management System):                      \
                                                                          \
  * Certificate Authority (CA)                                            \
  * Data Recovery Manager (DRM)                                           \
  * Online Certificate Status Protocol (OCSP) Manager                     \
  * Registration Authority (RA)                                           \
  * Token Key Service (TKS)                                               \
  * Token Processing System (TPS)                                         \
  * Enterprise Security Client (ESC)                                      \
                                                                          \
Additionally, it provides a console GUI application used for              \
server and user/group administration of CA, DRM, OCSP, and TKS,           \
javadocs on portions of the Dogtag API, as well as various                \
command-line tools used to assist with a Dogtag PKI deployment.           \
                                                                          \
To successfully deploy instances of a CA, DRM, OCSP, or TKS, a            \
Tomcat Web Server must be up and running locally on this machine.         \
                                                                          \
To successfully deploy instances of an RA, or TPS, an                     \
Apache Web Server must be up and running locally on this machine.         \
                                                                          \
To meet the database storage requirements of each CA, DRM, OCSP,          \
TKS, or TPS instance, a 389 Directory Server must be up and               \
running either locally on this machine, or remotely over the              \
attached network connection.                                              \
                                                                          \
To meet the database storage requirements of an RA, an SQLite             \
database will be created locally on this machine each time a              \
new RA instance is created.                                               \
                                                                          \
Dogtag utilizes the 'pkicreate' utility to install a PKI subsystem;       \
always use the 'pkicreate' and 'pkiremove' utilities to respectively      \
create and remove PKI instances.                                          \
                                                                          \
Finally, to become operational, each PKI subsystem instance must be       \
configured either manually via a Firefox browser, or by virtue of         \
the batch configuration utility called 'pkisilent'.                       \
                                                                          \
For deployment purposes, Dogtag PKI requires ALL of the subpackages       \
defined by the "pki-core" package.  Additionally, if an instance of       \
a DRM ('pki-kra'), OCSP ('pki-ocsp'), RA ('pki-ra'), TKS ('pki-tks'),     \
TPS ('pki-tps'), and/or ESC ('esc') is to be deployed, the associated     \
package(s) will also need to be installed (and configured).               \
                                                                          \
%{nil}

%description %{overview}


###############################################################################
###                   S U B P A C K A G E   H E A D E R S                   ###
###############################################################################

################################
##  dogtag-pki-common-theme   ##
################################

%package -n       dogtag-pki-common-theme
Summary:          Certificate System - PKI Common Framework User Interface
Group:            System Environment/Base

# NOTE:  Several PKI packages require a "virtual" Theme component.  These
#        "virtual" Theme components are "Provided" by various Theme "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" Theme components MUST be
#        mutually exclusive!
Conflicts:        null-pki-common-theme
Conflicts:        null-pki-common-ui
Conflicts:        redhat-pki-common-theme
Conflicts:        redhat-pki-common-ui

Obsoletes:        dogtag-pki-common-theme < %{version}-%{release}
Obsoletes:        dogtag-pki-common-ui

Provides:         pki-common-theme = %{version}-%{release}
Provides:         pki-common-ui = %{version}-%{release}

%description -n   dogtag-pki-common-theme
This PKI Common Framework User Interface contains
the Dogtag textual and graphical user interface for the PKI Common Framework.

This package is used by the Dogtag Certificate System.

%{overview}


################################
##    dogtag-pki-ca-theme     ##
################################

%package -n       dogtag-pki-ca-theme
Summary:          Certificate System - Certificate Authority User Interface
Group:            System Environment/Base

# NOTE:  Several PKI packages require a "virtual" Theme component.  These
#        "virtual" Theme components are "Provided" by various Theme "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" Theme components MUST be
#        mutually exclusive!
Conflicts:        null-pki-ca-theme
Conflicts:        null-pki-ca-ui
Conflicts:        redhat-pki-ca-theme
Conflicts:        redhat-pki-ca-ui

Obsoletes:        dogtag-pki-ca-theme < %{version}-%{release}
Obsoletes:        dogtag-pki-ca-ui

Provides:         pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-ui = %{version}-%{release}

%description -n   dogtag-pki-ca-theme
This Certificate Authority (CA) User Interface contains
the Dogtag textual and graphical user interface for the CA.

This package is used by the Dogtag Certificate System.

%{overview}


################################
##    dogtag-pki-kra-theme    ##
################################

%package -n       dogtag-pki-kra-theme
Summary:          Certificate System - Data Recovery Manager User Interface
Group:            System Environment/Base

# NOTE:  Several PKI packages require a "virtual" Theme component.  These
#        "virtual" Theme components are "Provided" by various Theme "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" Theme components MUST be
#        mutually exclusive!
#Conflicts:        null-pki-kra-theme
#Conflicts:        null-pki-kra-ui
Conflicts:        redhat-pki-kra-theme
Conflicts:        redhat-pki-kra-ui

Obsoletes:        dogtag-pki-kra-theme < %{version}-%{release}
Obsoletes:        dogtag-pki-kra-ui

Provides:         pki-kra-theme = %{version}-%{release}
Provides:         pki-kra-ui = %{version}-%{release}

%description -n   dogtag-pki-kra-theme
This Data Recovery Manager (DRM) User Interface contains
the Dogtag textual and graphical user interface for the DRM.

This package is used by the Dogtag Certificate System.

%{overview}


################################
##   dogtag-pki-ocsp-theme    ##
################################

%package -n       dogtag-pki-ocsp-theme
Summary:          Certificate System - Online Certificate Status Protocol Manager User Interface
Group:            System Environment/Base

# NOTE:  Several PKI packages require a "virtual" Theme component.  These
#        "virtual" Theme components are "Provided" by various Theme "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" Theme components MUST be
#        mutually exclusive!
#Conflicts:        null-pki-ocsp-theme
#Conflicts:        null-pki-ocsp-ui
Conflicts:        redhat-pki-ocsp-theme
Conflicts:        redhat-pki-ocsp-ui

Obsoletes:        dogtag-pki-ocsp-theme < %{version}-%{release}
Obsoletes:        dogtag-pki-ocsp-ui

Provides:         pki-ocsp-theme = %{version}-%{release}
Provides:         pki-ocsp-ui = %{version}-%{release}

%description -n   dogtag-pki-ocsp-theme
This Online Certificate Status Protocol (OCSP) Manager User Interface contains
the Dogtag textual and graphical user interface for the OCSP Manager.

This package is used by the Dogtag Certificate System.

%{overview}


################################
##    dogtag-pki-ra-theme     ##
################################

%package -n       dogtag-pki-ra-theme
Summary:          Certificate System - Registration Authority User Interface
Group:            System Environment/Base

# NOTE:  Several PKI packages require a "virtual" Theme component.  These
#        "virtual" Theme components are "Provided" by various Theme "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" Theme components MUST be
#        mutually exclusive!
#Conflicts:        null-pki-ra-theme
#Conflicts:        null-pki-ra-ui
Conflicts:        redhat-pki-ra-theme
Conflicts:        redhat-pki-ra-ui

Obsoletes:        dogtag-pki-ra-theme < %{version}-%{release}
Obsoletes:        dogtag-pki-ra-ui

Provides:         pki-ra-theme = %{version}-%{release}
Provides:         pki-ra-ui = %{version}-%{release}

%description -n   dogtag-pki-ra-theme
This Registration Authority (RA) User Interface contains
the Dogtag textual and graphical user interface for the RA.

This package is used by the Dogtag Certificate System.

%{overview}


################################
##    dogtag-pki-tks-theme    ##
################################

%package -n       dogtag-pki-tks-theme
Summary:          Certificate System - Token Key Service User Interface
Group:            System Environment/Base

# NOTE:  Several PKI packages require a "virtual" Theme component.  These
#        "virtual" Theme components are "Provided" by various Theme "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" Theme components MUST be
#        mutually exclusive!
#Conflicts:        null-pki-tks-theme
#Conflicts:        null-pki-tks-ui
Conflicts:        redhat-pki-tks-theme
Conflicts:        redhat-pki-tks-ui

Obsoletes:        dogtag-pki-tks-theme < %{version}-%{release}
Obsoletes:        dogtag-pki-tks-ui

Provides:         pki-tks-theme = %{version}-%{release}
Provides:         pki-tks-ui = %{version}-%{release}

%description -n   dogtag-pki-tks-theme
This Token Key Service (TKS) User Interface contains
the Dogtag textual and graphical user interface for the TKS.

This package is used by the Dogtag Certificate System.

%{overview}


################################
##    dogtag-pki-tps-theme    ##
################################

%package -n       dogtag-pki-tps-theme
Summary:          Certificate System - Token Processing System User Interface
Group:            System Environment/Base

# NOTE:  Several PKI packages require a "virtual" Theme component.  These
#        "virtual" Theme components are "Provided" by various Theme "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" Theme components MUST be
#        mutually exclusive!
#Conflicts:        null-pki-tps-theme
#Conflicts:        null-pki-tps-ui
Conflicts:        redhat-pki-tps-theme
Conflicts:        redhat-pki-tps-ui

Obsoletes:        dogtag-pki-tps-theme < %{version}-%{release}
Obsoletes:        dogtag-pki-tps-ui

Provides:         pki-tps-theme = %{version}-%{release}
Provides:         pki-tps-ui = %{version}-%{release}

%description -n   dogtag-pki-tps-theme
This Token Processing System (TPS) User Interface contains
the Dogtag textual and graphical user interface for the TPS.

This package is used by the Dogtag Certificate System.

%{overview}


################################
##  dogtag-pki-console-theme  ##
################################

%package -n       dogtag-pki-console-theme
Summary:          Certificate System - PKI Console User Interface
Group:            System Environment/Base

# NOTE:  Several PKI packages require a "virtual" Theme component.  These
#        "virtual" Theme components are "Provided" by various Theme "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" Theme components MUST be
#        mutually exclusive!
#Conflicts:        null-pki-console-theme
#Conflicts:        null-pki-console-ui
Conflicts:        redhat-pki-console-theme
Conflicts:        redhat-pki-console-ui

Obsoletes:        dogtag-pki-console-theme < %{version}-%{release}
Obsoletes:        dogtag-pki-console-ui

Provides:         pki-console-theme = %{version}-%{release}
Provides:         pki-console-ui = %{version}-%{release}

%description -n   dogtag-pki-console-theme
This PKI Console User Interface contains
the Dogtag textual and graphical user interface for the PKI Console.

This package is used by the Dogtag Certificate System.

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
%cmake -DBUILD_DOGTAG_PKI_THEME:BOOL=ON ..
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

################################
##  dogtag-pki-common-theme   ##
################################


################################
##    dogtag-pki-ca-theme     ##
################################


################################
##    dogtag-pki-kra-theme    ##
################################


################################
##   dogtag-pki-ocsp-theme    ##
################################


################################
##    dogtag-pki-ra-theme     ##
################################


################################
##    dogtag-pki-tks-theme    ##
################################


################################
##    dogtag-pki-tps-theme    ##
################################


################################
##  dogtag-pki-console-theme  ##
################################


###############################################################################
###  P R E  &  P O S T   I N S T A L L / U N I N S T A L L   S C R I P T S  ###
###############################################################################

################################
##  dogtag-pki-common-theme   ##
################################


################################
##    dogtag-pki-ca-theme     ##
################################


################################
##    dogtag-pki-kra-theme    ##
################################


################################
##   dogtag-pki-ocsp-theme    ##
################################


################################
##    dogtag-pki-ra-theme     ##
################################


################################
##    dogtag-pki-tks-theme    ##
################################


################################
##    dogtag-pki-tps-theme    ##
################################


################################
##  dogtag-pki-console-theme  ##
################################


###############################################################################
###   I N V E N T O R Y   O F   F I L E S   A N D   D I R E C T O R I E S   ### 
###############################################################################

################################
##  dogtag-pki-common-theme   ##
################################

%files -n dogtag-pki-common-theme
%defattr(-,root,root,-)
%doc dogtag/common-ui/LICENSE
%dir %{_datadir}/pki
%dir %{_datadir}/pki/common-ui
%{_datadir}/pki/common-ui/*


################################
##    dogtag-pki-ca-theme     ##
################################

%files -n dogtag-pki-ca-theme
%defattr(-,root,root,-)
%doc dogtag/ca-ui/LICENSE
%dir %{_datadir}/pki/ca-ui
%{_datadir}/pki/ca-ui/*


################################
##    dogtag-pki-kra-theme    ##
################################

%files -n dogtag-pki-kra-theme
%defattr(-,root,root,-)
%doc dogtag/kra-ui/LICENSE
%dir %{_datadir}/pki/kra-ui
%{_datadir}/pki/kra-ui/*


################################
##   dogtag-pki-ocsp-theme    ##
################################

%files -n dogtag-pki-ocsp-theme
%defattr(-,root,root,-)
%doc dogtag/ocsp-ui/LICENSE
%dir %{_datadir}/pki/ocsp-ui
%{_datadir}/pki/ocsp-ui/*


################################
##    dogtag-pki-ra-theme     ##
################################

%files -n dogtag-pki-ra-theme
%defattr(-,root,root,-)
%doc dogtag/ra-ui/LICENSE
%dir %{_datadir}/pki/ra-ui
%{_datadir}/pki/ra-ui/*


################################
##    dogtag-pki-tks-theme    ##
################################

%files -n dogtag-pki-tks-theme
%defattr(-,root,root,-)
%doc dogtag/tks-ui/LICENSE
%dir %{_datadir}/pki/tks-ui
%{_datadir}/pki/tks-ui/*


################################
##    dogtag-pki-tps-theme    ##
################################

%files -n dogtag-pki-tps-theme
%defattr(-,root,root,-)
%doc dogtag/tps-ui/LICENSE
%dir %{_datadir}/pki/tps-ui
%{_datadir}/pki/tps-ui/*


################################
##  dogtag-pki-console-theme  ##
################################

%files -n dogtag-pki-console-theme
%defattr(-,root,root,-)
%doc dogtag/console-ui/LICENSE
%{_javadir}/*
#%{_javadir}/pki/*


###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

