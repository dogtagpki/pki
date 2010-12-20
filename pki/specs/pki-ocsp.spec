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

Name:             pki-ocsp
Version:          9.0.0
Release:          1%{?dist}
Summary:          Certificate System - Online Certificate Status Protocol Manager
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Daemons

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    java-devel >= 1:1.6.0
BuildRequires:    jpackage-utils
BuildRequires:    jss >= 4.2.6
BuildRequires:    pki-common
BuildRequires:    pki-util

Requires:         java >= 1:1.6.0
Requires:         pki-common
Requires:         pki-ocsp-theme
Requires:         pki-selinux
Requires(post):   chkconfig
Requires(preun):  chkconfig
Requires(preun):  initscripts
Requires(postun): initscripts

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Certificate System (CS) is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Online Certificate Status Protocol (OCSP) Manager is an optional PKI
subsystem that can act as a stand-alone OCSP service.  The OCSP Manager
performs the task of an online certificate validation authority by enabling
OCSP-compliant clients to do real-time verification of certificates.  Note
that an online certificate-validation authority is often referred to as an
OCSP Responder.

Although the Certificate Authority (CA) is already configured with an
internal OCSP service.  An external OCSP Responder is offered as a separate
subsystem in case the user wants the OCSP service provided outside of a
firewall while the CA resides inside of a firewall, or to take the load of
requests off of the CA.

The OCSP Manager can receive Certificate Revocation Lists (CRLs) from
multiple CA servers, and clients can query the OCSP Manager for the
revocation status of certificates issued by all of these CA servers.

When an instance of OCSP Manager is set up with an instance of CA, and
publishing is set up to this OCSP Manager, CRLs are published to it
whenever they are issued or updated.

For deployment purposes, an OCSP Manager requires the following components
from the PKI Core package:

  * pki-setup
  * pki-native-tools
  * pki-util
  * pki-java-tools
  * pki-common
  * pki-selinux

and can also make use of the following optional components from the PKI Core
package:

  * pki-util-javadoc
  * pki-java-tools-javadoc
  * pki-common-javadoc
  * pki-silent

Additionally, Certificate System requires ONE AND ONLY ONE of the following
"Mutually-Exclusive" PKI Theme packages:

  * dogtag-pki-theme (Dogtag Certificate System deployments)
  * redhat-pki-theme (Red Hat Certificate System deployments)


%prep


%setup -q


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_OCSP:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot}


%pre


%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-ocspd || :


%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-ocspd stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-ocspd || :
fi


%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-ocspd condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root,-)
%doc base/ocsp/LICENSE
%{_initrddir}/pki-ocspd
%{_javadir}/ocsp-%{version}.jar
%{_javadir}/ocsp.jar
#%{_javadir}/pki/ocsp-%{version}.jar
#%{_javadir}/pki/ocsp/ocsp.jar
%dir %{_datadir}/pki/ocsp
%dir %{_datadir}/pki/ocsp/acl
%{_datadir}/pki/ocsp/acl/*
%dir %{_datadir}/pki/ocsp/conf
%{_datadir}/pki/ocsp/conf/*
%dir %{_datadir}/pki/ocsp/setup
%{_datadir}/pki/ocsp/setup/*
%dir %{_datadir}/pki/ocsp/webapps
%{_datadir}/pki/ocsp/webapps/*
%dir %{_localstatedir}/lock/pki/ocsp
%dir %{_localstatedir}/run/pki/ocsp


%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

