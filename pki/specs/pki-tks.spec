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

Name:             pki-tks
Version:          9.0.0
Release:          1%{?dist}
Summary:          Certificate System - Token Key Service
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
Requires:         pki-selinux
Requires:         pki-tks-theme
Requires(post):   chkconfig
Requires(preun):  chkconfig
Requires(preun):  initscripts
Requires(postun): initscripts

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Certificate System (CS) is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Token Key Service (TKS) is an optional PKI subsystem that manages the
master key(s) and the transport key(s) required to generate and distribute
keys for hardware tokens.  TKS provides the security between tokens and an
instance of Token Processing System (TPS), where the security relies upon the
relationship between the master key and the token keys.  A TPS communicates
with a TKS over SSL using client authentication.

TKS helps establish a secure channel (signed and encrypted) between the token
and the TPS, provides proof of presence of the security token during
enrollment, and supports key changeover when the master key changes on the
TKS.  Tokens with older keys will get new token keys.

Because of the sensitivity of the data that TKS manages, TKS should be set up
behind the firewall with restricted access.

For deployment purposes, a TKS requires the following components from the PKI
Core package:

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
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_TKS:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot}


%pre


%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-tksd || :


%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-tksd stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-tksd || :
fi


%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-tksd condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root,-)
%doc base/tks/LICENSE
%{_initrddir}/pki-tksd
%{_javadir}/tks-%{version}.jar
%{_javadir}/tks.jar
#%{_javadir}/pki/tks-%{version}.jar
#%{_javadir}/pki/tks/tks.jar
%dir %{_datadir}/pki/tks
%dir %{_datadir}/pki/tks/acl
%{_datadir}/pki/tks/acl/*
%dir %{_datadir}/pki/tks/conf
%{_datadir}/pki/tks/conf/*
%dir %{_datadir}/pki/tks/setup
%{_datadir}/pki/tks/setup/*
%dir %{_datadir}/pki/tks/webapps
%{_datadir}/pki/tks/webapps/*
%dir %{_localstatedir}/lock/pki/tks
%dir %{_localstatedir}/run/pki/tks


%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

