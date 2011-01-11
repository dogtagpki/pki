###############################################################################
###                       P A C K A G E   H E A D E R                       ###
###############################################################################

Name:             pki-kra
Version:          9.0.0
Release:          1%{?dist}
Summary:          Certificate System - Data Recovery Manager
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
Requires:         pki-kra-theme
Requires:         pki-selinux
Requires(post):   chkconfig
Requires(preun):  chkconfig
Requires(preun):  initscripts
Requires(postun): initscripts

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Certificate System (CS) is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Data Recovery Manager (DRM) is an optional PKI subsystem that can act
as a Key Recovery Authority (KRA).  When configured in conjunction with the
Certificate Authority (CA), the DRM stores private encryption keys as part of
the certificate enrollment process.  The key archival mechanism is triggered
when a user enrolls in the PKI and creates the certificate request.  Using the
Certificate Request Message Format (CRMF) request format, a request is
generated for the user's private encryption key.  This key is then stored in
the DRM which is configured to store keys in an encrypted format that can only
be decrypted by several agents requesting the key at one time, providing for
protection of the public encryption keys for the users in the PKI deployment.

Note that the DRM archives encryption keys; it does NOT archive signing keys,
since such archival would undermine non-repudiation properties of signing keys.

For deployment purposes, a DRM requires the following components from the PKI
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
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_KRA:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot}


%pre


%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-krad || :


%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-krad stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-krad || :
fi


%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-krad condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root,-)
%doc base/kra/LICENSE
%{_initrddir}/pki-krad
%{_javadir}/pki/
%dir %{_datadir}/pki
%dir %{_datadir}/pki/kra
%{_datadir}/pki/kra/conf/
%{_datadir}/pki/kra/setup/
%{_datadir}/pki/kra/webapps/
%dir %{_localstatedir}/lock/pki
%dir %{_localstatedir}/lock/pki/kra
%dir %{_localstatedir}/run/pki
%dir %{_localstatedir}/run/pki/kra


%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

