Name:           pki-selinux
Version:        1.3.0
Release:        5%{?dist}
Summary:        Dogtag Certificate System - PKI Selinux Policies
URL:            https://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: ant
BuildRequires: m4
BuildRequires: make
BuildRequires: policycoreutils
BuildRequires: selinux-policy-devel

Requires: policycoreutils
Requires: selinux-policy-targeted

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Selinux policies for the Pubic Key Infrastructure (PKI) components.

%prep

%setup -q -n %{name}-%{version}

%build
cd src
make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_datadir}/selinux/modules
cp -p src/pki.pp %{buildroot}%{_datadir}/selinux/modules

%clean
rm -rf %{buildroot}

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
semodule -s targeted -i %{_datadir}/selinux/modules/pki.pp
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

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_datadir}/selinux/modules/pki.pp

%changelog
* Fri Jan 8 2010 Kevin Wright <kwright@redhat.com> 1.3.0-5
- Removed fc10 and fc11-specific Requires and Build Requires

* Mon Dec 14 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Removed 'with exceptions' from License

* Mon Dec 7 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #528556 -  policycoreutils-python (semanage) prerequisite
  missing from rpm
- Removed "conditional" support for Fedora 9

* Tue Nov 17 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #521255 - Packaging for Fedora Dogtag PKI
- Remove un-necessary installation steps.

* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #521255 - Packaging for Fedora Dogtag PKI
