Name:           symkey
Version:        1.3.0
Release:        3%{?dist}
Summary:        Symmetric Key JNI Package
URL:            http://pki.fedoraproject.org/
License:        GPLv2 with exceptions
Group:          System Environment/Libraries

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  bash
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  nspr-devel >= 4.6.99
BuildRequires:  nss-devel >= 3.12.3.99
BuildRequires:  pkgconfig

Requires:       java >= 1:1.6.0
Requires:       jpackage-utils
Requires:       jss >= 4.2.6
Requires:       nss >= 3.12.3.99

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
The Symmetric Key Java Native Interface (JNI) package supplies various native
symmetric key operations to Java programs.

%prep

%setup -q -n %{name}-%{version}

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="" \
    -Dproduct="%{name}" \
    -Dversion="%{version}"
%configure \
%ifarch ppc64 s390x sparc64 x86_64
    --enable-64bit \
%endif
    --libdir=%{_libdir}
make

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

## rearrange files to be in the desired native packaging layout
mkdir -p %{buildroot}%{_libdir}/%{name}/
mv %{buildroot}/opt/java/%{name}.jar %{buildroot}%{_libdir}/%{name}/%{name}-%{version}.jar
mv %{buildroot}%{_libdir}/lib%{name}.so %{buildroot}%{_libdir}/%{name}/lib%{name}.so
mkdir -p %{buildroot}%{_jnidir}/
cd %{buildroot}%{_jnidir} ; ln -s %{_libdir}/%{name}/%{name}-%{version}.jar %{name}.jar

## remove unwanted files
rm -rf %{buildroot}/opt
rm -rf %{buildroot}%{_libdir}/lib%{name}.la

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_jnidir}/*
%{_libdir}/%{name}/

%changelog
* Fri Oct 30 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #522272 -  New Package for Dogtag PKI: symkey
- Removed LICENSE logic from installation section
- Take ownership of library directory
* Tue Oct 27 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #522272 -  New Package for Dogtag PKI: symkey
- Complied with Fedora JNI packaging logic
* Mon Oct 12 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-1
- Bugzilla Bug #522272 -  New Package for Dogtag PKI: symkey
