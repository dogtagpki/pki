Name:           osutil
Version:        9.0.0
Release:        1%{?dist}
Summary:        Operating System Utilities JNI Package
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Libraries

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  nspr-devel >= 4.6.99
BuildRequires:  nss-devel >= 3.12.3.99
BuildRequires:  pkgconfig

Requires:       java >= 1:1.6.0
Requires:       jpackage-utils
Requires:       nss >= 3.12.3.99

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%if 0%{?rhel}
#rhel has no java on ppc
ExcludeArch:    ppc
%endif


%description
The Operating System Utilities Java Native Interface (JNI) package
supplies various native operating system operations to Java programs.

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
make %{?_smp_mflags}

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
* Fri Nov 19 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0.
