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

Name:             osutil
Version:          9.0.0
Release:          1%{?dist}
Summary:          Operating System Utilities JNI Package
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Libraries

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    java-devel >= 1:1.6.0
BuildRequires:    jpackage-utils
BuildRequires:    nspr-devel >= 4.6.99
BuildRequires:    nss-devel >= 3.12.3.99
BuildRequires:    pkgconfig

Requires:         java >= 1:1.6.0
Requires:         jpackage-utils
Requires:         nss >= 3.12.3.99

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
The Operating System Utilities Java Native Interface (JNI) package
supplies various native operating system operations to Java programs.


%prep


%setup -q


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DBUILD_OSUTIL:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot}

cd %{buildroot}%{_jnidir}
%{__rm} osutil.jar
%{__ln_s} %{_libdir}/osutil/osutil-%{version}.jar osutil.jar

cd %{buildroot}%{_libdir}/osutil
%{__rm} osutil.jar
%{__ln_s} osutil-%{version}.jar osutil.jar


%files
%defattr(-,root,root,-)
%doc base/osutil/LICENSE
%{_jnidir}/osutil.jar
%dir %{_libdir}/osutil
%{_libdir}/osutil/*


%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

