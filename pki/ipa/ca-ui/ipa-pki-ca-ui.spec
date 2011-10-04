Name:           ipa-pki-ca-ui
Version:        9.0.1
Release:        1%{?dist}
Summary:        Certificate System - Certificate Authority User Interface
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Provides:       pki-ca-ui = %{version}-%{release}

Obsoletes:      pki-ca-ui < %{version}-%{release}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

# NOTE:  Several PKI packages require a "virtual" UI component.  These
#        "virtual" UI components are "Provided" by various UI "flavors"
#        including "dogtag", "redhat", and "ipa".  Consequently,
#        all "dogtag", "redhat", and "ipa" UI components MUST be
#        mutually exclusive!
Conflicts:      dogtag-pki-ca-ui
Conflicts:      redhat-pki-ca-ui

%description
This Certificate Authority User Interface contains NO graphical
user interface for the Certificate Authority.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="ipa" \
    -Dproduct.prefix="pki" \
    -Dproduct="ca-ui" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}

# Remove all '*.htm*' web pages and 'Dogtag-specific' graphics
# Map 'Dogtag' color '#225580' to black
# Map 'Dogtag' color '#4f52b5' to black
# Map 'DCS'    text to 'XXX'
# Map 'dogtag' text to 'XXXXXX'
# Map 'Dogtag' text to 'XXXXXX'
# Map 'DOGTAG' text to 'XXXXXX'
# Map 'Fedora' text to 'XXXXXX'
# Map 'FEDORA' text to 'XXXXXX'
cd %{buildroot}                                         ;
find . -name "favicon.ico"     -print -or \
       -name "*.htm"           -print -or \
       -name "*.html"          -print -or \
       -name "logo_header.gif" -print | xargs rm        ;
find . -type f -exec sed -i 's/#225580/#000000/g' {} \; ;
find . -type f -exec sed -i 's/#4f52b5/#000000/g' {} \; ;
find . -type f -exec sed -i 's/DCS/XXX/g'         {} \; ;
find . -type f -exec sed -i 's/dogtag/XXXXXX/g'   {} \; ;
find . -type f -exec sed -i 's/Dogtag/XXXXXX/g'   {} \; ;
find . -type f -exec sed -i 's/DOGTAG/XXXXXX/g'   {} \; ;
find . -type f -exec sed -i 's/Fedora/XXXXXX/g'   {} \; ;
find . -type f -exec sed -i 's/FEDORA/XXXXXX/g'   {} \;

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_datadir}/pki/

%changelog
* Tue Jan 18 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.1-1
- updated version due to Package Wrangler comments

* Fri Sep 17 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision.
