# BEGIN COPYRIGHT BLOCK
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
# (C) 2007 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK

###############################################################################
###                          D E F I N I T I O N S                          ###
###############################################################################

## Entity Definitions
%define base_entity       Dogtag
%define base_flavor       dogtag
%define base_prefix       pki

## Product Definitions
%define base_system       Certificate System
%define base_product      Token Processing System
%define base_component    tps
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_prefix}-%{base_component}
%define base_version      1.1.0
%define base_release      14
%define base_group        System Environment/Daemons
%define base_vendor       Red Hat, Inc.
%define base_license      LGPLv2 with exceptions
%define base_packager     %{base_vendor} <http://bugzilla.redhat.com/bugzilla>
%define base_summary      %{base_pki} - %{base_product}
%define base_url          http://pki.fedoraproject.org/wiki/PKI_Documentation

## Legacy Definitions
%define legacy_tokendb    tus

## Build Definitions
%define base_build_dir    blds
%define base_staging_dir  STAGING

## Installation Definitions
%define base_install_dir  /opt/%{base_component}
%define setup_package     setup_package

## Pre & Post Install/Uninstall Scripts Definitions
%define base_user         pkiuser
%define base_instance     /var/lib/%{base_name}

## Helper Definitions
%define pki_ca            %{base_entity} Certificate Authority
%define pki_drm           %{base_entity} Data Recovery Manager
%define pki_ds            Fedora Directory Server
%define pki_ocsp          %{base_entity} Online Certificate Status Protocol Manager
%define pki_ra            %{base_entity} Registration Authority
%define pki_tks           %{base_entity} Token Key Service
%define pki_tps           %{base_entity} Token Processing System

## Don't build the debug packages
%define debug_package     %{nil}


##===================##
## Linux Definitions ##
##===================##
%ifos Linux
## 32-bit Definitions
%ifarch i386
%define architecture      intel
%define configure_cmd     ../configure
%endif

## 64-bit Definitions
%ifarch x86_64
%define architecture      intel
%define configure_cmd     ../configure --enable-64bit --libdir=%{base_install_dir}/lib64
%endif

## Disallow an initial login shell
## NOTE:  SELinux policy requires a shell of /sbin/nologin
%define base_login_shell  /sbin/nologin

## For PKI version information, ALWAYS refer to the version of the
## Dogtag UI package dependency associated with this Dogtag spec file!
%define pki_version       %(echo `rpm -q --queryformat '%{VERSION}' %{base_flavor}-%{base_name}-ui`)

## A distribution model is required on certain Linux operating systems!
##
## check for a pre-defined distribution model
%define undefined_distro  %(test "%{dist}" = "" && echo 1 || echo 0)
%if %{undefined_distro}
%define is_fedora         %(test -e /etc/fedora-release && echo 1 || echo 0)
%if %{is_fedora}
## define a default distribution model on Fedora Linux
%define dist_prefix       .fc
%define dist_version      %(echo `rpm -qf --qf='%{VERSION}' /etc/fedora-release` | tr -d [A-Za-z])
%define dist              %{dist_prefix}%{dist_version}
%else
%define is_redhat         %(test -e /etc/redhat-release && echo 1 || echo 0)
%if %{is_redhat}
## define a default distribution model on Red Hat Linux
%define dist_prefix       .el
%define dist_version      %(echo `rpm -qf --qf='%{VERSION}' /etc/redhat-release` | tr -d [A-Za-z])
%define dist              %{dist_prefix}%{dist_version}
%endif
%endif
%endif
%endif



###############################################################################
###                       P A C K A G E   H E A D E R                       ###
###############################################################################

Name:           %{base_name}
Version:        %{base_version}
Release:        %{base_release}%{?dist}
Summary:        %{base_summary}
Vendor:         %{base_vendor}
URL:            %{base_url}
License:        %{base_license}
Packager:       %{base_packager}
Group:          %{base_group}


## Without AutoReqProv: no, rpmbuild finds all sorts of crazy
## dependencies that we don't care about, and refuses to install
AutoReqProv:    no

BuildRoot:      %{_builddir}/%{name}-root


## NOTE:  This spec file may require a specific JDK, "gcc", and/or "gcc-c++"
##        packages as well as the "rpm" and "rpm-build" packages.
##
##        Technically, "ant" should not need to be in "BuildRequires" since
##        it is the Java equivalent of "make" (and/or "Autotools").
##
BuildRequires:  apr-devel >= 0.9.4, apr-util-devel >= 0.9.4, %{base_flavor}-%{base_name}-ui >= 1.0.0, bash >= 3.0, cyrus-sasl-devel >= 2.1.19, httpd-devel >= 2.0.52, mozldap-devel >= 6.0.2, nspr-devel >= 4.6.99, nss-devel >= 3.12.0, pcre-devel >= 6.6, svrcore-devel >= 4.0.3.01, zlib >= 1.2.3, zlib-devel >= 1.2.3

## Without Requires something, rpmbuild will abort!
Requires:       %{base_prefix}-setup >= 1.0.0, %{base_name}-ui, mod_nss >= 1.0.7, mod_perl >= 1.99_16, mod_revocator >= 1.0.2, mozldap >= 6.0.2, perl-HTML-Parser >= 3.35, perl-HTML-Tagset >= 3.03, perl-Parse-RecDescent >= 1.94, perl-URI >= 1.30, perl-XML-NamespaceSupport >= 1.08, perl-XML-Parser >= 2.34, %{base_prefix}-selinux >= 1.0.0, perl-XML-Simple


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
%{base_pki} is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The %{pki_tps} is an optional PKI subsystem
that acts as a Registration Authority (RA) for authenticating and processing
enrollment requests, PIN reset requests, and formatting requests from the
Enterprise Security Client (ESC).

%{pki_tps} is designed to communicate with tokens that
conform to Global Platform's Open Platform Specification.

%{pki_tps} communicates over SSL with various
PKI backend subsystems (including the %{pki_ca},
the %{pki_drm}, and the %{pki_tks}) to
fulfill the user's requests.

%{pki_tps} also interacts with the token database,
an LDAP server that stores information about individual tokens.



###############################################################################
###                  P R E P A R A T I O N   &   S E T U P                  ###
###############################################################################

## On Linux systems, prep and setup expect there to be a Source file
## in the /usr/src/redhat/SOURCES directory - it will be unpacked
## in the _builddir (not BuildRoot)
%prep


%setup -q -n %{base_name}-%{base_version}


## This package currently contains no patches!
#%patch0
# patches



###############################################################################
###                        B U I L D   P R O C E S S                        ###
###############################################################################

%build
%{?pkg_config_cmd}
mkdir %{base_build_dir}
cd %{base_build_dir}
mkdir %{base_staging_dir}
%{configure_cmd}
make



###############################################################################
###                 I N S T A L L A T I O N   P R O C E S S                 ###
###############################################################################

%install
%{?pkg_config_cmd}
rm -rf ${RPM_BUILD_ROOT}
cd %{base_build_dir}
make install DESTDIR="`pwd`/%{base_staging_dir}"

## rearrange files to be in the desired native packaging layout
../%{setup_package} ${RPM_BUILD_ROOT} %{base_prefix} %{base_component} %{version} %{base_release} %{architecture} `pwd`/%{base_staging_dir}/%{base_install_dir}
sed -i 's/^preop.product.version=.*$/preop.product.version=%{pki_version}/' ${RPM_BUILD_ROOT}/usr/share/%{base_prefix}/%{base_component}/conf/CS.cfg


###############################################################################
###                      C L E A N U P   P R O C E S S                      ###
###############################################################################

%clean
rm -rf ${RPM_BUILD_ROOT}



###############################################################################
###  P R E  &  P O S T   I N S T A L L / U N I N S T A L L   S C R I P T S  ###
###############################################################################

%pre
if [ `grep -c %{base_user} /etc/group` -eq 0 ] ; then
	echo "Adding default PKI group \"%{base_user}\" to /etc/group."
	groupadd %{base_user}
fi
if [ `grep -c %{base_user} /etc/passwd` -eq 0 ] ; then
	echo "Adding default PKI user \"%{base_user}\" to /etc/passwd."
	useradd -g %{base_user} -d %{_datadir}/%{base_prefix} -s %{base_login_shell} -c "%{base_pki}" -m %{base_user}
fi


%post
chmod 00755 %{_datadir}/%{base_prefix}/%{base_component}/setup/postinstall
%{_datadir}/%{base_prefix}/%{base_component}/setup/postinstall %{base_prefix} %{base_component} %{base_version} %{base_release}
echo ""
echo "Install finished."


%preun
if [ -d %{base_instance} ] ; then
	echo "WARNING:  The default instance \"%{base_instance}\" was NOT removed!"
	echo ""
	echo "NOTE:  This means that the data in the default instance called"
	echo "       \"%{base_instance}\" will NOT be overwritten once the"
	echo "       \"%{name}\" package is re-installed."
	echo ""
	echo "Shutting down the default instance \"%{base_instance}\""
	echo "PRIOR to uninstalling the \"%{name}\" package:"
	echo ""
	/etc/init.d/%{base_name} stop
fi


## This package currently contains no post-uninstallation process!
#%postun



###############################################################################
###   I N V E N T O R Y   O F   F I L E S   A N D   D I R E C T O R I E S   ### 
###############################################################################

%files
%attr(-,root,root)     /etc/httpd/modules/*
%attr(00755,root,root) %{_bindir}/*
%attr(-,root,root)     %{_libdir}/*
%attr(-,root,root)     %{_datadir}/doc/%{base_name}-%{base_version}/*
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/alias
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/applets
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/cgi-bin
%attr(00660,root,root) %{_datadir}/%{base_prefix}/%{base_component}/conf/CS.cfg
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/conf/[a-z]*
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/docroot
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/etc
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/lib
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/logs
%attr(00770,root,root) %{_datadir}/%{base_prefix}/%{base_component}/logs/signedAudit
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/samples
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/scripts
%attr(-,root,root)     %{_datadir}/%{base_prefix}/%{base_component}/setup



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Fri May 8 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-14
- Bugzilla Bug #492735 -  Configuration wizard stores certain incorrect
  port values within TPS "CS.cfg" . . .
* Tue May 5 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-13
- Bugzilla Bug #492735 -  Configuration wizard stores certain incorrect
  port values within TPS "CS.cfg" . . .
- Bugzilla Bug #495597 -  Unable to access Agent page using a configured
  CA/KRA containing an HSM
* Fri May 1  2009 Jack Magne <jmagne@redhat.com> 1.1.0-12
- Bugzilla Bug #494983 - Can't re-enroll if policy is set to no.
* Thu Apr 30 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-11
- Bugzilla Bug #498528 -  Disable mod_revocator on RHEL since it will no
  longer work with the updated mod_nss which is required for HSMs
* Tue Apr 28 2009 Ade Lee <alee@redhat.com> 1.1.0-10
- Bugzilla Bug #493183 -   tps-audit.log file is not getting updated
* Mon Apr 27 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-9
- Bugzilla Bug #497585 -  rhcs80beta tps init script - restarting
  shows incorrect output
* Thu Apr 23 2009 Ade Lee <alee@redhat.com> 1.1.0-8
- Bugzilla Bug 497212 -  unable to enroll a tps operator/ agent/ admin using a token user
* Wed Apr 22 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-7
- Bugzilla Bug #488338 -  start/stop scripts should list all the
  available port numbers with their functionality
* Mon Apr 20 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-6
- Bugzilla Bug #496679 -  Use instance-specific paths rather than
  redirected paths in Execution Management Scripts
* Sat Apr 18 2009 Christina Fu <cfu@redhat.com> 1.1.0-5
- Bugzilla Bug #496416 - TPS smart card renewal clean-up needed
* Fri Apr 17 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-4
- Bugzilla Bug #489063 -  Smart card formatting/enrollment spits user password
  to the debug log
* Thu Apr 16 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-3
- Bugzilla Bug #493122 -  Proper invocation and use of mod_revocator
- Bugzilla Bug #495959 -  pkiremove requires "perl-XML-SAX" as a runtime
  dependency
* Fri Apr 10 2009 Ade Lee <alee@redhat.com> 1.1.0-2
- Bugzilla Bug #223353 - Values entered through web ui are not checked/escaped
* Sat Apr 4 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-1
- Version update to Dogtag 1.1.0.
* Tue Mar 31 2009 Christina Fu <cfu@redhat.com> 1.0.0-45
- Bugzilla Bug #488291 - Missing renewal feature for smart cards in TMS
* Sat Mar 28 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-44
- Bugzilla Bug #492180 -  Security officer: token recovery for a security
  officer throws error 28 'connection to server lost'.
- Bugzilla Bug #492503 -  Integrate "mod_revocator" as a runtime dependency
  for RA and TPS  
* Sat Mar 28 2009 Jack Magne <jmagne@redhat.com> 1.0.0-43
- Bugzilla #492361 - Better error message for formatting token not onwed by user.
* Wed Mar 25 2009 Jack Magne <jmagne@redhat.com> 1.0.0-42
- Bugzilla 492210 TPS Http Client fix.
* Wed Mar 25 2009 Jack Magne <jmagne@redhat.com> 1.0.0-41
- Bugzilla 491994 Key recovery into the token issue.
* Tue Mar 24 2009 Ade Lee <alee@redhat.com> 1.0.0-40
- Bugzilla 490452 support for signed audit in UI
* Fri Mar 20 2009 Ade Lee <alee@redhat.com> 1.0.0-39
- Bugzilla 489318 TPS does not list more than 20 activities
* Wed Mar 18 2009 Christina Fu <cfu@redhat.com> 1.0.0-38
- Bugzilla Bug # 485166 - Signed Audit Feature for TPS
* Thu Mar 12 2009 Jack Magne <jmagne@redhat.com> 1.0.0-37
- Bugilla Bug #48901 - Safenet 300J support key changeover.
* Wed Mar 11 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-36
- Bugzilla Bug #488338 -  start/stop scripts should list all the
  available port numbers with their functionality
- Bugzilla Bug #440164 -  Dogtag subsystems should show up in
  Fedora8 administrator Services window
* Wed Mar 11 2009 Ade Lee <alee@redhat.com> 1.0.0-35
  Bugzilla Bug #489712 RA and TPS need perl-XML-Simple as prereq
* Tue Mar 10 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-34
- Bugzilla Bug #440350 -  Removed use of "rhgb-console" from "httpd"
* Fri Mar 6 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-33
- Bugzilla Bug #440350 -  Dogtag stop/start scripts should be chkconfig aware
* Fri Mar 6 2009 Ade Lee <alee@redhat.com> 1.0.0-32
- Bugzilla Bug 472308 - web installer display wrong product version in first Welcome panel
* Wed Mar 4 2009 Ade Lee <alee@redhat.com> 1.0.0-31
- Bugzilla Bug 487871, 488561 - pkiremove cleanup and remove all selinux ports
* Wed Mar 4 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-30
- Bugzilla Bug #440344 -  Installation page should tell admins to use
  "service", not "/etc/init.d" on Linux
* Fri Feb 27 2009 Jack Magne <jmagne@redhat.com> 1.0.0-29
- Bugzilla #485829 - Support for 2048 bit safenet keys.
* Fri Feb 27 2009 Ade Lee <alee@redhat.com> 1.0.0-28
- Bugzilla 224835 and 367171: Allow cert nicknames to be edited and sizepanel fixes
* Thu Feb 26 2009 Ade Lee <alee@redhat.com> 1.0.0-27
- Bugzilla Bug 484275 and 483304: TPS roles defined and correcting error templates
* Thu Feb 26 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-26
- Bugzilla Bug #458337 -  Provide separate listening ports for CS
* Wed Feb 25 2009 Jack Magne <jmagne@redhat.com> 1.0.0-25
- Bugzillw Bug #445274 - Make esc security officer mode work.
* Tue Feb 24 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-24
- Bugzilla Bug #485859 -  port separation for RA and TPS
* Mon Feb 23 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-23
- Bugzilla Bug #486435 -  clicking on configuration URL results in error
* Tue Feb 17 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-22
- Bugzilla Bug #485790 -  Need changes made to spec files in various packages
  to be able to build in koji/brew
* Sat Feb 14 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-21
- Bugzilla Bug #250874 -Change spec file dependencies to rely on latest
  versions of components (NSPR, NSS, JSS, MOD_NSS)
* Wed Feb 11 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-20
- Bugzilla Bug #467155 - Change "renameTo" to "cp -p "
* Wed Feb 11 2009 Ade Lee <alee@redhat.com> 1.0.0-19
- Bugzilla # 484826 -selinux policy required for TPS and RA subsystems  
* Fri Feb 6 2009 Christina Fu <cfu@redhat.com> 1.0.0-18
- Bugzilla# 484420 - TPS public key challenge proof verification error
* Thu Feb 5 2009 Ade Lee <alee@redhat.com> 1.0.0-17
- Bugzilla Bugs: 484268, 224889, 431158, 481670, 483303, 484077 
* Tue Jan 27 2009 Ade Lee <alee@redhat.com> 1.0.0-16
- Bugzilla Bug 479092 - TPS roles enhancements
* Tue Jan 27 2009 Ade Lee <alee@redhat.com> 1.0.0-15
- Bugzilla Bug 480679 - Integrate selinux into framework
* Thu Jan 23 2009 Jack Magne <jmagne@redhat.com> 1.0.0-14
- Bugzilla Bug #459539 - Support safenet 330J token.
* Thu Jan 22 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-13
- Bugzilla Bug #480952 - moved "perl-XML-Simple" and "perl-libwww-perl"
  runtime dependencies to pki-setup
* Wed Dec 10 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-12
- Bugzilla Bug #475895 - Parameterize the initial login shell
* Mon Dec 8 2008 Ade Lee <alee@edhat.com> 1.0.0-11
- Bugzilla Bug #453508 - Changes to acvcomodate new NSS, apache changes
* Fri Dec 5 2008 Christina Fu <cfu@redhat.com> 1.0.0-10
- Buzilla Bug 474659 - moved public key challenge generation from TPS to TKS
    - fix for missed bytes in preEncryptedData
* Fri Dec 5 2008 Christina Fu <cfu@redhat.com> 1.0.0-9
- Buzilla Bug 474659 - moved public key challenge generation from TPS to TKS
* Thu Dec 4 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-8
- Bugzilla Bug #474369 - Remove NSS dependency on "pkcs11-devel" and
                         upgrade NSS/NSPR version dependencies  
* Fri Nov 28 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-7
- Bugzilla Bug #445402 - changed "linux"/"fedora" to "dogtag"; changed
                         "pki-svn.fedora.redhat.com" to "pki.fedoraproject.org"
* Sun Nov 23 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-6
- Bugzilla Bug #446662 - /usr/share/fpki/ra/conf path referred
                         to in CS.cfg doesn't exist
* Sat Nov 22 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-5
- Bugzilla Bug #450345 - Port Dogtag 1.0.0 to Fedora 9
  (32-bit i386 & 64-bit x86_64)
- Bugzilla Bug #453504 - RA perl scripts won't compile on Fedora 9
* Sat Nov 22 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-4
- Bugzilla Bug #472305 - "equality" tests in all spec files need to be fixed
- Bumped "java" and "java-devel" 1.4.2 and 1.5.0 dependencies to 1.6.0
- Changed "java-sdk" to "java-devel" for consistency
* Tue Aug 5 2008 Ade Lee <alee@redhat.com> 1.0.0-3
- Fix for bug#454565 - Broken Installation Wizard for TPS and RA with latest modutil.
* Tue Apr 1 2008 Jack Magne <jmagne@redhat.com> 1.0.0-2
- Fix for bug#440084 - Subsystem Installation Error Message Needs Improvement.
* Tue Feb 19 2008 PKI Team <pki-devel@redhat.com> 1.0.0-1
- Initial open source version based upon proprietary
  Red Hat Certificate System (RHCS) 7.3.

