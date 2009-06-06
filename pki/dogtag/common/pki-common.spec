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
%define base_product      PKI Common Framework
%define base_component    common
%define base_pki          %{base_entity} %{base_system}

## Package Header Definitions
%define base_name         %{base_prefix}-%{base_component}
%define base_version      1.1.0
%define base_release      27
%define base_group        System Environment/Base
%define base_vendor       Red Hat, Inc.
%define base_license      GPLv2 with exceptions
%define base_packager     %{base_vendor} <http://bugzilla.redhat.com/bugzilla>
%define base_summary      %{base_pki} - %{base_product}
%define base_url          http://pki.fedoraproject.org/wiki/PKI_Documentation

## Subpackage Header Definitions
%define javadoc_summary   %{base_summary} Javadocs
%define javadoc_group     Development/Documentation

## Helper Definitions
%define pki_jdk           java-devel >= 1:1.6.0
%define pki_jre           java >= 1:1.6.0
# Override the default 'pki_jdk' and 'pki_jre' on Fedora 8 platforms
%{?fc8:%define pki_jdk    java-devel >= 1.7.0}
%{?fc8:%define pki_jre    java >= 1.7.0}
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

BuildArch:      noarch
BuildRoot:      %{_builddir}/%{base_name}-root


## NOTE:  This spec file may require a specific JDK, "gcc", and/or "gcc-c++"
##        packages as well as the "rpm" and "rpm-build" packages.
##
##        Technically, "ant" should not need to be in "BuildRequires" since
##        it is the Java equivalent of "make" (and/or "Autotools").
##
BuildRequires:  ant >= 1.6.2, %{base_prefix}-util >= 1.0.0, %{base_flavor}-%{base_name}-ui >= 1.0.0, %{pki_jdk}, jpackage-utils >= 1.6.0, jss >= 4.2.6, ldapjdk >= 4.17, osutil >= 1.0.0, symkey >= 1.0.0, velocity >= 1.4, xalan-j2, xerces-j2

## Without Requires something, rpmbuild will abort!
Requires:       %{base_name}-ui, %{base_prefix}-java-tools >= 1.0.0, %{base_prefix}-setup >= 1.0.0, %{pki_jre}, osutil >= 1.0.0, rhgb >= 0.14.1, symkey >= 1.0.0, tomcatjss >= 1.1.0, velocity >= 1.4


## This package conflicts with the following packages!
Conflicts:      tomcat-native


## This package is non-relocatable!
#Prefix:

Source0:        %{base_name}-%{base_version}.tar.gz

## This package currently contains no patches!
#Patch0:


%description
%{base_pki} is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The %{base_entity} %{base_product} is required by the following four
%{base_entity} PKI subsystems:

    the %{pki_ca},
    the %{pki_drm},
    the %{pki_ocsp}, and
    the %{pki_tks}.



###############################################################################
###                    S U B P A C K A G E   H E A D E R                    ###
###############################################################################

%package javadoc
Summary:    %{javadoc_summary}
Group:      %{javadoc_group}


## Subpackages should always use package = version-release
Requires:   %{base_name} = %{version}-%{release}


%description javadoc
%{javadoc_summary}

This documentation pertains exclusively to version %{version} of
the %{base_entity} %{base_product}.



###############################################################################
###                  P R E P A R A T I O N   &   S E T U P                  ###
###############################################################################

## On Linux systems, prep and setup expect there to be a Source file
## in the /usr/src/redhat/SOURCES directory - it will be unpacked
## in the _builddir (not BuildRoot)
%prep


%setup -q


## This package currently contains no patches!
#%patch0
# patches



###############################################################################
###                        B U I L D   P R O C E S S                        ###
###############################################################################

%build
ant -Dspecfile=%{base_name}.spec



###############################################################################
###                 I N S T A L L A T I O N   P R O C E S S                 ###
###############################################################################

%install
cd dist/binary
unzip %{name}-%{version}.zip -d ${RPM_BUILD_ROOT}
cd ${RPM_BUILD_ROOT}/usr/share/java/%{base_prefix}
mv certsrv.jar certsrv-%{version}.jar
ln -s certsrv-%{version}.jar certsrv.jar
mv cms.jar cms-%{version}.jar
ln -s cms-%{version}.jar cms.jar
mv cmsbundle.jar cmsbundle-%{version}.jar
ln -s cmsbundle-%{version}.jar cmsbundle.jar
mv cmscore.jar cmscore-%{version}.jar
ln -s cmscore-%{version}.jar cmscore.jar
mkdir -p ${RPM_BUILD_ROOT}/var/lib/tomcat5/common/lib
cd ${RPM_BUILD_ROOT}/var/lib/tomcat5/common/lib
ln -s /usr/share/java/ldapjdk.jar ldapjdk.jar
ln -s /usr/share/java/velocity.jar velocity.jar
ln -s /usr/share/java/xalan-j2.jar xalan-j2.jar
ln -s /usr/share/java/xerces-j2.jar xerces-j2.jar
ln -s /usr/share/java/%{base_prefix}/cmsutil.jar cmsutil.jar
ln -s /usr/share/java/%{base_prefix}/nsutil.jar nsutil.jar



###############################################################################
###                      C L E A N U P   P R O C E S S                      ###
###############################################################################

%clean
rm -rf ${RPM_BUILD_ROOT}



###############################################################################
###  P R E  &  P O S T   I N S T A L L / U N I N S T A L L   S C R I P T S  ###
###############################################################################

## This package currently contains no pre-installation process!
#%pre


%post
chmod 00755 %{_datadir}/%{base_prefix}/setup/postinstall
%{_datadir}/%{base_prefix}/setup/postinstall %{base_prefix}


## This package currently contains no pre-uninstallation process!
#%preun


## This package currently contains no post-uninstallation process!
#%postun



###############################################################################
###   I N V E N T O R Y   O F   F I L E S   A N D   D I R E C T O R I E S   ### 
###############################################################################

%files
%attr(-,root,root)     %{_datadir}/doc/%{base_name}-%{base_version}/*
%attr(-,root,root)     %{_datadir}/java/%{base_prefix}
%attr(-,root,root)     %{_datadir}/%{base_prefix}/*
%attr(-,root,root)     %{_var}/lib/tomcat5/common/lib/*


%files javadoc
%defattr(0644,root,root,0755)
%dir %{_javadocdir}/%{name}-%{version}
%{_javadocdir}/%{name}-%{version}/*



###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Fri Jun 5 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-27
- Bugzilla Bug #471318 - adding triple DES and SHA1, SHA256, SHA512
* Fri Jun 5 2009 Jack Magne <jmagne@redhat.com> 1.1.0-26
- Bugzilla Bug #498123 - Unable to format a token with tks clone.
* Thu Jun 4 2009 Christina Fu <cfu@redhat.com> 1.1.0-25
- Bugzilla Bug#502861 - "Signed CMC-Authenticated User Certificate Enrollment" fails with Authorization
* Wed Jun 3 2009 Christina Fu <cfu@redhat.com> 1.1.0-24
- Bugzilla Bug #455305 - CA ECC signing Key Failure
  Bugzilla Bug #223279 - ECC: Ca: unable to perform agent auth on a machine with
 nCipher ECC HSM
* Tue Jun 2 2009 Christina Fu <cfu@redhat.com> 1.1.0-23
- Buzilla Bug # 500738 - (nethsm2k): KRA/TKS : Installation wizard fails
* Sat May 30 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-22
- Bugzilla Bug #482935 - Adding search limits
* Sat May 30 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-21
- Bugzilla Bug #503289 - Improvement of default signing algorithm selection
* Fri May 29 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-20
- Bugzilla Bug #500733 -  Subordinate CA - administrator certificate import
  fails (install wizard)
* Fri May 29 2009 Ade Lee <alee@redhat.com> 1.1.0-19
- Bugzilla Bug #480714 and #481659 - renewal fixes for expired_revoked certs and prevent key archival for renewals
* Thu May 28 2009 Ade Lee <alee@redhat.com> 1.1.0-18
- Bugzilla Bug #502257 - KRA cloning: during configuration throws "Clone is not ready" error message
* Fri May 22 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-17
- Bugzilla Bug #488303
* Wed May 20 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-16
- Bugzilla Bug #491185 - added new revocation reasons to comply with RFC 5280
* Tue May 19 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-15
- Bugzilla Bug #491185 - added Authority Info Access extension to comply with RFC 5280
* Mon May 18 2009 Ade Lee <alee@redhat.com> 1.1.0-14
- Bugzilla Bug #500736 -  \n characters are being incorrectly escaped on profile review form
* Wed May 13 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-13
- Bugzilla Bug #500498 -  CA installation wizard doesn't install
  administrator cert into browser on Firefox 3
* Sun May 10 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-12
- Bugzilla Bug #490551 - Use profile key constraints to control enrollment key sizes
* Fri May 8 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-11
- Bugzilla Bug #492735 -  Configuration wizard stores certain incorrect
  port values within TPS "CS.cfg" . . .
* Tue May 5 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-10
- Bugzilla Bug #492735 -  Configuration wizard stores certain incorrect
  port values within TPS "CS.cfg" . . .
- Bugzilla Bug #495597 -  Unable to access Agent page using a configured
  CA/KRA containing an HSM
* Fri May 1 2009 Ade Lee <alee@redhat.com> 1.1.0-9
- Bugzilla Bug #454032 - clone ca with ssl slapd has incorrect mmr agreements from configuration wizard
* Tue Apr 28 2009 Ade Lee <alee@redhat.com> 1.1.0-8
- Bugzilla Bug #496334 -  Renewal: Missing information in the first 6 requests in the CA request queue.
* Sat Apr 18 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-7
- Bugzilla Bug #496409 -  Display missing "Security Domain" information on
  Security Domain Login Panel
* Fri Apr 17 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-6
- Bugzilla Bug #443120 - administrator cannot remove imported CA certificate
* Tue Apr 14 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-5
- Bugzilla Bug #490224 - Monitor regression
* Mon Apr 13 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-4
- Bugzilla Bug #476318 - CA console throws Java exceptions when editing user supplied extension defaults
* Fri Apr 10 2009 Ade Lee <alee@redhat.com> 1.1.0-3
- Bugzilla Bug #223353 - Values entered through web ui are not checked/escaped
* Tue Apr 7 2009 Andrew Wnuk <awnuk@redhat.com> 1.1.0-2
- Bugzilla Bug #493758 - policy editor corrupts profile
* Sat Apr 4 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-1
- Version update to Dogtag 1.1.0.
* Tue Mar 31 2009 Ade Lee <alee@redhat.com> 1.0.0-60
- Bugzilla Bug: 481659 - Renewal: Manual user signing and encryption certificate after renewal responds with two request ids.
* Mon Mar 30 2009 Ade Lee <alee@redhat.com> 1.0.0-59
- Bugzilla Bug: 472916 - Renewal: certs created during post-installation can not be renewed via profile framework
* Mon Mar 30 2009 Ade Lee <alee@redhat.com> 1.0.0-58
- Bugzilla Bug 475566 - cannot tell renewals from enrollment requests
* Thu Mar 26 2009 Andrew Wnuk <awnuk@redhat.com> 1.0.0-57
- Bugzilla Bug: 445052 - HTTP 1.1 support when fetching CRLs - adding compression
* Tue Mar 24 2009 Andrew Wnuk <awnuk@redhat.com> 1.0.0-56
- Bugzilla Bug: 478909 - possible connection leaks to CA internal DB
* Fri Mar 20 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-55
- Bugzilla Bug #490489 -  Configuration modifications are not replicated
  between admins, agents, and end entities
- Bugzilla Bug #490483 -  Unable to configure CA using "Shared Ports"
* Fri Mar 20 2009 Christina Fu <cfu@redhat.com> 1.0.0-54
- Bugzilla Bug #472916 - Renewal: certs created during post-installation can not be renewed via profile framework.  PHASE 1 ONLY.
* Tue Mar 17 2009 Andrew Wnuk <awnuk@redhat.com> 1.0.0-53
- Bugzilla Bug #490461 - Certificate file based publishing fails
* Wed Mar 11 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-52
- Bugzilla Bug #488338 -  start/stop scripts should list all the
  available port numbers with their functionality
- Bugzilla Bug #440164 -  Dogtag subsystems should show up in
  Fedora8 administrator Services window
* Tue Mar 10 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-51
- Bugzilla Bug #489404 -  fixed non-secure port
* Fri Mar 6 2009 Andrew Wnuk <awnuk@redhat.com> 1.0.0-50
- Bugzilla Bug #334253 - Revoked certs must appear on one CRL after expiration
* Wed Mar 4 2009 Ade Lee <alee@redhat.com> 1.0.0-49
- Bugzilla Bug 487871, 488561 - pkiremove cleanup and remove all selinux ports
* Wed Mar 4 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-48
- Bugzilla Bug #440344 -  Installation page should tell admins to use
  "service", not "/etc/init.d" on Linux
* Tue Mar 3 2009 Ade Lee <alee@redhat.com> 1.0.0-47
- Bugzilla Bug #487739 -  Unable to setup cloning
* Fri Feb 27 2009 Ade Lee <alee@redhat.com> 1.0.0-46
- Bugzilla 224835 and 367171: Allow cert nicknames to be edited and sizepanel fixes
* Thu Feb 26 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-45
- Bugzilla Bug #458337 -  Provide separate listening ports for CS
* Wed Feb 25 2009 Christina Fu <cfu@redhat.com> 1.0.0-44
- Bugzilla Bugs: 487592 - nsTokenUserKeySubjectNameDefault does not fill in
  attributes retrieved from ldap
  481790 - SubjectAltNameExtDefault: Handling Of Non-UUID OtherName Is Broken
* Wed Feb 25 2009 Andrew Wnuk <awnuk@redhat.com> 1.0.0-43
- Bugzilla Bug: 480804 - to save general settings
* Tue Feb 24 2009 Andrew Wnuk <awnuk@redhat.com> 1.0.0-42
- Bugzilla Bug: 449857 - publishing enhancement
* Sat Feb 14 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-41
- Bugzilla Bug #250874 -Change spec file dependencies to rely on latest
  versions of components (NSPR, NSS, JSS, MOD_NSS)
* Fri Feb 13 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-40
- Bugzilla Bug #485522 -  Need rpm spec file to require xerces-j2
- required to build javadocs
* Thu Feb 12 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-39
- Bugzilla Bug #483699 -  problem with the epoch in the spec file causes
  build to fail
* Wed Feb 11 2009 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-38
- Bugzilla Bug #467155 - Change "renameTo" to "cp -p "
- cleaned up some javadoc warnings
* Wed Feb 11 2009 Ade Lee <alee@redhat.com> 1.0.0-37
- Bugzilla Bug: 443417 - requestor email does not make it to mail 
* Mon Feb 2 2009 Ade Lee <alee@redhat.com> 1.0.0-36
- Bugzilla Bug: 482761 - additional changes to get cloning working
* Fri Jan 30 2009 Ade Lee <alee@redhat.com> 1.0.0-35
- Bugzilla Bug #460582 - add UTF-8 support
* Wed Jan 28 2009 Christina Fu <cfu@redhat.com> 1.0.0-34
- Bugzilla Bug #482733 - make outputXML available via profiles; add request id i
n response for deferred
* Tue Jan 27 2009 Ade Lee <alee@redhat.com> 1.0.0-33
- Bugzilla Bugs: 482738 and 482761
* Mon Jan 26 2009 Andrew Wnuk <awnuk@redhat.com> 1.0.0-32
- Bugzilla Bugs: 480825, 481177, and 481688
* Thu Jan 22 2009 Christina Fu <cfu@redhat.com> 1.0.0-31
- Bugzilla Bug 481237 - Audit Log signing framework
* Mon Jan 5 2009 Ade Lee <alee@redhat.com> 1.0.0-30
- Bugzilla Bug 472006, 472007 - serial number management
* Fri Dec 5 2008 Christina Fu <cfu@redhat.com> 1.0.0-29
- Buzilla Bug 474659 - moved public key challenge generation from TPS to TKS
* Fri Nov 28 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-28
- Bugzilla Bug #445402 - changed "linux"/"fedora" to "dogtag"; changed
                         "pki-svn.fedora.redhat.com" to "pki.fedoraproject.org"
* Sat Nov 22 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-27
- Bugzilla Bug #472305 - "equality" tests in all spec files need to be fixed
- Bumped "java" and "java-devel" 1.4.2 and 1.5.0 dependencies to 1.6.0
- Changed "java-sdk" to "java-devel" for consistency
* Tue Nov 18 2008 Christina Fu <cfu@redhat.com> 1.0.0-26
- Bugzilla Bug #471622 - Need Renewal feature via enrollment profile Framework (Phase 1)
* Mon Oct 27 2008 Ade Lee <alee@redhat.com> 1.0.0-25
- Fix for Bugs: 223324, 430745, 224765, 223309
* Fri Oct 17 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-24
- Fix for Bug 335111: pkiconsole exception on wrong uniqueMember syntax
* Wed Oct 15 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-23
- Fix for Bug 466064: Search filters built by CA servlets are not always correct
* Fri Oct 10 2008 Ade Lee <alee@redhat.com> 1.0.0-22
- Fix for Bug 223361. Security Domains in LDAP.
* Thu Oct 9 2008 Ade Lee <alee@redhat.com> 1.0.0-21
- Fix for bug 462035 (pkisilent).
* Thu Oct 9 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-20
- Fix for Bug 465997: getBySerial servlet causing Java exception.
* Wed Sep 24 2008 Ade Lee <alee@redhat.com> 1.0.0-19
- Fix for bug 223367 and 224902.
* Tue Sep 16 2008 Christina Fu <cfu@redhat.com> 1.0.0-18
- Fix for bug #462488: IPAddress in SubjAltNameExt incorrectly padded with extra bytes in cert
* Wed Aug 13 2008 Ade Lee     <alee@redhat.com> 1.0.0-17
- Fix for Bug 458499: UniqueSubjectName plugin for plugins does not account for revoked certs
* Fri Aug 8 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-16
- Fix for Bug 453834.
* Thu Aug 7 2008 Jack Magne  <jmagne@redhat.com> 1.0.0-15
- Fix for Bug #458337.
* Thu Aug 7 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-14
- Fix for Bug 453834.
* Mon Jul 21 2008 Ade Lee <alee@redhat.com> 1.0.0-13
- Fix for Bug 455331.
* Fri Jul 11 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-12
- Fix for bug #243804.
* Wed Jul 9 2008 Christina Fu <cfu@redhat.com> 1.0.0-11
- Fix for Bugzilla Bug #446685: LDAP publisher doesn't store the bind password properly
* Tue Jul 8 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-10
- Fix for Bugzilla Bug #454559:  OCSP returns a nullpointer exception
  if the request is not provided as a parameter in the GET operation
* Wed Jun 25 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-9
- Fix for bug #443687.
* Fri May 16 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-8
- Fix for bug #445470.
* Tue May 7 2008 Jack Magne <jmagne@redhat.com> 1.0.0-7
- Fix for Bug#440079.
* Tue May 6 2008 Andrew Wnuk <awnuk@redhat.com> 1.0.0-6
- Provided CRL page size as configurable parameter - bug #445400. 
- Fixed typo - bugzilla bug #304668
* Fri Apr 18 2008 Matthew Harmsen <mharmsen@redhat.com> 1.0.0-5
- Fixed bug #441974 - Added "Conflicts: tomcat-native" statement to spec file.
* Thu Apr 17 2008 Christina Fu <cfu@redhat.com> 1.0.0-4
- Implemented bug #442800 - support UUID in Subject Alternative Name extension.  Version 4 only, for now.
* Fri Apr 4 2008 Christina Fu <cfu@redhat.com> 1.0.0-3
- Fixed bug #440989 - [SECURITY] CMC authorization check not done by default
* Fri Apr 4 2008 Christina Fu <cfu@redhat.com> 1.0.0-2
- Fixed bug #439052 - CMC CRMF requests cause exception in logging: Unmatched braces in the pattern
* Tue Feb 19 2008 PKI Team <pki-devel@redhat.com> 1.0.0-1
- Initial open source version based upon proprietary
  Red Hat Certificate System (RHCS) 7.3.

