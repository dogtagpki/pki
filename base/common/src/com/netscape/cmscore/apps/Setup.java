// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.apps;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

/**
 * Select certificate server serices.
 *
 * @author thomask
 * @author nicolson
 * @version $Revision$, $Date$
 */
public class Setup {

    // These are a bunch of fixed values that just need to be stored to the
    // config file before the server is started.
    public static final String[][] authEntries = new String[][] {
            { "auths._000", "##" },
            { "auths._001", "## new authentication" },
            { "auths._002", "##" },
            { "auths.impl._000", "##" },
            { "auths.impl._001", "## authentication manager implementations" },
            { "auths.impl._002", "##" },
            { "auths.impl.UidPwdDirAuth.class", "com.netscape.cms.authentication.UidPwdDirAuthentication" },
            { "auths.impl.UidPwdPinDirAuth.class", "com.netscape.cms.authentication.UidPwdPinDirAuthentication" },
            { "auths.impl.UdnPwdDirAuth.class", "com.netscape.cms.authentication.UdnPwdDirAuthentication" },
            { "auths.impl.NISAuth.class", "com.netscape.cms.authentication.NISAuth" },
            { "auths.impl.CMCAuth.class", "com.netscape.cms.authentication.CMCAuth" },
            { "auths.impl.AgentCertAuth.class", "com.netscape.cms.authentication.AgentCertAuthentication" },
            { "auths.impl.PortalEnroll.class", "com.netscape.cms.authentication.PortalEnroll"
            },
            { "auths.revocationChecking.bufferSize", "50" },
    };

    public static void installAuthImpls(IConfigStore c)
            throws EBaseException {
        for (int i = 0; i < authEntries.length; i++) {
            c.putString(authEntries[i][0], authEntries[i][1]);
        }
    }

    public static final String[][] oidmapEntries = new String[][] {
            { "oidmap.pse.class", "netscape.security.extensions.PresenceServerExtension" },
            { "oidmap.pse.oid", "2.16.840.1.113730.1.18" },
            { "oidmap.ocsp_no_check.class", "netscape.security.extensions.OCSPNoCheckExtension" },
            { "oidmap.ocsp_no_check.oid", "1.3.6.1.5.5.7.48.1.5" },
            { "oidmap.netscape_comment.class", "netscape.security.x509.NSCCommentExtension" },
            { "oidmap.netscape_comment.oid", "2.16.840.1.113730.1.13" },
            { "oidmap.extended_key_usage.class", "netscape.security.extensions.ExtendedKeyUsageExtension" },
            { "oidmap.extended_key_usage.oid", "2.5.29.37" },
            { "oidmap.subject_info_access.class", "netscape.security.extensions.SubjectInfoAccessExtension" },
            { "oidmap.subject_info_access.oid", "1.3.6.1.5.5.7.1.11" },
            { "oidmap.auth_info_access.class", "netscape.security.extensions.AuthInfoAccessExtension" },
            { "oidmap.auth_info_access.oid", "1.3.6.1.5.5.7.1.1" },
            { "oidmap.challenge_password.class", "com.netscape.cms.servlet.cert.scep.ChallengePassword" },
            { "oidmap.challenge_password.oid", "1.2.840.113549.1.9.7" },
            { "oidmap.extensions_requested_vsgn.class", "com.netscape.cms.servlet.cert.scep.ExtensionsRequested" },
            { "oidmap.extensions_requested_vsgn.oid", "2.16.840.1.113733.1.9.8" },
            { "oidmap.extensions_requested_pkcs9.class", "com.netscape.cms.servlet.cert.scep.ExtensionsRequested" },
            { "oidmap.extensions_requested_pkcs9.oid", "1.2.840.113549.1.9.14" },
        };

    public static void installOIDMap(IConfigStore c)
            throws EBaseException {
        for (int i = 0; i < oidmapEntries.length; i++) {
            c.putString(oidmapEntries[i][0], oidmapEntries[i][1]);
        }
    }

    /**
     * This function is used for installation and upgrade.
     */
    public static void installPolicyImpls(String prefix, IConfigStore c)
            throws EBaseException {
        boolean isCA = false;

        if (prefix.equals("ca"))
            isCA = true;

        //
        // Policy implementations (class names)
        //
        c.putString(prefix + ".Policy.impl._000", "##");
        c.putString(prefix + ".Policy.impl._001",
                "## Policy Implementations");
        c.putString(prefix + ".Policy.impl._002", "##");
        c.putString(
                prefix + ".Policy.impl.KeyAlgorithmConstraints.class",
                "com.netscape.cmscore.policy.KeyAlgorithmConstraints");
        c.putString(
                prefix + ".Policy.impl.DSAKeyConstraints.class",
                "com.netscape.cmscore.policy.DSAKeyConstraints");
        c.putString(
                prefix + ".Policy.impl.RSAKeyConstraints.class",
                "com.netscape.cmscore.policy.RSAKeyConstraints");
        c.putString(
                prefix + ".Policy.impl.SigningAlgorithmConstraints.class",
                "com.netscape.cmscore.policy.SigningAlgorithmConstraints");
        c.putString(
                prefix + ".Policy.impl.ValidityConstraints.class",
                "com.netscape.cmscore.policy.ValidityConstraints");

        /**
         * c.putString(
         * prefix + ".Policy.impl.NameConstraints.class",
         * "com.netscape.cmscore.policy.NameConstraints");
         **/
        c.putString(
                prefix + ".Policy.impl.RenewalConstraints.class",
                "com.netscape.cmscore.policy.RenewalConstraints");
        c.putString(
                prefix + ".Policy.impl.RenewalValidityConstraints.class",
                "com.netscape.cmscore.policy.RenewalValidityConstraints");
        c.putString(
                prefix + ".Policy.impl.RevocationConstraints.class",
                "com.netscape.cmscore.policy.RevocationConstraints");
        //getTempCMSConfig().putString(
        //        prefix + ".Policy.impl.DefaultRevocation.class",
        //        "com.netscape.cmscore.policy.DefaultRevocation");
        c.putString(
                prefix + ".Policy.impl.NSCertTypeExt.class",
                "com.netscape.cmscore.policy.NSCertTypeExt");
        c.putString(
                prefix + ".Policy.impl.KeyUsageExt.class",
                "com.netscape.cmscore.policy.KeyUsageExt");
        c.putString(
                prefix + ".Policy.impl.SubjectKeyIdentifierExt.class",
                "com.netscape.cmscore.policy.SubjectKeyIdentifierExt");
        c.putString(
                prefix + ".Policy.impl.CertificatePoliciesExt.class",
                "com.netscape.cmscore.policy.CertificatePoliciesExt");
        c.putString(
                prefix + ".Policy.impl.NSCCommentExt.class",
                "com.netscape.cmscore.policy.NSCCommentExt");
        c.putString(
                prefix + ".Policy.impl.IssuerAltNameExt.class",
                "com.netscape.cmscore.policy.IssuerAltNameExt");
        c.putString(
                prefix + ".Policy.impl.PrivateKeyUsagePeriodExt.class",
                "com.netscape.cmscore.policy.PrivateKeyUsagePeriodExt");
        c.putString(
                prefix + ".Policy.impl.AttributePresentConstraints.class",
                "com.netscape.cmscore.policy.AttributePresentConstraints");
        c.putString(
                prefix + ".Policy.impl.SubjectAltNameExt.class",
                "com.netscape.cmscore.policy.SubjectAltNameExt");
        c.putString(
                prefix + ".Policy.impl.SubjectDirectoryAttributesExt.class",
                "com.netscape.cmscore.policy.SubjectDirectoryAttributesExt");
        c.putString(
                prefix + ".Policy.impl.CertificateRenewalWindowExt.class",
                "com.netscape.cmscore.policy.CertificateRenewalWindowExt");
        c.putString(
                prefix + ".Policy.impl.CertificateScopeOfUseExt.class",
                "com.netscape.cmscore.policy.CertificateScopeOfUseExt");
        if (isCA) {
            c.putString(
                    prefix + ".Policy.impl.AuthorityKeyIdentifierExt.class",
                    "com.netscape.cmscore.policy.AuthorityKeyIdentifierExt");
            c.putString(
                    prefix + ".Policy.impl.BasicConstraintsExt.class",
                    "com.netscape.cmscore.policy.BasicConstraintsExt");
            c.putString(
                    prefix + ".Policy.impl.SubCANameConstraints.class",
                    "com.netscape.cmscore.policy.SubCANameConstraints");
        }
        c.putString(
                prefix + ".Policy.impl.CRLDistributionPointsExt.class",
                "com.netscape.cmscore.policy.CRLDistributionPointsExt");
        c.putString(
                prefix + ".Policy.impl.AuthInfoAccessExt.class",
                "com.netscape.cmscore.policy.AuthInfoAccessExt");
        c.putString(
                prefix + ".Policy.impl.OCSPNoCheckExt.class",
                "com.netscape.cmscore.policy.OCSPNoCheckExt");
        c.putString(
                prefix + ".Policy.impl.ExtendedKeyUsageExt.class",
                "com.netscape.cmscore.policy.ExtendedKeyUsageExt");
        if (isCA) {
            c.putString(
                    prefix + ".Policy.impl.UniqueSubjectNameConstraints.class",
                    "com.netscape.cmscore.policy.UniqueSubjectNameConstraints");
        }
        c.putString(
                prefix + ".Policy.impl.GenericASN1Ext.class",
                "com.netscape.cmscore.policy.GenericASN1Ext");
        c.putString(
                prefix + ".Policy.impl.RemoveBasicConstraintsExt.class",
                "com.netscape.cmscore.policy.RemoveBasicConstraintsExt");
    }

    /**
     * This function is used for installation and upgrade.
     */
    public static void installCACRLExtensions(IConfigStore c)
            throws EBaseException {
        // ca crl extensions

        // AuthorityKeyIdentifier
        c.putString("ca.crl.MasterCRL.extension.AuthorityKeyIdentifier.enable",
                "false");
        c.putString("ca.crl.MasterCRL.extension.AuthorityKeyIdentifier.critical",
                "false");
        c.putString("ca.crl.MasterCRL.extension.AuthorityKeyIdentifier.type",
                "CRLExtension");
        c.putString("ca.crl.MasterCRL.extension.AuthorityKeyIdentifier.class",
                "com.netscape.cms.crl.CMSAuthorityKeyIdentifierExtension");

        // IssuerAlternativeName
        c.putString("ca.crl.MasterCRL.extension.IssuerAlternativeName.enable",
                "false");
        c.putString("ca.crl.MasterCRL.extension.IssuerAlternativeName.critical",
                "false");
        c.putString("ca.crl.MasterCRL.extension.IssuerAlternativeName.type",
                "CRLExtension");
        c.putString("ca.crl.MasterCRL.extension.IssuerAlternativeName.class",
                "com.netscape.cms.crl.CMSIssuerAlternativeNameExtension");
        c.putString("ca.crl.MasterCRL.extension.IssuerAlternativeName.numNames", "0");
        c.putString("ca.crl.MasterCRL.extension.IssuerAlternativeName.nameType0", "");
        c.putString("ca.crl.MasterCRL.extension.IssuerAlternativeName.name0", "");

        // CRLNumber
        c.putString("ca.crl.MasterCRL.extension.CRLNumber.enable", "true");
        c.putString("ca.crl.MasterCRL.extension.CRLNumber.critical", "false");
        c.putString("ca.crl.MasterCRL.extension.CRLNumber.type", "CRLExtension");
        c.putString("ca.crl.MasterCRL.extension.CRLNumber.class",
                "com.netscape.cms.crl.CMSCRLNumberExtension");

        // DeltaCRLIndicator
        c.putString("ca.crl.MasterCRL.extension.DeltaCRLIndicator.enable", "false");
        c.putString("ca.crl.MasterCRL.extension.DeltaCRLIndicator.critical", "true");
        c.putString("ca.crl.MasterCRL.extension.DeltaCRLIndicator.type", "CRLExtension");
        c.putString("ca.crl.MasterCRL.extension.DeltaCRLIndicator.class",
                "com.netscape.cms.crl.CMSDeltaCRLIndicatorExtension");

        // IssuingDistributionPoint
        c.putString("ca.crl.MasterCRL.extension.IssuingDistributionPoint.enable",
                "false");
        c.putString("ca.crl.MasterCRL.extension.IssuingDistributionPoint.critical",
                "true");
        c.putString("ca.crl.MasterCRL.extension.IssuingDistributionPoint.type",
                "CRLExtension");
        c.putString("ca.crl.MasterCRL.extension.IssuingDistributionPoint.class",
                "com.netscape.cms.crl.CMSIssuingDistributionPointExtension");
        c.putString("ca.crl.MasterCRL.extension.IssuingDistributionPoint.pointType", "");
        c.putString("ca.crl.MasterCRL.extension.IssuingDistributionPoint.pointName", "");
        c.putString("ca.crl.MasterCRL.extension.IssuingDistributionPoint.onlyContainsUserCerts",
                "false");
        c.putString("ca.crl.MasterCRL.extension.IssuingDistributionPoint.onlyContainsCACerts",
                "false");
        c.putString("ca.crl.MasterCRL.extension.IssuingDistributionPoint.onlySomeReasons", "");
        //"keyCompromise,cACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold");
        c.putString("ca.crl.MasterCRL.extension.IssuingDistributionPoint.indirectCRL",
                "false");

        // CRLReason
        c.putString("ca.crl.MasterCRL.extension.CRLReason.enable", "true");
        c.putString("ca.crl.MasterCRL.extension.CRLReason.critical", "false");
        c.putString("ca.crl.MasterCRL.extension.CRLReason.type", "CRLEntryExtension");
        c.putString("ca.crl.MasterCRL.extension.CRLReason.class",
                "com.netscape.cms.crl.CMSCRLReasonExtension");

        // HoldInstruction
        c.putString("ca.crl.MasterCRL.extension.HoldInstruction.enable", "false");
        c.putString("ca.crl.MasterCRL.extension.HoldInstruction.critical", "false");
        c.putString("ca.crl.MasterCRL.extension.HoldInstruction.type", "CRLEntryExtension");
        c.putString("ca.crl.MasterCRL.extension.HoldInstruction.class",
                "com.netscape.cms.crl.CMSHoldInstructionExtension");
        c.putString("ca.crl.MasterCRL.extension.HoldInstruction.instruction", "none");

        // InvalidityDate
        c.putString("ca.crl.MasterCRL.extension.InvalidityDate.enable", "true");
        c.putString("ca.crl.MasterCRL.extension.InvalidityDate.critical", "false");
        c.putString("ca.crl.MasterCRL.extension.InvalidityDate.type", "CRLEntryExtension");
        c.putString("ca.crl.MasterCRL.extension.InvalidityDate.class",
                "com.netscape.cms.crl.CMSInvalidityDateExtension");

        // CertificateIssuer
        /*
         c.putString("ca.crl.MasterCRL.extension.CertificateIssuer.enable", "false");
         c.putString("ca.crl.MasterCRL.extension.CertificateIssuer.critical", "true");
         c.putString("ca.crl.MasterCRL.extension.CertificateIssuer.type", "CRLEntryExtension");
         c.putString("ca.crl.MasterCRL.extension.CertificateIssuer.class",
         "com.netscape.cms.crl.CMSCertificateIssuerExtension");
         c.putString("ca.crl.MasterCRL.extension.CertificateIssuer.numNames", "0");
         c.putString("ca.crl.MasterCRL.extension.CertificateIssuer.nameType0", "");
         c.putString("ca.crl.MasterCRL.extension.CertificateIssuer.name0", "");
         */

        // FreshestCRL
        c.putString("ca.crl.MasterCRL.extension.FreshestCRL.enable", "false");
        c.putString("ca.crl.MasterCRL.extension.FreshestCRL.critical", "false");
        c.putString("ca.crl.MasterCRL.extension.FreshestCRL.type", "CRLExtension");
        c.putString("ca.crl.MasterCRL.extension.FreshestCRL.class",
                "com.netscape.cms.crl.CMSFreshestCRLExtension");
        c.putString("ca.crl.MasterCRL.extension.FreshestCRL.numPoints", "0");
        c.putString("ca.crl.MasterCRL.extension.FreshestCRL.pointType0", "");
        c.putString("ca.crl.MasterCRL.extension.FreshestCRL.pointName0", "");
    }

    public static void installCAPublishingImpls(IConfigStore c)
            throws EBaseException {
        for (int i = 0; i < caLdappublishImplsEntries.length; i++) {
            c.putString(
                    caLdappublishImplsEntries[i][0], caLdappublishImplsEntries[i][1]);
        }
    }

    private static final String[][] caLdappublishImplsEntries = new String[][] {
            { "ca.publish.mapper.impl.LdapCaSimpleMap.class", "com.netscape.cms.publish.LdapCaSimpleMap" },
            { "ca.publish.mapper.impl.LdapSimpleMap.class", "com.netscape.cms.publish.LdapSimpleMap" },
            { "ca.publish.mapper.impl.LdapEnhancedMap.class", "com.netscape.cms.publish.LdapEnhancedMap" },
            { "ca.publish.mapper.impl.LdapDNCompsMap.class", "com.netscape.cms.publish.LdapCertCompsMap" },
            { "ca.publish.mapper.impl.LdapSubjAttrMap.class", "com.netscape.cms.publish.LdapCertSubjMap" },
            { "ca.publish.mapper.impl.LdapDNExactMap.class", "com.netscape.cms.publish.LdapCertExactMap" },
            //{"ca.publish.mapper.impl.LdapCrlIssuerCompsMap.class","com.netscape.cms.publish.LdapCrlIssuerCompsMap"},
            {
                    "ca.publish.publisher.impl.LdapUserCertPublisher.class",
                    "com.netscape.cms.publish.LdapUserCertPublisher" },
            {
                    "ca.publish.publisher.impl.LdapCaCertPublisher.class",
                    "com.netscape.cms.publish.LdapCaCertPublisher" },
            { "ca.publish.publisher.impl.LdapCrlPublisher.class", "com.netscape.cms.publish.LdapCrlPublisher" },
            {
                    "ca.publish.publisher.impl.FileBasedPublisher.class",
                    "com.netscape.cms.publish.FileBasedPublisher" },
            { "ca.publish.publisher.impl.OCSPPublisher.class", "com.netscape.cms.publish.OCSPPublisher" },
            { "ca.publish.rule.impl.Rule.class", "com.netscape.cmscore.ldap.LdapRule" },
    };

}
