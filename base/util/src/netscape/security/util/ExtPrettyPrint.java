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
package netscape.security.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.util.Enumeration;
import java.util.ResourceBundle;
import java.util.Vector;

import netscape.security.extensions.AccessDescription;
import netscape.security.extensions.AuthInfoAccessExtension;
import netscape.security.extensions.CertificateScopeEntry;
import netscape.security.extensions.CertificateScopeOfUseExtension;
import netscape.security.extensions.ExtendedKeyUsageExtension;
import netscape.security.extensions.InhibitAnyPolicyExtension;
import netscape.security.extensions.NSCertTypeExtension;
import netscape.security.extensions.OCSPNoCheckExtension;
import netscape.security.extensions.PresenceServerExtension;
import netscape.security.extensions.SubjectInfoAccessExtension;
import netscape.security.x509.Attribute;
import netscape.security.x509.AuthorityKeyIdentifierExtension;
import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.CPSuri;
import netscape.security.x509.CRLDistributionPoint;
import netscape.security.x509.CRLDistributionPointsExtension;
import netscape.security.x509.CRLDistributionPointsExtension.Reason;
import netscape.security.x509.CRLNumberExtension;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.CertificateIssuerExtension;
import netscape.security.x509.CertificatePoliciesExtension;
import netscape.security.x509.CertificatePolicyInfo;
import netscape.security.x509.CertificatePolicyMap;
import netscape.security.x509.DeltaCRLIndicatorExtension;
import netscape.security.x509.DisplayText;
import netscape.security.x509.Extension;
import netscape.security.x509.FreshestCRLExtension;
import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNameInterface;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.HoldInstructionExtension;
import netscape.security.x509.InvalidityDateExtension;
import netscape.security.x509.IssuerAlternativeNameExtension;
import netscape.security.x509.IssuingDistributionPoint;
import netscape.security.x509.IssuingDistributionPointExtension;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.KeyUsageExtension;
import netscape.security.x509.NSCCommentExtension;
import netscape.security.x509.NameConstraintsExtension;
import netscape.security.x509.NoticeReference;
import netscape.security.x509.OIDMap;
import netscape.security.x509.PolicyConstraintsExtension;
import netscape.security.x509.PolicyMappingsExtension;
import netscape.security.x509.PolicyQualifierInfo;
import netscape.security.x509.PolicyQualifiers;
import netscape.security.x509.PrivateKeyUsageExtension;
import netscape.security.x509.Qualifier;
import netscape.security.x509.RDN;
import netscape.security.x509.SerialNumber;
import netscape.security.x509.SubjectAlternativeNameExtension;
import netscape.security.x509.SubjectDirAttributesExtension;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.UserNotice;

/**
 * This class will display the certificate content in predefined
 * format.
 *
 * @author Andrew Wnuk
 * @version $Revision$, $Date$
 */
public class ExtPrettyPrint {

    /*==========================================================
     * variables
     *==========================================================*/
    private Extension mExt = null;
    private ResourceBundle mResource = null;
    private PrettyPrintFormat pp = null;
    private int mIndentSize = 0;

    DateFormat dateFormater = null;

    /*==========================================================
     * constructors
     *==========================================================*/

    public ExtPrettyPrint(Extension ext, int indentSize) {
        mExt = ext;
        mResource = ResourceBundle.getBundle(PrettyPrintResources.class.getName());
        mIndentSize = indentSize;
        pp = new PrettyPrintFormat(":");
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * This method return string representation of the certificate
     * in predefined format using specified client local. I18N Support.
     *
     * @param clientLocale Locale to be used for localization
     * @return string representation of the certificate
     */
    //    public String toString(int indentSize) {
    public String toString() {

        StringBuffer sb = new StringBuffer();

        //check if the extension is known
        if (mExt instanceof KeyUsageExtension) {
            return getKeyUsage();
        }
        if (mExt instanceof NSCertTypeExtension) {
            return getCertType();
        }
        if (mExt instanceof AuthorityKeyIdentifierExtension) {
            return getAuthorityKeyIdentifier();
        }
        if (mExt instanceof SubjectKeyIdentifierExtension) {
            return getSubjectKeyIdentifier();
        }
        if (mExt instanceof CRLReasonExtension) {
            return getCRLReasonExtension();
        }
        if (mExt instanceof BasicConstraintsExtension) {
            return getBasicConstraintsExtension();
        }
        if (mExt instanceof NSCCommentExtension) {
            return getNSCCommentExtension();
        }
        if (mExt instanceof NameConstraintsExtension) {
            return getNameConstraintsExtension();
        }
        if (mExt instanceof CRLNumberExtension) {
            return getCRLNumberExtension();
        }
        if (mExt instanceof DeltaCRLIndicatorExtension) {
            return getDeltaCRLIndicatorExtension();
        }
        if (mExt instanceof IssuerAlternativeNameExtension) {
            return getIssuerAlternativeNameExtension();
        }
        if (mExt instanceof SubjectAlternativeNameExtension) {
            return getSubjectAlternativeNameExtension();
        }
        if (mExt instanceof FreshestCRLExtension) {
            return getFreshestCRLExtension();
        }
        if (mExt instanceof CRLDistributionPointsExtension) {
            return getCRLDistributionPointsExtension();
        }
        if (mExt instanceof IssuingDistributionPointExtension) {
            return getIssuingDistributionPointExtension();
        }
        if (mExt instanceof ExtendedKeyUsageExtension) {
            return getExtendedKeyUsageExtension();
        }
        if (mExt instanceof AuthInfoAccessExtension) {
            return getAuthInfoAccessExtension();
        }
        if (mExt instanceof SubjectInfoAccessExtension) {
            return getSubjectInfoAccessExtension();
        }
        if (mExt instanceof OCSPNoCheckExtension) {
            return getOCSPNoCheckExtension();
        }
        if (mExt instanceof PrivateKeyUsageExtension) {
            return getPrivateKeyUsageExtension();
        }
        if (mExt instanceof InvalidityDateExtension) {
            return getInvalidityDateExtension();
        }
        if (mExt instanceof CertificateIssuerExtension) {
            return getCertificateIssuerExtension();
        }
        if (mExt instanceof HoldInstructionExtension) {
            return getHoldInstructionExtension();
        }
        if (mExt instanceof PolicyConstraintsExtension) {
            return getPolicyConstraintsExtension();
        }
        if (mExt instanceof PolicyMappingsExtension) {
            return getPolicyMappingsExtension();
        }
        if (mExt instanceof SubjectDirAttributesExtension) {
            return getSubjectDirAttributesExtension();
        }
        if (mExt instanceof CertificateScopeOfUseExtension) {
            return getCertificateScopeOfUseExtension();
        }
        if (mExt instanceof PresenceServerExtension) {
            return getPresenceServerExtension();
        }

        if (mExt instanceof InhibitAnyPolicyExtension) {
            return getInhibitAnyPolicyExtension();
        }

        if (mExt instanceof CertificatePoliciesExtension) {
            return getCertificatePoliciesExtension();
        }

        //unknown cert extension
        String extName = OIDMap.getName(mExt.getExtensionId());

        if (extName == null)
            sb.append(pp.indent(mIndentSize) + mResource.getString(
                    PrettyPrintResources.TOKEN_IDENTIFIER) +
                    mExt.getExtensionId().toString() + "\n");
        else
            sb.append(pp.indent(mIndentSize) + mResource.getString(
                    PrettyPrintResources.TOKEN_IDENTIFIER) + " " + extName + " - " +
                    mExt.getExtensionId().toString() + "\n");

        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_VALUE) + "\n");
        sb.append(pp.toHexString(mExt.getExtensionValue(), mIndentSize + 8, 16));

        return sb.toString();

    }

    /*==========================================================
     * Private methods
     *==========================================================*/

    private String getNSCCommentExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_NSC_COMMENT) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }
        sb.append(pp.indent(mIndentSize + 4) + ((NSCCommentExtension) mExt).toPrint(mIndentSize) + "\n");
        return sb.toString();
    }

    private String getNameConstraintsExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_NAME_CONSTRAINTS) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }

        sb.append(pp.indent(mIndentSize + 4) + ((NameConstraintsExtension) mExt).toPrint(mIndentSize + 4));

        return sb.toString();
    }

    private String getOCSPNoCheckExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_OCSP_NOCHECK) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }
        return sb.toString();
    }

    private String getSubjectInfoAccessExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_SIA) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_ACCESS_DESC) + "\n");
        SubjectInfoAccessExtension aia = (SubjectInfoAccessExtension) mExt;

        for (int i = 0; i < aia.numberOfAccessDescription(); i++) {
            AccessDescription ad = aia.getAccessDescription(i);
            ObjectIdentifier method = ad.getMethod();

            if (method.equals(SubjectInfoAccessExtension.METHOD_OCSP)) {
                sb.append(pp.indent(mIndentSize + 8) + "Method #" + i + ": " +
                        "ocsp" + "\n");
            } else {
                sb.append(pp.indent(mIndentSize + 8) + "Method #" + i + ": " +
                        method.toString() + "\n");
            }
            sb.append(pp.indent(mIndentSize + 8) + "Location #" + i + ": " +
                    ad.getLocation().toString() + "\n");
        }
        return sb.toString();
    }

    private String getAuthInfoAccessExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_AIA) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_ACCESS_DESC) + "\n");
        AuthInfoAccessExtension aia = (AuthInfoAccessExtension) mExt;

        for (int i = 0; i < aia.numberOfAccessDescription(); i++) {
            AccessDescription ad = aia.getAccessDescription(i);
            ObjectIdentifier method = ad.getMethod();

            if (method.equals(AuthInfoAccessExtension.METHOD_OCSP)) {
                sb.append(pp.indent(mIndentSize + 8) + "Method #" + i + ": " +
                        "ocsp" + "\n");
            } else {
                sb.append(pp.indent(mIndentSize + 8) + "Method #" + i + ": " +
                        method.toString() + "\n");
            }
            sb.append(pp.indent(mIndentSize + 8) + "Location #" + i + ": " +
                    ad.getLocation().toString() + "\n");
        }
        return sb.toString();
    }

    private String getPresenceServerExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_PRESENCE_SERVER) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }

        PresenceServerExtension pse = (PresenceServerExtension) mExt;

        sb.append(pp.indent(mIndentSize + 4) + "Version : " + pse.getVersion() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + "Street Address : " + pse.getStreetAddress() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + "Telephone Number : " + pse.getTelephoneNumber() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + "RFC822 Name : " + pse.getRFC822() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + "ID : " + pse.getID() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + "Host Name : " + pse.getHostName() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + "Port Number : " + pse.getPortNumber() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + "Max Users : " + pse.getMaxUsers() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + "Service Level : " + pse.getServiceLevel() + "\n");

        return sb.toString();
    }

    private String getPrivateKeyUsageExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_PRIVATE_KEY_USAGE) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }

        PrivateKeyUsageExtension usage = (PrivateKeyUsageExtension) mExt;

        sb.append(pp.indent(mIndentSize + 4) + "Validity:\n");

        if (dateFormater == null) {
            dateFormater = DateFormat.getDateInstance(DateFormat.FULL);
        }
        String notBefore = dateFormater.format(usage.getNotBefore());
        String notAfter = dateFormater.format(usage.getNotAfter());

        sb.append(pp.indent(mIndentSize + 8) + "Not Before: " + notBefore + "\n");
        sb.append(pp.indent(mIndentSize + 8) + "Not  After: " + notAfter + "\n");

        return sb.toString();
    }

    private String getExtendedKeyUsageExtension() {
        StringBuffer sb = new StringBuffer();
        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_EXTENDED_KEY_USAGE) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_EXTENDED_KEY_USAGE) + "\n");
        ExtendedKeyUsageExtension usage = (ExtendedKeyUsageExtension) mExt;
        Enumeration<ObjectIdentifier> e = usage.getOIDs();

        if (e != null) {
            while (e.hasMoreElements()) {
                ObjectIdentifier oid = e.nextElement();

                if (oid.equals(ExtendedKeyUsageExtension.OID_OCSP_SIGNING)) {
                    sb.append(pp.indent(mIndentSize + 8) + "OCSPSigning" + "\n");
                } else {
                    sb.append(pp.indent(mIndentSize + 8) + oid.toString() + "\n");
                }
            }
        }
        return sb.toString();
    }

    /**
     * String Representation of KeyUsageExtension
     */
    private String getKeyUsage() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(
                    PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_KEY_USAGE) +
                    "- " + mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                    PrettyPrintResources.TOKEN_CRITICAL));
            if (mExt.isCritical()) {
                sb.append(mResource.getString(
                        PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(
                        PrettyPrintResources.TOKEN_NO) + "\n");
            }
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                    PrettyPrintResources.TOKEN_KEY_USAGE) + "\n");
            KeyUsageExtension usage = (KeyUsageExtension) mExt;

            if (((Boolean) usage.get(KeyUsageExtension.DIGITAL_SIGNATURE)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(KeyUsageExtension.DIGITAL_SIGNATURE) + "\n");
            }
            if (((Boolean) usage.get(KeyUsageExtension.NON_REPUDIATION)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(KeyUsageExtension.NON_REPUDIATION) + "\n");
            }
            if (((Boolean) usage.get(KeyUsageExtension.KEY_ENCIPHERMENT)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(KeyUsageExtension.KEY_ENCIPHERMENT) + "\n");
            }
            if (((Boolean) usage.get(KeyUsageExtension.DATA_ENCIPHERMENT)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(KeyUsageExtension.DATA_ENCIPHERMENT) + "\n");
            }
            if (((Boolean) usage.get(KeyUsageExtension.KEY_AGREEMENT)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(KeyUsageExtension.KEY_AGREEMENT) + "\n");
            }
            if (((Boolean) usage.get(KeyUsageExtension.KEY_CERTSIGN)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(KeyUsageExtension.KEY_CERTSIGN) + "\n");
            }
            if (((Boolean) usage.get(KeyUsageExtension.CRL_SIGN)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(KeyUsageExtension.CRL_SIGN) + "\n");
            }
            if (((Boolean) usage.get(KeyUsageExtension.ENCIPHER_ONLY)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(KeyUsageExtension.ENCIPHER_ONLY) + "\n");
            }
            if (((Boolean) usage.get(KeyUsageExtension.DECIPHER_ONLY)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(KeyUsageExtension.DECIPHER_ONLY) + "\n");
            }
            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return sb.toString();
        }

    }

    /**
     * String Representation of NSCertTypeExtension
     */
    private String getCertType() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_CERT_TYPE)
                    + "- " + mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CERT_USAGE) + "\n");
            NSCertTypeExtension type = (NSCertTypeExtension) mExt;

            if (((Boolean) type.get(NSCertTypeExtension.SSL_CLIENT)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(NSCertTypeExtension.SSL_CLIENT) + "\n");
            }
            if (((Boolean) type.get(NSCertTypeExtension.SSL_SERVER)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(NSCertTypeExtension.SSL_SERVER) + "\n");
            }
            if (((Boolean) type.get(NSCertTypeExtension.EMAIL)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(NSCertTypeExtension.EMAIL) + "\n");
            }
            if (((Boolean) type.get(NSCertTypeExtension.OBJECT_SIGNING)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(NSCertTypeExtension.OBJECT_SIGNING) + "\n");
            }
            if (((Boolean) type.get(NSCertTypeExtension.SSL_CA)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(NSCertTypeExtension.SSL_CA) + "\n");
            }
            if (((Boolean) type.get(NSCertTypeExtension.EMAIL_CA)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8) + mResource.getString(NSCertTypeExtension.EMAIL_CA) + "\n");
            }
            if (((Boolean) type.get(NSCertTypeExtension.OBJECT_SIGNING_CA)).booleanValue()) {
                sb.append(pp.indent(mIndentSize + 8)
                        + mResource.getString(NSCertTypeExtension.OBJECT_SIGNING_CA) + "\n");
            }
            return sb.toString();
        } catch (CertificateException e) {
            e.printStackTrace();
            return "";
        }

    }

    /**
     * String Representation of SubjectKeyIdentifierExtension
     */
    private String getSubjectKeyIdentifier() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_SKI)
                    + "- " + mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }
            SubjectKeyIdentifierExtension id = (SubjectKeyIdentifierExtension) mExt;
            KeyIdentifier keyId = (KeyIdentifier) id.get(SubjectKeyIdentifierExtension.KEY_ID);

            if (keyId != null) {
                sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_KEY_ID) + "\n");
                sb.append(pp.toHexString(keyId.getIdentifier(), 24, 16));
            }
            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * String Representation of AuthorityKeyIdentifierExtension
     */
    private String getAuthorityKeyIdentifier() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_AKI)
                    + "- " + mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }
            AuthorityKeyIdentifierExtension id = (AuthorityKeyIdentifierExtension) mExt;
            KeyIdentifier keyId = (KeyIdentifier) id.get(AuthorityKeyIdentifierExtension.KEY_ID);

            if (keyId != null) {
                sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_KEY_ID) + "\n");
                sb.append(pp.toHexString(keyId.getIdentifier(), mIndentSize + 8, 16));
                //                sb.append(pp.toHexString(keyId.getIdentifier(),24,16));
            }
            GeneralNames authNames = (GeneralNames) id.get(AuthorityKeyIdentifierExtension.AUTH_NAME);

            if (authNames != null) {
                for (int i = 0; i < authNames.size(); i++) {
                    GeneralName authName = (GeneralName) authNames.elementAt(i);

                    if (authName != null) {
                        sb.append(pp.indent(mIndentSize + 4)
                                + mResource.getString(PrettyPrintResources.TOKEN_AUTH_NAME) + authName.toString()
                                + "\n");
                    }
                }
            }

            SerialNumber serial = (SerialNumber) id.get(AuthorityKeyIdentifierExtension.SERIAL_NUMBER);

            if (serial != null) {
                sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_SERIAL) +
                        "0x" + serial.getNumber().toBigInteger().toString(16).toUpperCase() + "\n");
            }
            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * String Representation of CRLReasonExtension
     */
    private String getCRLReasonExtension() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_REVOCATION_REASON) + "- " +
                    mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
            CRLReasonExtension ext = (CRLReasonExtension) mExt;

            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_REASON) +
                    ext.getReason().toString() + "\n");

            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * String Representation of InhibitAnyPolicyExtension
     */
    private String getInhibitAnyPolicyExtension() {
        StringBuffer sb = new StringBuffer();
        sb.append(pp.indent(mIndentSize) +
                mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(
                PrettyPrintResources.TOKEN_INHIBIT_ANY_POLICY_EXT) + "- " +
                mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) +
                mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
        InhibitAnyPolicyExtension ext = (InhibitAnyPolicyExtension) mExt;
        if (mExt.isCritical())
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        else
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_SKIP_CERTS));
        BigInt num = ext.getSkipCerts();
        sb.append("" + num.toInt() + "\n");
        return sb.toString();
    }

    /**
     * String Representation of BasicConstraintsExtension
     */
    private String getBasicConstraintsExtension() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_BASIC_CONSTRAINTS) + "- " +
                    mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
            BasicConstraintsExtension ext = (BasicConstraintsExtension) mExt;

            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_IS_CA));
            boolean isCA = ((Boolean) ext.get(BasicConstraintsExtension.IS_CA)).booleanValue();

            if (isCA) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }
            Integer pathLength = (Integer) ext.get(BasicConstraintsExtension.PATH_LEN);

            if (pathLength != null) {
                if (pathLength.longValue() >= 0) {
                    sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_PATH_LEN) +
                            pathLength.toString() + "\n");
                } else if (pathLength.longValue() == -1 || pathLength.longValue() == -2) {
                    sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_PATH_LEN) +
                            mResource.getString(PrettyPrintResources.TOKEN_PATH_LEN_UNLIMITED) + "\n");
                } else {
                    sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_PATH_LEN) +
                            mResource.getString(PrettyPrintResources.TOKEN_PATH_LEN_INVALID) +
                            " (" + pathLength.toString() + ")\n");
                }
            }

            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * String Representation of CRLNumberExtension
     */
    private String getCRLNumberExtension() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_CRL_NUMBER) + "- " +
                    mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
            CRLNumberExtension ext = (CRLNumberExtension) mExt;

            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }
            BigInteger crlNumber = (BigInteger) ext.get(CRLNumberExtension.NUMBER);

            if (crlNumber != null) {
                sb.append(pp.indent(mIndentSize + 4) +
                        mResource.getString(PrettyPrintResources.TOKEN_NUMBER) +
                        crlNumber.toString() + "\n");
            }

            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * String Representation of DeltaCRLIndicatorExtension
     */
    private String getDeltaCRLIndicatorExtension() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_DELTA_CRL_INDICATOR) + "- " +
                    mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
            DeltaCRLIndicatorExtension ext = (DeltaCRLIndicatorExtension) mExt;

            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }
            BigInteger crlNumber = (BigInteger) ext.get(DeltaCRLIndicatorExtension.NUMBER);

            if (crlNumber != null) {
                sb.append(pp.indent(mIndentSize + 4) +
                        mResource.getString(PrettyPrintResources.TOKEN_BASE_CRL_NUMBER) +
                        crlNumber.toString() + "\n");
            }

            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * String Representation of IssuerAlternativeName Extension
     */
    private String getIssuerAlternativeNameExtension() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_ISSUER_ALT_NAME) + "- " +
                    mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
            IssuerAlternativeNameExtension ext = (IssuerAlternativeNameExtension) mExt;

            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }

            GeneralNames issuerNames = (GeneralNames) ext.get(IssuerAlternativeNameExtension.ISSUER_NAME);

            if (issuerNames != null) {
                sb.append(pp.indent(mIndentSize + 4) +
                        mResource.getString(PrettyPrintResources.TOKEN_ISSUER_NAMES) + "\n");
                for (int i = 0; i < issuerNames.size(); i++) {
                    GeneralName issuerName = (GeneralName) issuerNames.elementAt(i);

                    if (issuerName != null) {
                        String nameType = "";

                        if (issuerName.getType() == GeneralNameInterface.NAME_DIRECTORY)
                            nameType = "DirectoryName: ";
                        sb.append(pp.indent(mIndentSize + 8) + nameType + issuerName.toString() + "\n");
                    }
                }
            }

            return sb.toString();
        } catch (IOException e) {
            return "";
        }
    }

    /**
     * String Representation of SubjectAlternativeName Extension
     */
    private String getSubjectAlternativeNameExtension() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_SUBJECT_ALT_NAME) + "- " +
                    mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
            SubjectAlternativeNameExtension ext = (SubjectAlternativeNameExtension) mExt;

            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }

            GeneralNames subjectNames = (GeneralNames) ext.get(SubjectAlternativeNameExtension.SUBJECT_NAME);

            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_VALUE) + "\n");
            for (int i = 0; i < subjectNames.size(); i++) {
                GeneralName subjectName = (GeneralName) subjectNames.elementAt(i);

                if (subjectName != null) {
                    String nameType = "";

                    if (subjectName.getType() == GeneralNameInterface.NAME_DIRECTORY)
                        nameType = "DirectoryName: ";
                    sb.append(pp.indent(mIndentSize + 8) + nameType + subjectName.toString() + "\n");
                }
            }

            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * String Representation of CertificateScopeOfUse Extension
     */
    private String getCertificateScopeOfUseExtension() {
        StringBuffer sb = new StringBuffer();
        sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_CERT_SCOPE_OF_USE) + "- " +
                mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
        CertificateScopeOfUseExtension ext = (CertificateScopeOfUseExtension) mExt;

        if (mExt.isCritical()) {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
        }
        Vector<CertificateScopeEntry> entries = ext.getCertificateScopeEntries();

        if (entries != null) {
            sb.append(pp.indent(mIndentSize + 4) +
                    mResource.getString(PrettyPrintResources.TOKEN_SCOPE_OF_USE) + "\n");
            for (int i = 0; i < entries.size(); i++) {
                CertificateScopeEntry se = entries.elementAt(i);
                GeneralName gn = se.getGeneralName();

                if (gn != null) {
                    String nameType = "";

                    if (gn.getType() == GeneralNameInterface.NAME_DIRECTORY)
                        nameType = "DirectoryName: ";
                    sb.append(pp.indent(mIndentSize + 8) + nameType + gn.toString() + "\n");
                }
                BigInt port = se.getPort();

                if (port != null) {
                    sb.append(pp.indent(mIndentSize + 8) + PrettyPrintResources.TOKEN_PORT +
                            port.toBigInteger().toString() + "\n");
                }
            }
        }
        return sb.toString();
    }

    /**
     * String Representation of FreshestCRLExtension
     */
    private String getFreshestCRLExtension() {
        StringBuffer sb = new StringBuffer();

        //
        // Generic stuff: name, OID, criticality
        //
        sb.append(pp.indent(mIndentSize) +
                mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(
                PrettyPrintResources.TOKEN_FRESHEST_CRL_EXT) + "- " +
                mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) +
                mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }

        //
        // Now the CRLDP-specific stuff
        //
        FreshestCRLExtension ext = (FreshestCRLExtension) mExt;

        int numPoints = ext.getNumPoints();

        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRLDP_NUMPOINTS)
                + numPoints + "\n");

        for (int i = 0; i < numPoints; i++) {

            //
            // print one individual CRL distribution point
            //

            int idt;

            idt = mIndentSize + 4; // reset each time through loop
            boolean isEmpty = true;

            sb.append(pp.indent(idt) +
                    mResource.getString(PrettyPrintResources.TOKEN_CRLDP_POINTN) +
                    i + "\n");

            CRLDistributionPoint pt = ext.getPointAt(i);

            idt += 4; // further indent rest of information

            if (pt.getFullName() != null) {
                isEmpty = false;
                sb.append(pp.indent(idt) +
                        mResource.getString(PrettyPrintResources.TOKEN_CRLDP_DISTPOINT)
                        + pt.getFullName() + "\n");
            }

            if (pt.getRelativeName() != null) {
                isEmpty = false;
                sb.append(pp.indent(idt) +
                        mResource.getString(PrettyPrintResources.TOKEN_CRLDP_DISTPOINT)
                        + pt.getRelativeName() + "\n");
            }

            if (pt.getReasons() != null) {
                isEmpty = false;
                byte[] reasonBits = pt.getReasons().toByteArray();
                String reasonList = reasonBitsToReasonList(reasonBits);

                sb.append(pp.indent(idt) +
                        mResource.getString(PrettyPrintResources.TOKEN_CRLDP_REASONS)
                        + reasonList + "\n");
            }

            if (pt.getCRLIssuer() != null) {
                isEmpty = false;
                sb.append(pp.indent(idt) +
                        mResource.getString(PrettyPrintResources.TOKEN_CRLDP_CRLISSUER)
                        + pt.getCRLIssuer() + "\n");
            }

            if (isEmpty) {
                sb.append(pp.indent(idt) + "<i>empty</i>\n");
            }

        }

        return sb.toString();
    }

    /**
     * String Representation of CRLDistributionPointsExtension
     */
    private String getCRLDistributionPointsExtension() {
        StringBuffer sb = new StringBuffer();

        //
        // Generic stuff: name, OID, criticality
        //
        sb.append(pp.indent(mIndentSize) +
                mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(
                PrettyPrintResources.TOKEN_CRL_DP_EXT) + "- " +
                mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) +
                mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(
                    PrettyPrintResources.TOKEN_NO) + "\n");
        }

        //
        // Now the CRLDP-specific stuff
        //
        CRLDistributionPointsExtension ext =
                (CRLDistributionPointsExtension) mExt;

        int numPoints = ext.getNumPoints();

        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRLDP_NUMPOINTS)
                + numPoints + "\n");

        for (int i = 0; i < numPoints; i++) {

            //
            // print one individual CRL distribution point
            //

            int idt;

            idt = mIndentSize + 4; // reset each time through loop
            boolean isEmpty = true;

            sb.append(pp.indent(idt) +
                    mResource.getString(PrettyPrintResources.TOKEN_CRLDP_POINTN) +
                    i + "\n");

            CRLDistributionPoint pt = ext.getPointAt(i);

            idt += 4; // further indent rest of information

            if (pt.getFullName() != null) {
                isEmpty = false;
                sb.append(pp.indent(idt) +
                        mResource.getString(PrettyPrintResources.TOKEN_CRLDP_DISTPOINT)
                        + pt.getFullName() + "\n");
            }

            if (pt.getRelativeName() != null) {
                isEmpty = false;
                sb.append(pp.indent(idt) +
                        mResource.getString(PrettyPrintResources.TOKEN_CRLDP_DISTPOINT)
                        + pt.getRelativeName() + "\n");
            }

            if (pt.getReasons() != null) {
                isEmpty = false;
                byte[] reasonBits = pt.getReasons().toByteArray();
                String reasonList = reasonBitsToReasonList(reasonBits);

                sb.append(pp.indent(idt) +
                        mResource.getString(PrettyPrintResources.TOKEN_CRLDP_REASONS)
                        + reasonList + "\n");
            }

            if (pt.getCRLIssuer() != null) {
                isEmpty = false;
                sb.append(pp.indent(idt) +
                        mResource.getString(PrettyPrintResources.TOKEN_CRLDP_CRLISSUER)
                        + pt.getCRLIssuer() + "\n");
            }

            if (isEmpty) {
                sb.append(pp.indent(idt) + "<i>empty</i>\n");
            }

        }

        return sb.toString();
    }

    private static String reasonBitsToReasonList(byte[] reasonBits) {

        Reason[] reasons = Reason.bitArrayToReasonArray(reasonBits);

        if (reasons.length == 0) {
            return "";
        } else {
            StringBuffer buf = new StringBuffer();

            buf.append(reasons[0].getName());
            for (int i = 1; i < reasons.length; i++) {
                buf.append(", ");
                buf.append(reasons[i].getName());
            }
            return buf.toString();
        }
    }

    /**
     * String Representation of IssuerAlternativeName Extension
     */
    private String getIssuingDistributionPointExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_ISSUING_DIST_POINT) + "- " +
                mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
        }

        IssuingDistributionPointExtension ext = (IssuingDistributionPointExtension) mExt;
        IssuingDistributionPoint issuingDistributionPoint = ext.getIssuingDistributionPoint();

        if (issuingDistributionPoint != null) {
            GeneralNames fullNames = issuingDistributionPoint.getFullName();
            RDN relativeName = issuingDistributionPoint.getRelativeName();

            if (fullNames != null || relativeName != null) {
                sb.append(pp.indent(mIndentSize + 4)
                        + mResource.getString(PrettyPrintResources.TOKEN_DIST_POINT_NAME) + "\n");
                if (fullNames != null) {
                    sb.append(pp.indent(mIndentSize + 8)
                            + mResource.getString(PrettyPrintResources.TOKEN_FULL_NAME) + "\n");
                    for (int i = 0; i < fullNames.size(); i++) {
                        GeneralName fullName = (GeneralName) fullNames.elementAt(i);

                        if (fullName != null) {
                            sb.append(pp.indent(mIndentSize + 12) + fullName.toString() + "\n");
                        }
                    }
                }
                if (relativeName != null) {
                    sb.append(pp.indent(mIndentSize + 8)
                            + mResource.getString(PrettyPrintResources.TOKEN_RELATIVE_NAME) +
                            relativeName.toString() + "\n");
                }
            }

            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_ONLY_USER_CERTS));
            if (issuingDistributionPoint.getOnlyContainsUserCerts()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_ONLY_CA_CERTS));
            if (issuingDistributionPoint.getOnlyContainsCACerts()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }

            BitArray onlySomeReasons = issuingDistributionPoint.getOnlySomeReasons();

            if (onlySomeReasons != null) {
                sb.append(pp.indent(mIndentSize + 4)
                        + mResource.getString(PrettyPrintResources.TOKEN_ONLY_SOME_REASONS));
                sb.append("0x" + pp.toHexString(onlySomeReasons.toByteArray()));
            }

            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(PrettyPrintResources.TOKEN_INDIRECT_CRL));
            if (issuingDistributionPoint.getIndirectCRL()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }
        }

        return sb.toString();
    }

    /**
     * String Representation of InvalidityDateExtension
     */
    private String getInvalidityDateExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_INVALIDITY_DATE) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        InvalidityDateExtension ext = (InvalidityDateExtension) mExt;

        if (mExt.isCritical()) {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
        }
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_DATE_OF_INVALIDITY) +
                ext.getInvalidityDate().toString() + "\n");
        return sb.toString();
    }

    /**
     * String Representation of CertificateIssuerExtension
     */
    private String getCertificateIssuerExtension() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(
                    PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_CERTIFICATE_ISSUER) +
                    "- " + mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                    PrettyPrintResources.TOKEN_CRITICAL));
            CertificateIssuerExtension ext = (CertificateIssuerExtension) mExt;

            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }

            GeneralNames issuerNames = (GeneralNames) ext.get(
                    CertificateIssuerExtension.CERTIFICATE_ISSUER);

            if (issuerNames != null) {
                sb.append(pp.indent(mIndentSize + 4) +
                        mResource.getString(PrettyPrintResources.TOKEN_ISSUER_NAMES) + "\n");
                for (int i = 0; i < issuerNames.size(); i++) {
                    GeneralName issuerName = (GeneralName) issuerNames.elementAt(i);

                    if (issuerName != null) {
                        String nameType = "";

                        if (issuerName.getType() == GeneralNameInterface.NAME_DIRECTORY)
                            nameType = "DirectoryName: ";
                        sb.append(pp.indent(mIndentSize + 8) + nameType + issuerName.toString() + "\n");
                    }
                }
            }

            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * String Representation of HoldInstructionExtension
     */
    private String getHoldInstructionExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_HOLD_INSTRUCTION) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        HoldInstructionExtension ext = (HoldInstructionExtension) mExt;

        if (mExt.isCritical()) {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
        }
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_HOLD_INSTRUCTION_CODE) +
                ext.getHoldInstructionCodeDescription() + "\n");
        return sb.toString();
    }

    /**
     * String Representation of PolicyConstraintsExtension
     */
    private String getPolicyConstraintsExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(
                mResource.getString(
                        PrettyPrintResources.TOKEN_POLICY_CONSTRAINTS) +
                        "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
        }

        PolicyConstraintsExtension ext = (PolicyConstraintsExtension) mExt;
        int require = ext.getRequireExplicitMapping();
        int inhibit = ext.getInhibitPolicyMapping();

        sb.append(
                pp.indent(mIndentSize + 4) +
                        mResource.getString(
                                PrettyPrintResources.TOKEN_REQUIRE_EXPLICIT_POLICY) +
                        ((require == -1) ?
                                mResource.getString(PrettyPrintResources.TOKEN_NOT_SET) :
                                String.valueOf(require)) + "\n");
        sb.append(
                pp.indent(mIndentSize + 4) +
                        mResource.getString(
                                PrettyPrintResources.TOKEN_INHIBIT_POLICY_MAPPING) +
                        ((inhibit == -1) ?
                                mResource.getString(PrettyPrintResources.TOKEN_NOT_SET) :
                                String.valueOf(inhibit)) + "\n");
        return sb.toString();
    }

    /**
     * String Representation of PolicyMappingsExtension
     */
    private String getPolicyMappingsExtension() {
        StringBuffer sb = new StringBuffer();

        sb.append(pp.indent(mIndentSize) + mResource.getString(
                PrettyPrintResources.TOKEN_IDENTIFIER));
        sb.append(mResource.getString(PrettyPrintResources.TOKEN_POLICY_MAPPINGS) +
                "- " + mExt.getExtensionId().toString() + "\n");
        sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                PrettyPrintResources.TOKEN_CRITICAL));
        if (mExt.isCritical()) {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
        } else {
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
        }

        PolicyMappingsExtension ext = (PolicyMappingsExtension) mExt;
        Enumeration<CertificatePolicyMap> maps = ext.getMappings();

        sb.append(pp.indent(mIndentSize + 4) +
                mResource.getString(PrettyPrintResources.TOKEN_MAPPINGS));
        if (maps == null || !maps.hasMoreElements()) {
            sb.append(
                    mResource.getString(PrettyPrintResources.TOKEN_NONE) + "\n");
        } else {
            sb.append("\n");
            for (int i = 0; maps.hasMoreElements(); i++) {
                sb.append(pp.indent(mIndentSize + 8) +
                        mResource.getString(
                                PrettyPrintResources.TOKEN_MAP) + i + ":" + "\n");
                CertificatePolicyMap m =
                        maps.nextElement();

                sb.append(pp.indent(mIndentSize + 12) +
                        mResource.getString(
                                PrettyPrintResources.TOKEN_ISSUER_DOMAIN_POLICY) +
                        m.getIssuerIdentifier().getIdentifier().toString() + "\n");
                sb.append(pp.indent(mIndentSize + 12) +
                        mResource.getString(
                                PrettyPrintResources.TOKEN_SUBJECT_DOMAIN_POLICY) +
                        m.getSubjectIdentifier().getIdentifier().toString() + "\n");
            }
        }
        return sb.toString();
    }

    /**
     * String Representation of SubjectDirAttributesExtension
     */
    private String getSubjectDirAttributesExtension() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(
                    PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_SUBJECT_DIR_ATTR) +
                    "- " + mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) +
                    mResource.getString(PrettyPrintResources.TOKEN_CRITICAL));
            if (mExt.isCritical()) {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(PrettyPrintResources.TOKEN_NO) + "\n");
            }

            SubjectDirAttributesExtension ext =
                    (SubjectDirAttributesExtension) mExt;

            sb.append(pp.indent(mIndentSize + 4) +
                    mResource.getString(PrettyPrintResources.TOKEN_ATTRIBUTES));
            Enumeration<Attribute> attrs = ext.getAttributesList();

            if (attrs == null || !attrs.hasMoreElements()) {
                sb.append(
                        mResource.getString(PrettyPrintResources.TOKEN_NONE) + "\n");
            } else {
                sb.append("\n");
                for (int j = 0; attrs.hasMoreElements(); j++) {
                    Attribute attr = attrs.nextElement();

                    sb.append(pp.indent(mIndentSize + 8) +
                            mResource.getString(
                                    PrettyPrintResources.TOKEN_ATTRIBUTE) + j + ":" + "\n");
                    sb.append(pp.indent(mIndentSize + 12) +
                            mResource.getString(
                                    PrettyPrintResources.TOKEN_IDENTIFIER) +
                            attr.getOid().toString() + "\n");
                    sb.append(pp.indent(mIndentSize + 12) +
                            mResource.getString(
                                    PrettyPrintResources.TOKEN_VALUES));
                    Enumeration<String> values = attr.getValues();

                    if (values == null || !values.hasMoreElements()) {
                        sb.append(mResource.getString(
                                PrettyPrintResources.TOKEN_NONE) + "\n");
                    } else {
                        for (int k = 0; values.hasMoreElements(); k++) {
                            String v = values.nextElement();

                            if (k != 0)
                                sb.append(",");
                            sb.append(v);
                        }
                    }
                    sb.append("\n");
                }
            }
            return sb.toString();
        } catch (Throwable e) {
            return "";
        }
    }

    private String getCertificatePoliciesExtension() {
        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(mIndentSize) + mResource.getString(
                    PrettyPrintResources.TOKEN_IDENTIFIER));
            sb.append(mResource.getString(PrettyPrintResources.TOKEN_CERT_POLICIES) +
                    "- " + mExt.getExtensionId().toString() + "\n");
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                    PrettyPrintResources.TOKEN_CRITICAL));
            if (mExt.isCritical()) {
                sb.append(mResource.getString(
                        PrettyPrintResources.TOKEN_YES) + "\n");
            } else {
                sb.append(mResource.getString(
                        PrettyPrintResources.TOKEN_NO) + "\n");
            }
            sb.append(pp.indent(mIndentSize + 4) + mResource.getString(
                    PrettyPrintResources.TOKEN_CERT_POLICIES) + "\n");
            CertificatePoliciesExtension cp = (CertificatePoliciesExtension) mExt;
            @SuppressWarnings("unchecked")
            Vector<CertificatePolicyInfo> cpv = (Vector<CertificatePolicyInfo>) cp.get("infos");
            Enumeration<CertificatePolicyInfo> e = cpv.elements();

            if (e != null) {
                while (e.hasMoreElements()) {
                    CertificatePolicyInfo cpi = e.nextElement();

                    sb.append(pp.indent(mIndentSize + 8)
                            + "Policy Identifier: " + cpi.getPolicyIdentifier().getIdentifier().toString() + "\n");
                    PolicyQualifiers cpq = cpi.getPolicyQualifiers();
                    if (cpq != null) {
                        for (int i = 0; i < cpq.size(); i++) {
                            PolicyQualifierInfo pq = cpq.getInfoAt(i);
                            Qualifier q = pq.getQualifier();
                            if (q instanceof CPSuri) {
                                sb.append(pp.indent(mIndentSize + 12)
                                        + "Policy Qualifier Identifier: CPS Pointer Qualifier - "
                                        + pq.getId() + "\n");
                                sb.append(pp.indent(mIndentSize + 12)
                                        + "Policy Qualifier Data: " + ((CPSuri) q).getURI() + "\n");
                            } else if (q instanceof UserNotice) {
                                sb.append(pp.indent(mIndentSize + 12)
                                        + "Policy Qualifier Identifier: CPS User Notice Qualifier - "
                                        + pq.getId() + "\n");
                                NoticeReference nref = ((UserNotice) q).getNoticeReference();
                                DisplayText dt = ((UserNotice) q).getDisplayText();
                                sb.append(pp.indent(mIndentSize + 12) + "Policy Qualifier Data: \n");
                                if (nref != null) {
                                    sb.append(pp.indent(mIndentSize + 16)
                                            + "Organization: " + nref.getOrganization().toString() + "\n");
                                    sb.append(pp.indent(mIndentSize + 16) + "Notice Numbers: ");
                                    int[] nums = nref.getNumbers();
                                    for (int k = 0; k < nums.length; k++) {
                                        if (k != 0) {
                                            sb.append(",");
                                            sb.append(nums[k]);
                                        } else {
                                            sb.append(nums[k]);
                                        }
                                    }
                                    sb.append("\n");
                                }
                                if (dt != null) {
                                    sb.append(pp.indent(mIndentSize + 16) + "Explicit Text: " + dt.toString() + "\n");
                                }
                            }
                        }
                    }
                }
            }
            return sb.toString();
        } catch (IOException e) {
            return sb.toString();
        }
    }

}
