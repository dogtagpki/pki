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
package netscape.security.x509;

import netscape.security.util.ObjectIdentifier;

/**
 * Lists all the object identifiers of the X509 extensions of the PKIX profile.
 * 
 * <p>
 * Extensions are addiitonal attributes which can be inserted in a X509 v3
 * certificate. For example a "Driving License Certificate" could have the
 * driving license number as a extension.
 * 
 * <p>
 * Extensions are represented as a sequence of the extension identifier (Object
 * Identifier), a boolean flag stating whether the extension is to be treated as
 * being critical and the extension value itself (this is again a DER encoding
 * of the extension value).
 * 
 * @see Extension
 * 
 * @version 1.4
 * 
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class PKIXExtensions {
    // The object identifiers
    private static final int AuthorityKey_data[] = { 2, 5, 29, 35 };
    private static final int SubjectKey_data[] = { 2, 5, 29, 14 };
    private static final int KeyUsage_data[] = { 2, 5, 29, 15 };
    private static final int PrivateKeyUsage_data[] = { 2, 5, 29, 16 };
    private static final int CertificatePolicies_data[] = { 2, 5, 29, 32 };
    private static final int PolicyMappings_data[] = { 2, 5, 29, 33 };
    private static final int SubjectAlternativeName_data[] = { 2, 5, 29, 17 };
    private static final int IssuerAlternativeName_data[] = { 2, 5, 29, 18 };
    private static final int SubjectDirectoryAttributes_data[] = { 2, 5, 29, 9 };
    private static final int BasicConstraints_data[] = { 2, 5, 29, 19 };
    private static final int NameConstraints_data[] = { 2, 5, 29, 30 };
    private static final int PolicyConstraints_data[] = { 2, 5, 29, 36 };
    private static final int CRLDistributionPoints_data[] = { 2, 5, 29, 31 };
    private static final int CRLNumber_data[] = { 2, 5, 29, 20 };
    private static final int IssuingDistributionPoint_data[] = { 2, 5, 29, 28 };
    private static final int DeltaCRLIndicator_data[] = { 2, 5, 29, 27 };
    private static final int ReasonCode_data[] = { 2, 5, 29, 21 };
    private static final int HoldInstructionCode_data[] = { 2, 5, 29, 23 };
    private static final int InvalidityDate_data[] = { 2, 5, 29, 24 };
    private static final int CertificateIssuer_data[] = { 2, 5, 29, 29 };
    private static final int FreshestCRL_data[] = { 2, 5, 29, 46 };

    /**
     * Identifies the particular public key used to sign the certificate.
     */
    public static final ObjectIdentifier AuthorityKey_Id = new ObjectIdentifier(
            AuthorityKey_data);

    /**
     * Identifies the particular public key used in an application.
     */
    public static final ObjectIdentifier SubjectKey_Id = new ObjectIdentifier(
            SubjectKey_data);

    /**
     * Defines the purpose of the key contained in the certificate.
     */
    public static final ObjectIdentifier KeyUsage_Id = new ObjectIdentifier(
            KeyUsage_data);

    /**
     * Allows the certificate issuer to specify a different validity period for
     * the private key than the certificate.
     */
    public static final ObjectIdentifier PrivateKeyUsage_Id = new ObjectIdentifier(
            PrivateKeyUsage_data);

    /**
     * Contains the sequence of policy information terms.
     */
    public static final ObjectIdentifier CertificatePolicies_Id = new ObjectIdentifier(
            CertificatePolicies_data);

    /**
     * Lists pairs of objectidentifiers of policies considered equivalent by the
     * issuing CA to the subject CA.
     */
    public static final ObjectIdentifier PolicyMappings_Id = new ObjectIdentifier(
            PolicyMappings_data);

    /**
     * Allows additional identities to be bound to the subject of the
     * certificate.
     */
    public static final ObjectIdentifier SubjectAlternativeName_Id = new ObjectIdentifier(
            SubjectAlternativeName_data);

    /**
     * Allows additional identities to be associated with the certificate
     * issuer.
     */
    public static final ObjectIdentifier IssuerAlternativeName_Id = new ObjectIdentifier(
            IssuerAlternativeName_data);

    /**
     * Identifies additional directory attributes. This extension is always
     * non-critical.
     */
    public static final ObjectIdentifier SubjectDirectoryAttributes_Id = new ObjectIdentifier(
            SubjectDirectoryAttributes_data);

    /**
     * Identifies whether the subject of the certificate is a CA and how deep a
     * certification path may exist through that CA.
     */
    public static final ObjectIdentifier BasicConstraints_Id = new ObjectIdentifier(
            BasicConstraints_data);

    /**
     * Provides for permitted and excluded subtrees that place restrictions on
     * names that may be included within a certificate issued by a given CA.
     */
    public static final ObjectIdentifier NameConstraints_Id = new ObjectIdentifier(
            NameConstraints_data);

    /**
     * Used to either prohibit policy mapping or limit the set of policies that
     * can be in subsequent certificates.
     */
    public static final ObjectIdentifier PolicyConstraints_Id = new ObjectIdentifier(
            PolicyConstraints_data);

    /**
     * Identifies how CRL information is obtained.
     */
    public static final ObjectIdentifier CRLDistributionPoints_Id = new ObjectIdentifier(
            CRLDistributionPoints_data);

    /**
     * Conveys a monotonically increasing sequence number for each CRL issued by
     * a given CA.
     */
    public static final ObjectIdentifier CRLNumber_Id = new ObjectIdentifier(
            CRLNumber_data);

    /**
     * Identifies the CRL distribution point for a particular CRL.
     */
    public static final ObjectIdentifier IssuingDistributionPoint_Id = new ObjectIdentifier(
            IssuingDistributionPoint_data);

    /**
     * Identifies the delta CRL.
     */
    public static final ObjectIdentifier DeltaCRLIndicator_Id = new ObjectIdentifier(
            DeltaCRLIndicator_data);

    /**
     * Identifies the reason for the certificate revocation.
     */
    public static final ObjectIdentifier ReasonCode_Id = new ObjectIdentifier(
            ReasonCode_data);

    /**
     * This extension provides a registered instruction identifier indicating
     * the action to be taken, after encountering a certificate that has been
     * placed on hold.
     */
    public static final ObjectIdentifier HoldInstructionCode_Id = new ObjectIdentifier(
            HoldInstructionCode_data);

    /**
     * Identifies the date on which it is known or suspected that the private
     * key was compromised or that the certificate otherwise became invalid.
     */
    public static final ObjectIdentifier InvalidityDate_Id = new ObjectIdentifier(
            InvalidityDate_data);

    /**
     * Identifies the date on which it is known or suspected that the private
     * key was compromised or that the certificate otherwise became invalid.
     */
    public static final ObjectIdentifier CertificateIssuer_Id = new ObjectIdentifier(
            CertificateIssuer_data);

    /**
     * Identifies how delta CRL information is obtained.
     */
    public static final ObjectIdentifier FreshestCRL_Id = new ObjectIdentifier(
            FreshestCRL_data);

}
