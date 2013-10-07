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
package com.netscape.cmscore.cert;

import java.util.ListResourceBundle;

import netscape.security.extensions.NSCertTypeExtension;
import netscape.security.x509.KeyUsageExtension;

/**
 * Resource Boundle for the Pretty Print
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */

public class PrettyPrintResources extends ListResourceBundle {

    /**
     * Returns content
     */
    public Object[][] getContents() {
        return contents;
    }

    /**
     * Constants. The suffix represents the number of
     * possible parameters.
     */

    //certificate pretty print
    public final static String TOKEN_CERTIFICATE = "tokenCertificate";
    public final static String TOKEN_DATA = "tokenData";
    public final static String TOKEN_VERSION = "tokenVersion";
    public final static String TOKEN_SERIAL = "tokenSerial";
    public final static String TOKEN_SIGALG = "tokenSignatureAlgorithm";
    public final static String TOKEN_ISSUER = "tokenIssuer";
    public final static String TOKEN_VALIDITY = "tokenValidity";
    public final static String TOKEN_NOT_BEFORE = "tokenNotBefore";
    public final static String TOKEN_NOT_AFTER = "tokenNotAfter";
    public final static String TOKEN_SUBJECT = "tokenSubject";
    public final static String TOKEN_SPKI = "tokenSPKI";
    public final static String TOKEN_ALGORITHM = "tokenAlgorithm";
    public final static String TOKEN_PUBLIC_KEY = "tokenPublicKey";
    public final static String TOKEN_PUBLIC_KEY_MODULUS = "tokenPublicKeyModulus";
    public final static String TOKEN_PUBLIC_KEY_EXPONENT = "tokenPublicKeyExponent";
    public final static String TOKEN_EXTENSIONS = "tokenExtensions";
    public final static String TOKEN_SIGNATURE = "tokenSignature";

    //extension pretty print
    public final static String TOKEN_YES = "tokenYes";
    public final static String TOKEN_NO = "tokenNo";
    public final static String TOKEN_IDENTIFIER = "tokenIdentifier";
    public final static String TOKEN_CRITICAL = "tokenCritical";
    public final static String TOKEN_VALUE = "tokenValue";

    //specific extension token
    public final static String TOKEN_KEY_TYPE = "tokenKeyType";
    public final static String TOKEN_CERT_TYPE = "tokenCertType";
    public final static String TOKEN_SKI = "tokenSKI";
    public final static String TOKEN_AKI = "tokenAKI";
    public final static String TOKEN_ACCESS_DESC = "tokenAccessDesc";
    public final static String TOKEN_OCSP_NOCHECK = "tokenOcspNoCheck";
    public final static String TOKEN_EXTENDED_KEY_USAGE = "tokenExtendedKeyUsage";
    public final static String TOKEN_PRIVATE_KEY_USAGE = "tokenPrivateKeyUsage";
    public final static String TOKEN_PRESENCE_SERVER = "tokenPresenceServer";
    public final static String TOKEN_AIA = "tokenAIA";
    public final static String TOKEN_KEY_USAGE = "tokenKeyUsage";
    public final static String TOKEN_CERT_USAGE = "tokenCertUsage";
    public final static String TOKEN_KEY_ID = "tokenKeyId";
    public final static String TOKEN_AUTH_NAME = "tokenAuthName";

    public final static String TOKEN_CRL = "tokenCRL";
    public final static String TOKEN_THIS_UPDATE = "tokenThisUpdate";
    public final static String TOKEN_NEXT_UPDATE = "tokenNextUpdate";
    public final static String TOKEN_REVOKED_CERTIFICATES = "revokedCerts";
    public final static String TOKEN_REVOCATION_DATE = "revocationDate";

    public final static String TOKEN_REVOCATION_REASON = "revocationReason";
    public final static String TOKEN_REASON = "reason";

    public final static String TOKEN_BASIC_CONSTRAINTS = "basicConstraints";
    public final static String TOKEN_NAME_CONSTRAINTS = "tokenNameConstraints";
    public final static String TOKEN_NSC_COMMENT = "tokenNSCComment";
    public final static String TOKEN_IS_CA = "isCA";
    public final static String TOKEN_PATH_LEN = "pathLen";
    public final static String TOKEN_PATH_LEN_UNLIMITED = "pathLenUnlimited";
    public final static String TOKEN_PATH_LEN_UNDEFINED = "pathLenUndefined";
    public final static String TOKEN_PATH_LEN_INVALID = "pathLenInvalid";

    public final static String TOKEN_CRL_NUMBER = "CRLNumber";
    public final static String TOKEN_NUMBER = "Number";

    public final static String TOKEN_DELTA_CRL_INDICATOR = "DeltaCRLIndicator";
    public final static String TOKEN_BASE_CRL_NUMBER = "BaseCRLNumber";

    public final static String TOKEN_CERT_SCOPE_OF_USE = "CertificateScopeOfUse";
    public final static String TOKEN_SCOPE_OF_USE = "ScopeOfUse";
    public final static String TOKEN_PORT = "Port";

    public final static String TOKEN_ISSUER_ALT_NAME = "IssuerAlternativeName";
    public final static String TOKEN_ISSUER_NAMES = "IssuerNames";

    public final static String TOKEN_SUBJECT_ALT_NAME = "SubjectAlternativeName";
    public final static String TOKEN_SUBJECT_NAME = "SubjectName";

    public final static String TOKEN_DECODING_ERROR = "decodingError";

    public final static String TOKEN_FRESHEST_CRL_EXT = "FreshestCRL";

    public final static String TOKEN_CRL_DP_EXT = "CRLDistributionPoints";
    public final static String TOKEN_CRLDP_NUMPOINTS = "CRLDP_NUMPOINTS";
    public final static String TOKEN_CRLDP_POINTN = "CRLDP_POINTN";
    public final static String TOKEN_CRLDP_DISTPOINT = "CRLDP_DISTPOINT";
    public final static String TOKEN_CRLDP_REASONS = "CRLDP_REASONS";
    public final static String TOKEN_CRLDP_CRLISSUER = "CRLDP_CRLISSUER";

    public final static String TOKEN_ISSUING_DIST_POINT = "IssuingDistributionPoint";
    public final static String TOKEN_DIST_POINT_NAME = "DistributionPointName";
    public final static String TOKEN_FULL_NAME = "FullName";
    public final static String TOKEN_RELATIVE_NAME = "NameRelativeToCRLIssuer";
    public final static String TOKEN_ONLY_USER_CERTS = "OnlyContainsUserCerts";
    public final static String TOKEN_ONLY_CA_CERTS = "OnlyContainsCACerts";
    public final static String TOKEN_ONLY_SOME_REASONS = "OnlySomeReasons";
    public final static String TOKEN_INDIRECT_CRL = "IndirectCRL";

    public final static String TOKEN_INVALIDITY_DATE = "invalidityDate";
    public final static String TOKEN_DATE_OF_INVALIDITY = "dateOfInvalidity";

    public final static String TOKEN_CERTIFICATE_ISSUER = "CertificateIssuer";

    public final static String TOKEN_HOLD_INSTRUCTION = "HoldInstruction";
    public final static String TOKEN_HOLD_INSTRUCTION_CODE = "HoldInstructionCode";
    public final static String TOKEN_POLICY_CONSTRAINTS = "PolicyConstraints";
    public final static String TOKEN_POLICY_MAPPINGS = "PolicyMappings";
    public final static String TOKEN_SUBJECT_DIR_ATTR = "SubjectDirectoryAttributes";

    // policy constriants extension fields
    public final static String TOKEN_INHIBIT_POLICY_MAPPING = "inhibitPolicyMapping";
    public final static String TOKEN_REQUIRE_EXPLICIT_POLICY = "requireExplicitPolicy";

    // policy mappings extension fields
    public final static String TOKEN_MAPPINGS = "mappings";
    public final static String TOKEN_MAP = "map";
    public final static String TOKEN_ISSUER_DOMAIN_POLICY = "issuerDomainPolicy";
    public final static String TOKEN_SUBJECT_DOMAIN_POLICY = "subjectDomainPolicy";

    // subject directory attribute fields
    public final static String TOKEN_ATTRIBUTES = "Attributes";
    public final static String TOKEN_ATTRIBUTE = "Attribute";
    public final static String TOKEN_VALUES = "Values";

    // field values
    public final static String TOKEN_NOT_SET = "notSet";
    public final static String TOKEN_NONE = "none";

    public final static String TOKEN_CACHE_NOT_AVAILABLE = "cacheNotAvailable";
    public final static String TOKEN_CACHE_IS_EMPTY = "cacheIsEmpty";

    //Tokens should have blank_space as trailer
    static final Object[][] contents = {
            { TOKEN_CERTIFICATE, "Certificate: " },
            { TOKEN_DATA, "Data: " },
            { TOKEN_VERSION, "Version: " },
            { TOKEN_SERIAL, "Serial Number: " },
            { TOKEN_SIGALG, "Signature Algorithm: " },
            { TOKEN_ISSUER, "Issuer: " },
            { TOKEN_VALIDITY, "Validity: " },
            { TOKEN_NOT_BEFORE, "Not Before: " },
            { TOKEN_NOT_AFTER, "Not  After: " },
            { TOKEN_SUBJECT, "Subject: " },
            { TOKEN_SPKI, "Subject Public Key Info: " },
            { TOKEN_ALGORITHM, "Algorithm: " },
            { TOKEN_PUBLIC_KEY, "Public Key: " },
            { TOKEN_PUBLIC_KEY_MODULUS, "Public Key Modulus: " },
            { TOKEN_PUBLIC_KEY_EXPONENT, "Exponent: " },
            { TOKEN_EXTENSIONS, "Extensions: " },
            { TOKEN_SIGNATURE, "Signature: " },
            { TOKEN_YES, "yes " },
            { TOKEN_NO, "no " },
            { TOKEN_IDENTIFIER, "Identifier: " },
            { TOKEN_CRITICAL, "Critical: " },
            { TOKEN_VALUE, "Value: " },
            { TOKEN_KEY_TYPE, "Key Type " },
            { TOKEN_CERT_TYPE, "Netscape Certificate Type " },
            { TOKEN_SKI, "Subject Key Identifier " },
            { TOKEN_AKI, "Authority Key Identifier " },
            { TOKEN_ACCESS_DESC, "Access Description: " },
            { TOKEN_OCSP_NOCHECK, "OCSP NoCheck: " },
            { TOKEN_EXTENDED_KEY_USAGE, "Extended Key Usage: " },
            { TOKEN_PRIVATE_KEY_USAGE, "Private Key Usage: " },
            { TOKEN_PRESENCE_SERVER, "Presence Server: " },
            { TOKEN_AIA, "Authority Info Access: " },
            { TOKEN_KEY_USAGE, "Key Usage: " },
            { KeyUsageExtension.DIGITAL_SIGNATURE, "Digital Signature " },
            { KeyUsageExtension.NON_REPUDIATION, "Non Repudiation " },
            { KeyUsageExtension.KEY_ENCIPHERMENT, "Key Encipherment " },
            { KeyUsageExtension.DATA_ENCIPHERMENT, "Data Encipherment " },
            { KeyUsageExtension.KEY_AGREEMENT, "Key Agreement " },
            { KeyUsageExtension.KEY_CERTSIGN, "Key CertSign " },
            { KeyUsageExtension.CRL_SIGN, "Crl Sign " },
            { KeyUsageExtension.ENCIPHER_ONLY, "Encipher Only " },
            { KeyUsageExtension.DECIPHER_ONLY, "Decipher Only " },
            { TOKEN_CERT_USAGE, "Certificate Usage: " },
            { NSCertTypeExtension.SSL_CLIENT, "SSL Client " },
            { NSCertTypeExtension.SSL_SERVER, "SSL Server " },
            { NSCertTypeExtension.EMAIL, "Secure Email " },
            { NSCertTypeExtension.OBJECT_SIGNING, "Object Signing " },
            { NSCertTypeExtension.SSL_CA, "SSL CA " },
            { NSCertTypeExtension.EMAIL_CA, "Secure Email CA " },
            { NSCertTypeExtension.OBJECT_SIGNING_CA, "ObjectSigning CA " },
            { TOKEN_KEY_ID, "Key Identifier: " },
            { TOKEN_AUTH_NAME, "Authority Name: " },
            { TOKEN_CRL, "Certificate Revocation List: " },
            { TOKEN_THIS_UPDATE, "This Update: " },
            { TOKEN_NEXT_UPDATE, "Next Update: " },
            { TOKEN_REVOKED_CERTIFICATES, "Revoked Certificates: " },
            { TOKEN_REVOCATION_DATE, "Revocation Date: " },
            { TOKEN_REVOCATION_REASON, "Revocation Reason " },
            { TOKEN_REASON, "Reason: " },
            { TOKEN_BASIC_CONSTRAINTS, "Basic Constraints " },
            { TOKEN_NAME_CONSTRAINTS, "Name Constraints " },
            { TOKEN_NSC_COMMENT, "Netscape Comment " },
            { TOKEN_IS_CA, "Is CA: " },
            { TOKEN_PATH_LEN, "Path Length Constraint: " },
            { TOKEN_PATH_LEN_UNLIMITED, "UNLIMITED" },
            { TOKEN_PATH_LEN_UNDEFINED, "UNDEFINED" },
            { TOKEN_PATH_LEN_INVALID, "INVALID" },
            { TOKEN_CRL_NUMBER, "CRL Number " },
            { TOKEN_NUMBER, "Number: " },
            { TOKEN_DELTA_CRL_INDICATOR, "Delta CRL Indicator " },
            { TOKEN_BASE_CRL_NUMBER, "Base CRL Number: " },
            { TOKEN_CERT_SCOPE_OF_USE, "Certificate Scope of Use " },
            { TOKEN_SCOPE_OF_USE, "Scope of Use: " },
            { TOKEN_PORT, "Port: " },
            { TOKEN_ISSUER_ALT_NAME, "Issuer Alternative Name " },
            { TOKEN_ISSUER_NAMES, "Issuer Names: " },
            { TOKEN_SUBJECT_ALT_NAME, "Subject Alternative Name " },
            { TOKEN_DECODING_ERROR, "Decoding Error" },
            { TOKEN_FRESHEST_CRL_EXT, "Freshest CRL " },
            { TOKEN_CRL_DP_EXT, "CRL Distribution Points " },
            { TOKEN_CRLDP_NUMPOINTS, "Number of Points: " },
            { TOKEN_CRLDP_POINTN, "Point " },
            { TOKEN_CRLDP_DISTPOINT, "Distribution Point: " },
            { TOKEN_CRLDP_REASONS, "Reason Flags: " },
            { TOKEN_CRLDP_CRLISSUER, "CRL Issuer: " },
            { TOKEN_ISSUING_DIST_POINT, "Issuing Distribution Point " },
            { TOKEN_DIST_POINT_NAME, "Distribution Point: " },
            { TOKEN_FULL_NAME, "Full Name: " },
            { TOKEN_RELATIVE_NAME, "Name Relative To CRL Issuer: " },
            { TOKEN_ONLY_USER_CERTS, "Only Contains User Certificates: " },
            { TOKEN_ONLY_CA_CERTS, "Only Contains CA Certificates: " },
            { TOKEN_ONLY_SOME_REASONS, "Only Some Reasons: " },
            { TOKEN_INDIRECT_CRL, "Indirect CRL: " },
            { TOKEN_INVALIDITY_DATE, "Invalidity Date " },
            { TOKEN_DATE_OF_INVALIDITY, "Invalidity Date: " },
            { TOKEN_CERTIFICATE_ISSUER, "Certificate Issuer " },
            { TOKEN_HOLD_INSTRUCTION, "Hold Instruction Code " },
            { TOKEN_HOLD_INSTRUCTION_CODE, "Hold Instruction Code: " },
            { TOKEN_POLICY_CONSTRAINTS, "Policy Constraints " },
            { TOKEN_INHIBIT_POLICY_MAPPING, "Inhibit Policy Mapping: " },
            { TOKEN_REQUIRE_EXPLICIT_POLICY, "Require Explicit Policy: " },
            { TOKEN_POLICY_MAPPINGS, "Policy Mappings " },
            { TOKEN_MAPPINGS, "Mappings: " },
            { TOKEN_MAP, "Map " },
            { TOKEN_ISSUER_DOMAIN_POLICY, "Issuer Domain Policy: " },
            { TOKEN_SUBJECT_DOMAIN_POLICY, "Subject Domain Policy: " },
            { TOKEN_SUBJECT_DIR_ATTR, "Subject Directory Attributes " },
            { TOKEN_ATTRIBUTES, "Attributes:" },
            { TOKEN_ATTRIBUTE, "Attribute " },
            { TOKEN_VALUES, "Values: " },
            { TOKEN_NOT_SET, "not set" },
            { TOKEN_NONE, "none" },
            { TOKEN_CACHE_NOT_AVAILABLE, "CRL cache is not available. " },
            { TOKEN_CACHE_IS_EMPTY, "CRL cache is empty. " },
        };

}
