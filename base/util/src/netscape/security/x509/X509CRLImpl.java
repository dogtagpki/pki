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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.Set;

import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * <p>
 * An implmentation for X509 CRL (Certificate Revocation List).
 * <p>
 * The X.509 v2 CRL format is described below in ASN.1:
 *
 * <pre>
 * </pre>
 * <p>
 * CertificateList ::= SEQUENCE { tbsCertList TBSCertList, signatureAlgorithm AlgorithmIdentifier, signature BIT STRING
 * }
 * <p>
 * A good description and profiling is provided in the IETF PKIX WG draft, Part I: X.509 Certificate and CRL Profile,
 * &lt;draft-ietf-pkix-ipki-part1-06.txt&gt;.
 * <p>
 * The ASN.1 definition of <code>tbsCertList</code> is:
 *
 * <pre>
 * TBSCertList  ::=  SEQUENCE  {
 *     version                 Version OPTIONAL,
 *                             -- if present, must be v2
 *     signature               AlgorithmIdentifier,
 *     issuer                  Name,
 *     thisUpdate              ChoiceOfTime,
 *     nextUpdate              ChoiceOfTime OPTIONAL,
 *     revokedCertificates     SEQUENCE OF SEQUENCE  {
 *         userCertificate         CertificateSerialNumber,
 *         revocationDate          ChoiceOfTime,
 *         crlEntryExtensions      Extensions OPTIONAL
 *                                 -- if present, must be v2
 *         }  OPTIONAL,
 *     crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                  -- if present, must be v2
 *     }
 * </pre>
 *
 * @author Hemma Prafullchandra
 * @version 1.8
 * @see X509CRL
 */
public class X509CRLImpl extends X509CRL {

    // CRL data, and its envelope
    private byte[] signedCRL = null; // DER encoded crl
    private byte[] signature = null; // raw signature bits
    private byte[] tbsCertList = null; // DER encoded "to-be-signed" CRL
    private AlgorithmId sigAlgId; // sig alg in CRL

    // crl information
    private int version;
    private AlgorithmId infoSigAlgId; // sig alg in "to-be-signed" crl
    private X500Name issuer;
    private Date thisUpdate = null;
    private Date nextUpdate = null;
    //    private static final Hashtable revokedCerts = new Hashtable();
    private Hashtable<BigInteger, RevokedCertificate> revokedCerts = new Hashtable<BigInteger, RevokedCertificate>();
    //    private static CRLExtensions    extensions = null;
    private CRLExtensions extensions = null;
    private boolean entriesIncluded = true;
    private final static boolean isExplicit = true;

    private boolean readOnly = false;

    /**
     * Unmarshals an X.509 CRL from its encoded form, parsing the encoded
     * bytes. This form of constructor is used by agents which
     * need to examine and use CRL contents. Note that the buffer
     * must include only one CRL, and no "garbage" may be left at
     * the end.
     *
     * @param crlData the encoded bytes, with no trailing padding.
     * @exception CRLException on parsing errors.
     * @exception X509ExtensionException on extension handling errors.
     */
    public X509CRLImpl(byte[] crlData)
            throws CRLException, X509ExtensionException {
        try {
            DerValue in = new DerValue(crlData);

            parse(in);
            signedCRL = crlData;
        } catch (IOException e) {
            throw new CRLException("Parsing error: " + e.getMessage());
        }
    }

    public X509CRLImpl(byte[] crlData, boolean includeEntries)
            throws CRLException, X509ExtensionException {
        try {
            entriesIncluded = includeEntries;
            DerValue in = new DerValue(crlData);

            parse(in, includeEntries);
            signedCRL = crlData;
        } catch (IOException e) {
            throw new CRLException("Parsing error: " + e.getMessage());
        }
    }

    /**
     * Unmarshals an X.509 CRL from an input stream. Only one CRL
     * is expected at the end of the input stream.
     *
     * @param inStrm an input stream holding at least one CRL
     * @exception CRLException on parsing errors.
     * @exception X509ExtensionException on extension handling errors.
     */
    public X509CRLImpl(InputStream inStrm)
            throws CRLException, X509ExtensionException {
        try {
            DerValue val = new DerValue(inStrm);

            parse(val);
            signedCRL = val.toByteArray();
        } catch (IOException e) {
            throw new CRLException("Parsing error: " + e.getMessage());
        }
    }

    /**
     * Initial CRL constructor, no revoked certs, and no extensions.
     *
     * @param issuer the name of the CA issuing this CRL.
     * @param thisUpdate the Date of this issue.
     * @param nextUpdate the Date of the next CRL.
     */
    public X509CRLImpl(X500Name issuer, Date thisDate, Date nextDate) {
        this.issuer = issuer;
        this.thisUpdate = thisDate;
        this.nextUpdate = nextDate;
    }

    /**
     * CRL constructor, revoked certs, no extensions.
     *
     * @param issuer the name of the CA issuing this CRL.
     * @param thisUpdate the Date of this issue.
     * @param nextUpdate the Date of the next CRL.
     * @param badCerts the array of revoked certificates.
     *
     * @exception CRLException on parsing/construction errors.
     * @exception X509ExtensionException on extension handling errors.
     */
    public X509CRLImpl(X500Name issuer, Date thisDate, Date nextDate,
                       RevokedCertificate[] badCerts)
            throws CRLException, X509ExtensionException {
        this.issuer = issuer;
        this.thisUpdate = thisDate;
        this.nextUpdate = nextDate;
        if (badCerts != null) {
            for (int i = 0; i < badCerts.length; i++)
                this.revokedCerts.put(badCerts[i].getSerialNumber(),
                                 badCerts[i]);
        }
    }

    /**
     * CRL constructor, revoked certs and extensions.
     *
     * @param issuer the name of the CA issuing this CRL.
     * @param thisUpdate the Date of this issue.
     * @param nextUpdate the Date of the next CRL.
     * @param badCerts the array of revoked certificates.
     * @param crlExts the CRL extensions.
     *
     * @exception CRLException on parsing/construction errors.
     * @exception X509ExtensionException on extension handling errors.
     */
    public X509CRLImpl(X500Name issuer, Date thisDate, Date nextDate,
               RevokedCertificate[] badCerts, CRLExtensions crlExts)
            throws CRLException, X509ExtensionException {
        this.issuer = issuer;
        this.thisUpdate = thisDate;
        this.nextUpdate = nextDate;
        if (badCerts != null) {
            for (int i = 0; i < badCerts.length; i++) {
                if (badCerts[i] != null) {
                    this.revokedCerts.put(badCerts[i].getSerialNumber(),
                                          badCerts[i]);
                    if (badCerts[i].hasExtensions())
                        this.version = 1;
                }
            }
        }
        if (crlExts != null) {
            this.extensions = crlExts;
            this.version = 1;
        }
    }

    /**
     * CRL constructor, revoked certs and extensions.
     * This will be used by code that constructs CRL and uses
     * encodeInfo() in order to sign it using external means
     * (other than sign() method)
     *
     * @param issuer the name of the CA issuing this CRL.
     * @param sigAlg signing algorithm id
     * @param thisUpdate the Date of this issue.
     * @param nextUpdate the Date of the next CRL.
     * @param badCerts the array of revoked certificates.
     * @param crlExts the CRL extensions.
     */
    public X509CRLImpl(X500Name issuer, AlgorithmId algId, Date thisDate, Date nextDate,
               RevokedCertificate[] badCerts, CRLExtensions crlExts)
            throws CRLException, X509ExtensionException {
        this(issuer, thisDate, nextDate, badCerts, crlExts);
        infoSigAlgId = algId;
    }

    /**
     * CRL constructor, revoked certs and extensions.
     *
     * @param issuer the name of the CA issuing this CRL.
     * @param sigAlg signing algorithm id
     * @param thisUpdate the Date of this issue.
     * @param nextUpdate the Date of the next CRL.
     * @param badCerts the hashtable of revoked certificates.
     * @param crlExts the CRL extensions.
     *
     * @exception CRLException on parsing/construction errors.
     * @exception X509ExtensionException on extension handling errors.
     */
    public X509CRLImpl(X500Name issuer, AlgorithmId algId,
                       Date thisDate, Date nextDate,
                       Hashtable<BigInteger, RevokedCertificate> badCerts, CRLExtensions crlExts)
            throws CRLException, X509ExtensionException {
        this.issuer = issuer;
        this.thisUpdate = thisDate;
        this.nextUpdate = nextDate;
        this.revokedCerts = badCerts;
        if (crlExts != null) {
            this.extensions = crlExts;
            this.version = 1;
        }
        infoSigAlgId = algId;
    }

    /**
     * Returns the ASN.1 DER encoded form of this CRL.
     *
     * @exception CRLException if an encoding error occurs.
     */
    public byte[] getEncoded() throws CRLException {
        if (signedCRL == null)
            throw new CRLException("Null CRL to encode");
        byte[] dup = new byte[signedCRL.length];
        System.arraycopy(signedCRL, 0, dup, 0, dup.length);
        return dup;
    }

    /**
     * Returns true if signedCRL was set.
     *
     * @param byte array of containing signed CRL.
     */
    public boolean setSignedCRL(byte[] crl) {
        boolean done = false;
        if (tbsCertList != null && signedCRL == null) {
            signedCRL = new byte[crl.length];
            System.arraycopy(crl, 0, signedCRL, 0, signedCRL.length);
            done = true;
        }
        return done;
    }

    public boolean hasUnsupportedCriticalExtension() {
        // XXX NOT IMPLEMENTED
        return true;
    }

    /**
     * Encodes the "to-be-signed" CRL to the OutputStream.
     *
     * @param out the OutputStream to write to.
     * @exception CRLException on encoding errors.
     * @exception X509ExtensionException on extension encoding errors.
     */
    public void encodeInfo(OutputStream out)
            throws CRLException, X509ExtensionException {
        try (DerOutputStream seq = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();
            DerOutputStream rCerts = new DerOutputStream();

            if (version != 0) // v2 crl encode version
                tmp.putInteger(new BigInt(version));
            infoSigAlgId.encode(tmp);
            issuer.encode(tmp);

            // from 2050 should encode GeneralizedTime
            tmp.putUTCTime(thisUpdate);

            if (nextUpdate != null)
                tmp.putUTCTime(nextUpdate);

            if (!revokedCerts.isEmpty()) {
                for (Enumeration<RevokedCertificate> e = revokedCerts.elements(); e.hasMoreElements();)
                    ((RevokedCertImpl) e.nextElement()).encode(rCerts);
                tmp.write(DerValue.tag_Sequence, rCerts);
            }

            if (extensions != null)
                extensions.encode(tmp, isExplicit);

            seq.write(DerValue.tag_Sequence, tmp);

            tbsCertList = seq.toByteArray();
            out.write(tbsCertList);
        } catch (IOException e) {
            throw new CRLException("Encoding error: " + e.getMessage());
        }
    }

    /**
     * Verifies that this CRL was signed using the
     * private key that corresponds to the specified public key.
     *
     * @param key the PublicKey used to carry out the verification.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     *                algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException if there's no default provider.
     * @exception SignatureException on signature errors.
     * @exception CRLException on encoding errors.
     */
    public void verify(PublicKey key)
            throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException {
        verify(key, null);
    }

    /**
     * Verifies that this CRL was signed using the
     * private key that corresponds to the specified public key,
     * and that the signature verification was computed by
     * the given provider.
     *
     * @param key the PublicKey used to carry out the verification.
     * @param sigProvider the name of the signature provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     *                algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CRLException on encoding errors.
     */
    public void verify(PublicKey key, String sigProvider)
            throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException {
        if (signedCRL == null) {
            throw new CRLException("Uninitialized CRL");
        }
        Signature sigVerf = null;

        String sigAlg = sigAlgId.getName();
        if (sigProvider != null && sigProvider.equals("Mozilla-JSS")) {
            if (sigAlg.equals("MD5withRSA")) {
                sigAlg = "MD5/RSA";
            } else if (sigAlg.equals("MD2withRSA")) {
                sigAlg = "MD2/RSA";
            } else if (sigAlg.equals("SHA1withRSA")) {
                sigAlg = "SHA1/RSA";
            } else if (sigAlg.equals("SHA1withDSA")) {
                sigAlg = "SHA1/DSA";
            } else if (sigAlg.equals("SHA1withEC")) {
                sigAlg = "SHA1/EC";
            } else if (sigAlg.equals("SHA256withEC")) {
                sigAlg = "SHA256/EC";
            } else if (sigAlg.equals("SHA384withEC")) {
                sigAlg = "SHA384/EC";
            } else if (sigAlg.equals("SHA512withEC")) {
                sigAlg = "SHA512/EC";
            }
        }
        sigVerf = Signature.getInstance(sigAlg, sigProvider);
        sigVerf.initVerify(key);

        if (tbsCertList == null)
            throw new CRLException("Uninitialized CRL");

        sigVerf.update(tbsCertList, 0, tbsCertList.length);

        if (!sigVerf.verify(signature)) {
            throw new CRLException("Signature does not match.");
        }
    }

    /**
     * Encodes an X.509 CRL, and signs it using the key
     * passed.
     *
     * @param key the private key used for signing.
     * @param algorithm the name of the signature algorithm used.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     *                algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CRLException if any mandatory data was omitted.
     * @exception X509ExtensionException on any extension errors.
     */
    public void sign(PrivateKey key, String algorithm)
            throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException, X509ExtensionException {
        sign(key, algorithm, null);
    }

    /**
     * Encodes an X.509 CRL, and signs it using the key
     * passed.
     *
     * @param key the private key used for signing.
     * @param algorithm the name of the signature algorithm used.
     * @param provider the name of the provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     *                algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CRLException if any mandatory data was omitted.
     * @exception X509ExtensionException on any extension errors.
     */
    public void sign(PrivateKey key, String algorithm, String provider)
            throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException, X509ExtensionException {
        try (DerOutputStream out = new DerOutputStream()){
            if (readOnly)
                throw new CRLException("cannot over-write existing CRL");
            Signature sigEngine = null;
            if (provider == null)
                sigEngine = Signature.getInstance(algorithm);
            else
                sigEngine = Signature.getInstance(algorithm, provider);

            sigEngine.initSign(key);

            // in case the name is reset
            sigAlgId = AlgorithmId.get(sigEngine.getAlgorithm());
            infoSigAlgId = sigAlgId;

            DerOutputStream tmp = new DerOutputStream();

            // encode crl info
            encodeInfo(tmp);

            // encode algorithm identifier
            sigAlgId.encode(tmp);

            // Create and encode the signature itself.
            sigEngine.update(tbsCertList, 0, tbsCertList.length);
            signature = sigEngine.sign();
            tmp.putBitString(signature);

            // Wrap the signed data in a SEQUENCE { data, algorithm, sig }
            out.write(DerValue.tag_Sequence, tmp);
            signedCRL = out.toByteArray();
            readOnly = true;

        } catch (IOException e) {
            throw new CRLException("Error while encoding data: " +
                                   e.getMessage());
        }
    }

    /**
     * Returns a printable string of this CRL.
     *
     * @return value of this CRL in a printable form.
     */
    public String toString() {
        StringBuffer sb = new StringBuffer("X.509 CRL v" + (version + 1) + "\n" + "Signature Algorithm: " + sigAlgId +
                ", OID=" + sigAlgId.getOID() + "\n" + "Issuer: " + issuer + "\n" + "\nThis Update: " + thisUpdate
                + "\n");
        if (nextUpdate != null)
            sb.append("Next Update: " + nextUpdate + "\n");
        if (revokedCerts.isEmpty())
            sb.append("\nNO certificates have been revoked\n");
        else {
            sb.append("\nRevoked Certificates:\n");
            for (Enumeration<RevokedCertificate> e = revokedCerts.elements(); e.hasMoreElements();)
                sb.append(e.nextElement());
        }
        if (extensions != null) {
            for (int i = 0; i < extensions.size(); i++) {
                sb.append("\nCRL Extension[" + i + "]: " + extensions.elementAt(i));
            }
        }
        netscape.security.util.PrettyPrintFormat pp =
                new netscape.security.util.PrettyPrintFormat(" ", 20);
        String signaturebits = pp.toHexString(signature);
        sb.append("\nSignature:\n" + signaturebits);

        return sb.toString();
    }

    /**
     * Checks whether the given serial number is on this CRL.
     *
     * @param serialNumber the number to check for.
     * @return true if the given serial number is on this CRL,
     *         false otherwise.
     */
    public boolean isRevoked(BigInteger serialNumber) {
        if (revokedCerts == null || revokedCerts.isEmpty())
            return false;
        return revokedCerts.containsKey(serialNumber);
    }

    public boolean isRevoked(Certificate cert) {
        if (cert == null)
            return false;
        if (cert instanceof X509Certificate) {
            return isRevoked(((X509Certificate) cert).getSerialNumber());
        } else {
            return false;
        }
    }

    /**
     * Gets the version number from the CRL.
     * The ASN.1 definition for this is:
     *
     * <pre>
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     *             -- v3 does not apply to CRLs but appears for consistency
     *             -- with definition of Version for certs
     * </pre>
     *
     * @return the version number.
     */
    public int getVersion() {
        return version;
    }

    /**
     * Gets the issuer distinguished name from this CRL.
     * The issuer name identifies the entity who has signed (and
     * issued the CRL). The issuer name field contains an
     * X.500 distinguished name (DN).
     * The ASN.1 definition for this is:
     *
     * <pre>
     * issuer    Name
     *
     * Name ::= CHOICE { RDNSequence }
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     * RelativeDistinguishedName ::=
     *     SET OF AttributeValueAssertion
     *
     * AttributeValueAssertion ::= SEQUENCE {
     *                               AttributeType,
     *                               AttributeValue }
     * AttributeType ::= OBJECT IDENTIFIER
     * AttributeValue ::= ANY
     * </pre>
     *
     * The Name describes a hierarchical name composed of attributes,
     * such as country name, and corresponding values, such as US.
     * The type of the component AttributeValue is determined by the
     * AttributeType; in general it will be a directoryString.
     * A directoryString is usually one of PrintableString,
     * TeletexString or UniversalString.
     *
     * @return the issuer name.
     */
    public Principal getIssuerDN() {
        return issuer;
    }

    /**
     * Gets the thisUpdate date from the CRL.
     * The ASN.1 definition for this is:
     *
     * @return the thisUpdate date from the CRL.
     */
    public Date getThisUpdate() {
        return (new Date(thisUpdate.getTime()));
    }

    /**
     * Gets the nextUpdate date from the CRL.
     *
     * @return the nextUpdate date from the CRL, or null if
     *         not present.
     */
    public Date getNextUpdate() {
        if (nextUpdate == null)
            return null;
        return (new Date(nextUpdate.getTime()));
    }

    /**
     * Get the revoked certificate from the CRL by the serial
     * number provided.
     *
     * @return the revoked certificate or null if there is
     *         no entry in the CRL marked with the provided serial number.
     * @see RevokedCertificate
     */
    public X509CRLEntry getRevokedCertificate(BigInteger serialNumber) {
        if (revokedCerts == null || revokedCerts.isEmpty())
            return null;
        return revokedCerts.get(serialNumber);
    }

    /**
     * Gets all the revoked certificates from the CRL.
     * A Set of RevokedCertificate.
     *
     * @return all the revoked certificates or null if there are
     *         none.
     * @see RevokedCertificate
     */
    public Set<RevokedCertificate> getRevokedCertificates() {
        if (revokedCerts == null || revokedCerts.isEmpty())
            return null;
        else {
            Set<RevokedCertificate> certSet = new LinkedHashSet<RevokedCertificate>(revokedCerts.values());
            return certSet;
        }
    }

    @SuppressWarnings("unchecked")
    public Hashtable<BigInteger, RevokedCertificate> getListOfRevokedCertificates() {
        if (revokedCerts == null) {
            return null;
        } else {
            return (Hashtable<BigInteger, RevokedCertificate>) revokedCerts.clone();
        }
    }

    public int getNumberOfRevokedCertificates() {
        if (revokedCerts == null)
            return -1;
        else
            return revokedCerts.size();
    }

    /**
     * Gets the DER encoded CRL information, the <code>tbsCertList</code> from this CRL.
     * This can be used to verify the signature independently.
     *
     * @return the DER encoded CRL information.
     * @exception CRLException on parsing errors.
     * @exception X509ExtensionException on extension parsing errors.
     */
    public byte[] getTBSCertList()
            throws CRLException {
        if (tbsCertList == null)
            throw new CRLException("Uninitialized CRL");
        byte[] dup = new byte[tbsCertList.length];
        System.arraycopy(tbsCertList, 0, dup, 0, dup.length);
        return dup;
    }

    /**
     * Gets the raw Signature bits from the CRL.
     *
     * @return the signature.
     */
    public byte[] getSignature() {
        if (signature == null)
            return null;
        byte[] dup = new byte[signature.length];
        System.arraycopy(signature, 0, dup, 0, dup.length);
        return dup;
    }

    /**
     * Returns true if signature was set.
     *
     * @param byte array of containing CRL signature.
     */
    public boolean setSignature(byte[] crlSignature) {
        boolean done = false;
        if (tbsCertList != null && signature == null) {
            signature = new byte[crlSignature.length];
            System.arraycopy(crlSignature, 0, signature, 0, signature.length);
            done = true;
        }
        return done;
    }

    /**
     * Gets the signature algorithm name for the CRL
     * signature algorithm. For example, the string "SHA1withDSA".
     * The ASN.1 definition for this is:
     *
     * <pre>
     * AlgorithmIdentifier  ::=  SEQUENCE  {
     *     algorithm               OBJECT IDENTIFIER,
     *     parameters              ANY DEFINED BY algorithm OPTIONAL  }
     *                             -- contains a value of the type
     *                             -- registered for use with the
     *                             -- algorithm object identifier value
     * </pre>
     *
     * @return the signature algorithm name.
     */
    public String getSigAlgName() {
        if (sigAlgId == null)
            return null;
        return sigAlgId.getName();
    }

    /**
     * Gets the signature algorithm OID string from the CRL.
     * An OID is represented by a set of positive whole number separated
     * by ".", that means,<br>
     * &lt;positive whole number&gt;.&lt;positive whole number&gt;.&lt;...&gt;
     * For example, the string "1.2.840.10040.4.3" identifies the SHA-1
     * with DSA signature algorithm, as per the PKIX part I.
     *
     * @return the signature algorithm oid string.
     */
    public String getSigAlgOID() {
        if (sigAlgId == null)
            return null;
        ObjectIdentifier oid = sigAlgId.getOID();
        return oid.toString();
    }

    /**
     * Gets the DER encoded signature algorithm parameters from this
     * CRL's signature algorithm. In most cases, the signature
     * algorithm parameters are null, the parameters are usually
     * supplied with the Public Key.
     *
     * @return the DER encoded signature algorithm parameters, or
     *         null if no parameters are present.
     */
    public byte[] getSigAlgParams() {
        if (sigAlgId == null)
            return null;
        try {
            return sigAlgId.getEncodedParams();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Gets a Set of the extension(s) marked CRITICAL in the
     * CRL by OID strings.
     *
     * @return a set of the extension oid strings in the
     *         CRL that are marked critical.
     */
    public Set<String> getCriticalExtensionOIDs() {
        if (extensions == null)
            return null;
        Set<String> extSet = new LinkedHashSet<String>();
        Extension ex;
        for (Enumeration<Extension> e = extensions.getElements(); e.hasMoreElements();) {
            ex = e.nextElement();
            if (ex.isCritical()) {
                extSet.add(ex.getExtensionId().toString());
            }
        }
        return extSet;
    }

    /**
     * Gets a Set of the extension(s) marked NON-CRITICAL in the
     * CRL by OID strings.
     *
     * @return a set of the extension oid strings in the
     *         CRL that are NOT marked critical.
     */
    public Set<String> getNonCriticalExtensionOIDs() {
        if (extensions == null)
            return null;
        Set<String> extSet = new LinkedHashSet<String>();
        Extension ex;
        for (Enumeration<Extension> e = extensions.getElements(); e.hasMoreElements();) {
            ex = e.nextElement();
            if (!ex.isCritical())
                extSet.add(ex.getExtensionId().toString());
        }
        return extSet;
    }

    /**
     * Gets the DER encoded OCTET string for the extension value
     * (<code>extnValue</code>) identified by the passed in oid String.
     * The <code>oid</code> string is
     * represented by a set of positive whole number separated
     * by ".", that means,<br>
     * &lt;positive whole number&gt;.&lt;positive whole number&gt;.&lt;...&gt;
     *
     * @param oid the Object Identifier value for the extension.
     * @return the der encoded octet string of the extension value.
     */
    public byte[] getExtensionValue(String oid) {
        if (extensions == null)
            return null;
        try (DerOutputStream out = new DerOutputStream()) {
            String extAlias = OIDMap.getName(new ObjectIdentifier(oid));
            Extension crlExt = null;

            if (extAlias == null) { // may be unknown
                ObjectIdentifier findOID = new ObjectIdentifier(oid);
                Extension ex = null;
                ObjectIdentifier inCertOID;
                for (Enumeration<Extension> e = extensions.getElements(); e.hasMoreElements();) {
                    ex = e.nextElement();
                    inCertOID = ex.getExtensionId();
                    if (inCertOID.equals(findOID)) {
                        crlExt = ex;
                        break;
                    }
                }
            } else
                crlExt = extensions.get(extAlias);
            if (crlExt == null)
                return null;
            byte[] extData = crlExt.getExtensionValue();
            if (extData == null)
                return null;

            out.putOctetString(extData);
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    public BigInteger getCRLNumber() {
        try {
            CRLExtensions exts = getExtensions();
            if (exts == null)
                return null;
            Enumeration<Extension> e = exts.getElements();
            while (e.hasMoreElements()) {
                Extension ext = e.nextElement();
                if (ext instanceof CRLNumberExtension) {
                    CRLNumberExtension numExt = (CRLNumberExtension) ext;
                    return (BigInteger) numExt.get(CRLNumberExtension.NUMBER);
                }
            }
        } catch (Exception e) {
        }
        return null;
    }

    public BigInteger getDeltaBaseCRLNumber() {
        try {
            CRLExtensions exts = getExtensions();
            if (exts == null)
                return null;
            Enumeration<Extension> e = exts.getElements();
            while (e.hasMoreElements()) {
                Extension ext = e.nextElement();
                if (ext instanceof DeltaCRLIndicatorExtension) {
                    DeltaCRLIndicatorExtension numExt = (DeltaCRLIndicatorExtension) ext;
                    return (BigInteger) numExt.get(DeltaCRLIndicatorExtension.NUMBER);
                }
            }
        } catch (Exception e) {
        }
        return null;
    }

    public boolean isDeltaCRL() {
        try {
            CRLExtensions exts = getExtensions();
            if (exts == null)
                return false;
            Enumeration<Extension> e = exts.getElements();
            while (e.hasMoreElements()) {
                Extension ext = e.nextElement();
                if (ext instanceof DeltaCRLIndicatorExtension) {
                    return true;
                }
            }
        } catch (Exception e) {
        }
        return false;
    }

    /**
     * Returns extensions for this impl.
     *
     * @param extn CRLExtensions
     */
    public CRLExtensions getExtensions() {
        return extensions;
    }

    public boolean areEntriesIncluded() {
        return entriesIncluded;
    }

    /*********************************************************************/
    /*
     * Parses an X.509 CRL, should be used only by constructors.
     */
    private void parse(DerValue val)
            throws CRLException, IOException, X509ExtensionException {
        parse(val, true);
    }

    private void parse(DerValue val, boolean includeEntries)
            throws CRLException, IOException, X509ExtensionException {
        // check if can over write the certificate
        if (readOnly)
            throw new CRLException("cannot over-write existing CRL");

        readOnly = true;
        DerValue seq[] = new DerValue[3];

        seq[0] = val.data.getDerValue();
        seq[1] = val.data.getDerValue();
        seq[2] = val.data.getDerValue();

        if (val.data.available() != 0)
            throw new CRLException("signed overrun, bytes = "
                                     + val.data.available());

        if (seq[0].tag != DerValue.tag_Sequence)
            throw new CRLException("signed CRL fields invalid");

        sigAlgId = AlgorithmId.parse(seq[1]);
        signature = seq[2].getBitString();

        if (seq[1].data.available() != 0)
            throw new CRLException("AlgorithmId field overrun");

        if (seq[2].data.available() != 0)
            throw new CRLException("Signature field overrun");

        // the tbsCertsList
        tbsCertList = seq[0].toByteArray();

        // parse the information
        DerInputStream derStrm = seq[0].data;
        DerValue tmp;
        byte nextByte;

        // version (optional if v1)
        version = 0; // by default, version = v1 == 0
        nextByte = (byte) derStrm.peekByte();
        if (nextByte == DerValue.tag_Integer) {
            version = derStrm.getInteger().toInt();
            if (version != 1) // i.e. v2
                throw new CRLException("Invalid version");
        }
        tmp = derStrm.getDerValue();
        // signature
        {
            AlgorithmId tmpId = AlgorithmId.parse(tmp);
            if (!tmpId.equals(sigAlgId))
                throw new CRLException("Signature algorithm mismatch");

            infoSigAlgId = tmpId;
        }
        // issuer
        issuer = new X500Name(derStrm);

        // thisUpdate
        // check if UTCTime encoded or GeneralizedTime

        nextByte = (byte) derStrm.peekByte();
        if (nextByte == DerValue.tag_UtcTime) {
            thisUpdate = derStrm.getUTCTime();
        } else if (nextByte == DerValue.tag_GeneralizedTime) {
            thisUpdate = derStrm.getGeneralizedTime();
        } else {
            throw new CRLException("Invalid encoding for thisUpdate"
                                   + " (tag=" + nextByte + ")");
        }

        if (derStrm.available() == 0)
            return; // done parsing no more optional fields present

        // nextUpdate (optional)
        nextByte = (byte) derStrm.peekByte();
        if (nextByte == DerValue.tag_UtcTime) {
            nextUpdate = derStrm.getUTCTime();
        } else if (nextByte == DerValue.tag_GeneralizedTime) {
            nextUpdate = derStrm.getGeneralizedTime();
        } // else it is not present

        if (derStrm.available() == 0)
            return; // done parsing no more optional fields present

        // revokedCertificates (optional)
        nextByte = (byte) derStrm.peekByte();
        if ((nextByte == DerValue.tag_SequenceOf)
                && (!((nextByte & 0x0c0) == 0x080))) {
            if (includeEntries) {
                DerValue[] badCerts = derStrm.getSequence(4);
                for (int i = 0; i < badCerts.length; i++) {
                    RevokedCertImpl entry = new RevokedCertImpl(badCerts[i]);
                    if (entry.hasExtensions() && (version == 0))
                        throw new CRLException("Invalid encoding, extensions" +
                                " not supported in CRL v1 entries.");

                    revokedCerts.put(entry.getSerialNumber(),
                                     entry);
                }
            } else {
                derStrm.skipSequence(4);
            }
        }

        if (derStrm.available() == 0)
            return; // done parsing no extensions

        // crlExtensions (optional)
        tmp = derStrm.getDerValue();
        if (tmp.isConstructed() && tmp.isContextSpecific((byte) 0)) {
            if (version == 0)
                throw new CRLException("Invalid encoding, extensions not" +
                                   " supported in CRL v1.");
            extensions = new CRLExtensions(tmp.data);
        }
    }
}
