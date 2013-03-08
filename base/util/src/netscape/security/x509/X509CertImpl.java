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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.Vector;

import netscape.security.util.DerEncoder;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * The X509CertImpl class represents an X.509 certificate. These certificates
 * are widely used to support authentication and other functionality in
 * Internet security systems. Common applications include Privacy Enhanced
 * Mail (PEM), Transport Layer Security (SSL), code signing for trusted
 * software distribution, and Secure Electronic Transactions (SET). There
 * is a commercial infrastructure ready to manage large scale deployments
 * of X.509 identity certificates.
 *
 * <P>
 * These certificates are managed and vouched for by <em>Certificate
 * Authorities</em> (CAs). CAs are services which create certificates by placing data in the X.509 standard format and
 * then digitally signing that data. Such signatures are quite difficult to forge. CAs act as trusted third parties,
 * making introductions between agents who have no direct knowledge of each other. CA certificates are either signed by
 * themselves, or by some other CA such as a "root" CA.
 *
 * <P>
 * RFC 1422 is very informative, though it does not describe much of the recent work being done with X.509 certificates.
 * That includes a 1996 version (X.509v3) and a variety of enhancements being made to facilitate an explosion of
 * personal certificates used as "Internet Drivers' Licences", or with SET for credit card transactions.
 *
 * <P>
 * More recent work includes the IETF PKIX Working Group efforts, especially part 1.
 *
 * @author Dave Brownell
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.94 97/12/10
 * @see X509CertInfo
 */
public class X509CertImpl extends X509Certificate
        implements Serializable, DerEncoder {
    // Serialization compatibility with the X509CertImpl in x509v1.jar
    // supporting the subset of X509Certificate on JDK1.1.x platforms.
    static final long serialVersionUID = -2048442350420423405L;

    private static final String DOT = ".";
    /**
     * Public attribute names.
     */
    public static final String NAME = "x509";
    public static final String INFO = X509CertInfo.NAME;
    public static final String ALG_ID = "algorithm";
    public static final String SIGNATURE = "signature";
    public static final String SIGNED_CERT = "signed_cert";

    /**
     * The following are defined for ease-of-use. These
     * are the most frequently retrieved attributes.
     */
    // x509.info.subject.dname
    public static final String SUBJECT_DN = NAME + DOT + INFO + DOT +
                               X509CertInfo.SUBJECT + DOT +
                               CertificateSubjectName.DN_NAME;
    // x509.info.issuer.dname
    public static final String ISSUER_DN = NAME + DOT + INFO + DOT +
                               X509CertInfo.ISSUER + DOT +
                               CertificateIssuerName.DN_NAME;
    // x509.info.serialNumber.number
    public static final String SERIAL_ID = NAME + DOT + INFO + DOT +
                               X509CertInfo.SERIAL_NUMBER + DOT +
                               CertificateSerialNumber.NUMBER;
    // x509.info.key.value
    public static final String PUBLIC_KEY = NAME + DOT + INFO + DOT +
                               X509CertInfo.KEY + DOT +
                               CertificateX509Key.KEY;

    // x509.algorithm
    public static final String SIG_ALG = NAME + DOT + ALG_ID;

    // x509.signature
    public static final String SIG = NAME + DOT + SIGNATURE;

    // when we sign and decode we set this to true
    // this is our means to make certificates immutable
    private boolean readOnly = false;

    // Certificate data, and its envelope
    private byte[] signedCert;
    protected X509CertInfo info = null;
    protected AlgorithmId algId;
    protected byte[] signature;

    // recognized extension OIDS
    private static final String KEY_USAGE_OID = "2.5.29.15";
    private static final String BASIC_CONSTRAINT_OID = "2.5.29.19";

    /**
     * Default constructor.
     */
    public X509CertImpl() {
    }

    /**
     * Unmarshals a certificate from its encoded form, parsing the
     * encoded bytes. This form of constructor is used by agents which
     * need to examine and use certificate contents. That is, this is
     * one of the more commonly used constructors. Note that the buffer
     * must include only a certificate, and no "garbage" may be left at
     * the end. If you need to ignore data at the end of a certificate,
     * use another constructor.
     *
     * @param certData the encoded bytes, with no trailing padding.
     * @exception CertificateException on parsing and initialization errors.
     */
    public X509CertImpl(byte[] certData)
            throws CertificateException {
        this(certData, null);
    }

    /**
     * As a special optimization, this constructor acts as X509CertImpl(byte[])
     * except that it takes an X509CertInfo which it uses as a 'hint' for
     * how to construct one field.
     *
     * @param certData the encode bytes, with no traiing padding
     * @param certInfo the certInfo which has already been constructed
     *            from the certData
     */

    public X509CertImpl(byte[] certData, X509CertInfo certInfo)
            throws CertificateException {

        // setting info here causes it to skip decoding in the parse()
        // method
        info = certInfo;

        try {
            DerValue in = new DerValue(certData);

            parse(in);
            signedCert = certData;
        } catch (IOException e) {
            throw new CertificateException("Unable to initialize, " + e);
        }
    }

    /**
     * unmarshals an X.509 certificate from an input stream.
     *
     * @param in an input stream holding at least one certificate
     * @exception CertificateException on parsing and initialization errors.
     */
    public X509CertImpl(InputStream in)
            throws CertificateException {
        try {
            DerValue val = new DerValue(in);

            parse(val);
            signedCert = val.toByteArray();
        } catch (IOException e) {
            throw new CertificateException("Unable to initialize, " + e);
        }
    }

    /**
     * Construct an initialized X509 Certificate. The certificate is stored
     * in raw form and has to be signed to be useful.
     *
     * @param certInfo the X509CertificateInfo which the Certificate is to be
     *            created from.
     */
    public X509CertImpl(X509CertInfo certInfo) {
        this.info = certInfo;
    }

    /**
     * Unmarshal a certificate from its encoded form, parsing a DER value.
     * This form of constructor is used by agents which need to examine
     * and use certificate contents.
     *
     * @param derVal the der value containing the encoded cert.
     * @exception CertificateException on parsing and initialization errors.
     */
    public X509CertImpl(DerValue derVal)
            throws CertificateException {
        try {
            parse(derVal);
            signedCert = derVal.toByteArray();
        } catch (IOException e) {
            throw new CertificateException("Unable to initialize, " + e);
        }
    }

    public boolean hasUnsupportedCriticalExtension() {
        // XXX NOT IMPLEMENTED
        return true;
    }

    /**
     * Decode an X.509 certificate from an input stream.
     *
     * @param in an input stream holding at least one certificate
     * @exception CertificateException on parsing errors.
     * @exception IOException on other errors.
     */
    public void decode(InputStream in)
            throws CertificateException, IOException {
        DerValue val = new DerValue(in);

        parse(val);
        signedCert = val.toByteArray();
    }

    /**
     * Appends the certificate to an output stream.
     *
     * @param out an input stream to which the certificate is appended.
     * @exception CertificateEncodingException on encoding errors.
     */
    public void encode(OutputStream out)
            throws CertificateEncodingException {
        if (signedCert == null)
            throw new CertificateEncodingException(
                          "Null certificate to encode");
        try {
            out.write(signedCert);
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    /**
     * DER encode this object onto an output stream.
     * Implements the <code>DerEncoder</code> interface.
     *
     * @param out
     *            the output stream on which to write the DER encoding.
     *
     * @exception IOException on encoding error.
     */
    public void derEncode(OutputStream out) throws IOException {
        if (signedCert == null)
            throw new IOException("Null certificate to encode");

        out.write(signedCert);
    }

    /**
     * Returns the encoded form of this certificate. It is
     * assumed that each certificate type would have only a single
     * form of encoding; for example, X.509 certificates would
     * be encoded as ASN.1 DER.
     *
     * @exception CertificateEncodingException if an encoding error occurs.
     */
    public byte[] getEncoded() throws CertificateEncodingException {
        if (signedCert == null)
            throw new CertificateEncodingException(
                          "Null certificate to encode");
        byte[] dup = new byte[signedCert.length];
        System.arraycopy(signedCert, 0, dup, 0, dup.length);
        return dup;
    }

    /**
     * Throws an exception if the certificate was not signed using the
     * verification key provided. Successfully verifying a certificate
     * does <em>not</em> indicate that one should trust the entity which
     * it represents.
     *
     * @param key the public key used for verification.
     *
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchAlgorithmException on unsupported signature
     *                algorithms.
     * @exception NoSuchProviderException if there's no default provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    public void verify(PublicKey key)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {

        verify(key, null);
    }

    /**
     * Throws an exception if the certificate was not signed using the
     * verification key provided. Successfully verifying a certificate
     * does <em>not</em> indicate that one should trust the entity which
     * it represents.
     *
     * @param key the public key used for verification.
     * @param sigProvider the name of the provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     *                algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    public void verify(PublicKey key, String sigProvider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        if (signedCert == null) {
            throw new CertificateEncodingException("Uninitialized certificate");
        }
        // Verify the signature ...
        Signature sigVerf = null;

        sigVerf = Signature.getInstance(algId.getName(), sigProvider);
        sigVerf.initVerify(key);

        byte[] rawCert = info.getEncodedInfo();
        sigVerf.update(rawCert, 0, rawCert.length);

        if (!sigVerf.verify(signature)) {
            throw new SignatureException("Signature does not match.");
        }
    }

    /**
     * Creates an X.509 certificate, and signs it using the key
     * passed (associating a signature algorithm and an X.500 name).
     * This operation is used to implement the certificate generation
     * functionality of a certificate authority.
     *
     * @param key the private key used for signing.
     * @param algorithm the name of the signature algorithm used.
     *
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchAlgorithmException on unsupported signature
     *                algorithms.
     * @exception NoSuchProviderException if there's no default provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    public void sign(PrivateKey key, String algorithm)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        sign(key, algorithm, null);
    }

    /**
     * Creates an X.509 certificate, and signs it using the key
     * passed (associating a signature algorithm and an X.500 name).
     * This operation is used to implement the certificate generation
     * functionality of a certificate authority.
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
     * @exception CertificateException on encoding errors.
     */
    public void sign(PrivateKey key, String algorithm, String provider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        try (DerOutputStream out = new DerOutputStream()){
            if (readOnly)
                throw new CertificateEncodingException(
                              "cannot over-write existing certificate");
            Signature sigEngine = null;
            if (provider == null)
                sigEngine = Signature.getInstance(algorithm);
            else
                sigEngine = Signature.getInstance(algorithm, provider);

            sigEngine.initSign(key);

            // in case the name is reset
            algId = AlgorithmId.get(sigEngine.getAlgorithm());

            DerOutputStream tmp = new DerOutputStream();

            // encode certificate info
            info.encode(tmp);
            byte[] rawCert = tmp.toByteArray();

            // encode algorithm identifier
            algId.encode(tmp);

            // Create and encode the signature itself.
            sigEngine.update(rawCert, 0, rawCert.length);
            signature = sigEngine.sign();
            tmp.putBitString(signature);

            // Wrap the signed data in a SEQUENCE { data, algorithm, sig }
            out.write(DerValue.tag_Sequence, tmp);
            signedCert = out.toByteArray();
            readOnly = true;

        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    /**
     * Checks that the certificate is currently valid, i.e. the current
     * time is within the specified validity period.
     *
     * @exception CertificateExpiredException if the certificate has expired.
     * @exception CertificateNotYetValidException if the certificate is not
     *                yet valid.
     */
    public void checkValidity()
            throws CertificateExpiredException, CertificateNotYetValidException {
        Date date = new Date();
        checkValidity(date);
    }

    /**
     * Checks that the specified date is within the certificate's
     * validity period, or basically if the certificate would be
     * valid at the specified date/time.
     *
     * @param date the Date to check against to see if this certificate
     *            is valid at that date/time.
     *
     * @exception CertificateExpiredException if the certificate has expired
     *                with respect to the <code>date</code> supplied.
     * @exception CertificateNotYetValidException if the certificate is not
     *                yet valid with respect to the <code>date</code> supplied.
     */
    public void checkValidity(Date date)
            throws CertificateExpiredException, CertificateNotYetValidException {

        CertificateValidity interval = null;
        try {
            interval = (CertificateValidity) info.get(CertificateValidity.NAME);
        } catch (Exception e) {
            throw new CertificateNotYetValidException("Incorrect validity period");
        }
        if (interval == null)
            throw new CertificateNotYetValidException("Null validity period");
        interval.valid(date);
    }

    /**
     * Return the requested attribute from the certificate.
     *
     * @param name the name of the attribute.
     * @exception CertificateParsingException on invalid attribute identifier.
     */
    public Object get(String name)
            throws CertificateParsingException {
        X509AttributeName attr = new X509AttributeName(name);
        String id = attr.getPrefix();
        if (!(id.equalsIgnoreCase(NAME))) {
            throw new CertificateParsingException("Invalid root of "
                          + "attribute name, expected [" + NAME +
                          "], received " + "[" + id + "]");
        }
        attr = new X509AttributeName(attr.getSuffix());
        id = attr.getPrefix();

        if (id.equalsIgnoreCase(INFO)) {
            if (attr.getSuffix() != null) {
                try {
                    return info.get(attr.getSuffix());
                } catch (IOException e) {
                    throw new CertificateParsingException(e.toString());
                } catch (CertificateException e) {
                    throw new CertificateParsingException(e.toString());
                }
            } else {
                return (info);
            }
        } else if (id.equalsIgnoreCase(ALG_ID)) {
            return (algId);
        } else if (id.equalsIgnoreCase(SIGNATURE)) {
            return (signature);
        } else if (id.equalsIgnoreCase(SIGNED_CERT)) {
            return (signedCert);
        } else {
            throw new CertificateParsingException("Attribute name not "
                    + "recognized or get() not allowed for the same: " + id);
        }
    }

    /**
     * Set the requested attribute in the certificate.
     *
     * @param name the name of the attribute.
     * @param obj the value of the attribute.
     * @exception CertificateException on invalid attribute identifier.
     * @exception IOException on encoding error of attribute.
     */
    public void set(String name, Object obj)
            throws CertificateException, IOException {
        // check if immutable
        if (readOnly)
            throw new CertificateException("cannot over-write existing"
                                           + " certificate");

        X509AttributeName attr = new X509AttributeName(name);
        String id = attr.getPrefix();
        if (!(id.equalsIgnoreCase(NAME))) {
            throw new CertificateException("Invalid root of attribute name,"
                           + " expected [" + NAME + "], received " + id);
        }
        attr = new X509AttributeName(attr.getSuffix());
        id = attr.getPrefix();

        if (id.equalsIgnoreCase(INFO)) {
            if (attr.getSuffix() == null) {
                if (!(obj instanceof X509CertInfo)) {
                    throw new CertificateException("Attribute value should"
                                    + " be of type X509CertInfo.");
                }
                info = (X509CertInfo) obj;
                signedCert = null; //reset this as certificate data has changed
            } else {
                info.set(attr.getSuffix(), obj);
                signedCert = null; //reset this as certificate data has changed
            }
        } else {
            throw new CertificateException("Attribute name not recognized or " +
                              "set() not allowed for the same: " + id);
        }
    }

    /**
     * Delete the requested attribute from the certificate.
     *
     * @param name the name of the attribute.
     * @exception CertificateException on invalid attribute identifier.
     * @exception IOException on other errors.
     */
    public void delete(String name)
            throws CertificateException, IOException {
        // check if immutable
        if (readOnly)
            throw new CertificateException("cannot over-write existing"
                                           + " certificate");

        X509AttributeName attr = new X509AttributeName(name);
        String id = attr.getPrefix();
        if (!(id.equalsIgnoreCase(NAME))) {
            throw new CertificateException("Invalid root of attribute name,"
                                   + " expected ["
                                   + NAME + "], received " + id);
        }
        attr = new X509AttributeName(attr.getSuffix());
        id = attr.getPrefix();

        if (id.equalsIgnoreCase(INFO)) {
            if (attr.getSuffix() != null) {
                info = null;
            } else {
                info.delete(attr.getSuffix());
            }
        } else if (id.equalsIgnoreCase(ALG_ID)) {
            algId = null;
        } else if (id.equalsIgnoreCase(SIGNATURE)) {
            signature = null;
        } else if (id.equalsIgnoreCase(SIGNED_CERT)) {
            signedCert = null;
        } else {
            throw new CertificateException("Attribute name not recognized or " +
                              "delete() not allowed for the same: " + id);
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(NAME + DOT + INFO);
        elements.addElement(NAME + DOT + ALG_ID);
        elements.addElement(NAME + DOT + SIGNATURE);
        elements.addElement(NAME + DOT + SIGNED_CERT);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    /**
     * Returns a printable representation of the certificate. This does not
     * contain all the information available to distinguish this from any
     * other certificate. The certificate must be fully constructed
     * before this function may be called.
     */
    public String toString() {
        if (info == null || algId == null || signature == null)
            return "";

        StringBuffer sb = new StringBuffer("[\n"+info.toString() + "\n" + "  Algorithm: [" + algId.toString() + "]\n");

        netscape.security.util.PrettyPrintFormat pp =
                new netscape.security.util.PrettyPrintFormat(" ", 20);
        String signaturebits = pp.toHexString(signature);
        sb.append("  Signature:\n" + signaturebits);
        sb.append("]");

        return sb.toString();
    }

    // the strongly typed gets, as per java.security.cert.X509Certificate

    /**
     * Gets the publickey from this certificate.
     *
     * @return the publickey.
     */
    public PublicKey getPublicKey() {
        if (info == null)
            return null;
        try {
            PublicKey key = (PublicKey) info.get(CertificateX509Key.NAME
                                 + DOT + CertificateX509Key.KEY);
            return key;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the version number from the certificate.
     *
     * @return the version number.
     */
    public int getVersion() {
        if (info == null)
            return -1;
        try {
            int vers = ((Integer) info.get(CertificateVersion.NAME
                            + DOT + CertificateVersion.VERSION)).intValue();
            return vers;
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Gets the serial number from the certificate.
     *
     * @return the serial number.
     */
    public BigInteger getSerialNumber() {
        if (info == null)
            return null;
        try {
            SerialNumber ser = (SerialNumber) info.get(
                                  CertificateSerialNumber.NAME + DOT +
                                          CertificateSerialNumber.NUMBER);
            return ser.getNumber().toBigInteger();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the subject distinguished name from the certificate.
     *
     * @return the subject name.
     */
    public Principal getSubjectDN() {
        if (info == null)
            return null;
        try {
            Principal subject = (Principal) info.get(
                                     CertificateSubjectName.NAME + DOT +
                                             CertificateSubjectName.DN_NAME);
            return subject;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the issuer distinguished name from the certificate.
     *
     * @return the issuer name.
     */
    public Principal getIssuerDN() {
        if (info == null)
            return null;
        try {
            Principal issuer = (Principal) info.get(
                                    CertificateIssuerName.NAME + DOT +
                                            CertificateIssuerName.DN_NAME);
            return issuer;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the notBefore date from the validity period of the certificate.
     *
     * @return the start date of the validity period.
     */
    public Date getNotBefore() {
        if (info == null)
            return null;
        try {
            Date d = (Date) info.get(CertificateValidity.NAME + DOT +
                                         CertificateValidity.NOT_BEFORE);
            return d;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the notAfter date from the validity period of the certificate.
     *
     * @return the end date of the validity period.
     */
    public Date getNotAfter() {
        if (info == null)
            return null;
        try {
            Date d = (Date) info.get(CertificateValidity.NAME + DOT +
                                         CertificateValidity.NOT_AFTER);
            return d;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the DER encoded certificate informations, the <code>tbsCertificate</code> from this certificate.
     * This can be used to verify the signature independently.
     *
     * @return the DER encoded certificate information.
     * @exception CertificateEncodingException if an encoding error occurs.
     */
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        if (info != null) {
            return info.getEncodedInfo();
        } else
            throw new CertificateEncodingException("Uninitialized certificate");
    }

    /**
     * Gets the raw Signature bits from the certificate.
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
     * Gets the signature algorithm name for the certificate
     * signature algorithm.
     * For example, the string "SHA-1/DSA" or "DSS".
     *
     * @return the signature algorithm name.
     */
    public String getSigAlgName() {
        if (algId == null)
            return null;
        return (algId.getName());
    }

    /**
     * Gets the signature algorithm OID string from the certificate.
     * For example, the string "1.2.840.10040.4.3"
     *
     * @return the signature algorithm oid string.
     */
    public String getSigAlgOID() {
        if (algId == null)
            return null;
        ObjectIdentifier oid = algId.getOID();
        return (oid.toString());
    }

    /**
     * Gets the DER encoded signature algorithm parameters from this
     * certificate's signature algorithm.
     *
     * @return the DER encoded signature algorithm parameters, or
     *         null if no parameters are present.
     */
    public byte[] getSigAlgParams() {
        if (algId == null)
            return null;
        try {
            return algId.getEncodedParams();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Gets the Issuer Unique Identity from the certificate.
     *
     * @return the Issuer Unique Identity.
     */
    public boolean[] getIssuerUniqueID() {
        if (info == null)
            return null;
        try {
            UniqueIdentity id = (UniqueIdentity) info.get(
                                     CertificateIssuerUniqueIdentity.NAME
                                             + DOT + CertificateIssuerUniqueIdentity.ID);
            if (id == null)
                return null;
            else
                return (id.getId());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the Subject Unique Identity from the certificate.
     *
     * @return the Subject Unique Identity.
     */
    public boolean[] getSubjectUniqueID() {
        if (info == null)
            return null;
        try {
            UniqueIdentity id = (UniqueIdentity) info.get(
                                     CertificateSubjectUniqueIdentity.NAME
                                             + DOT + CertificateSubjectUniqueIdentity.ID);
            if (id == null)
                return null;
            else
                return (id.getId());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets a Set of the extension(s) marked CRITICAL in the
     * certificate by OID strings.
     *
     * @return a set of the extension oid strings in the
     *         certificate that are marked critical.
     */
    public Set<String> getCriticalExtensionOIDs() {
        if (info == null)
            return null;
        try {
            CertificateExtensions exts = (CertificateExtensions) info.get(
                                             CertificateExtensions.NAME);
            if (exts == null)
                return null;
            Set<String> extSet = new LinkedHashSet<String>();
            Extension ex;
            for (Enumeration<Extension> e = exts.getAttributes(); e.hasMoreElements();) {
                ex = e.nextElement();
                if (ex.isCritical())
                    extSet.add(ex.getExtensionId().toString());
            }
            return extSet;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets a Set of the extension(s) marked NON-CRITICAL in the
     * certificate by OID strings.
     *
     * @return a set of the extension oid strings in the
     *         certificate that are NOT marked critical.
     */
    public Set<String> getNonCriticalExtensionOIDs() {
        if (info == null)
            return null;
        try {
            CertificateExtensions exts = (CertificateExtensions) info.get(
                                             CertificateExtensions.NAME);
            if (exts == null)
                return null;

            Set<String> extSet = new LinkedHashSet<String>();
            Extension ex;
            for (Enumeration<Extension> e = exts.getAttributes(); e.hasMoreElements();) {
                ex = e.nextElement();
                if (!ex.isCritical())
                    extSet.add(ex.getExtensionId().toString());
            }
            return extSet;
        } catch (Exception e) {
            return null;
        }
    }

    public Extension getExtension(String oid) {
        try {
            CertificateExtensions exts = (CertificateExtensions) info.get(
                                         CertificateExtensions.NAME);
            if (exts == null)
                return null;
            ObjectIdentifier findOID = new ObjectIdentifier(oid);
            Extension ex = null;
            ;
            ObjectIdentifier inCertOID;
            for (Enumeration<Extension> e = exts.getAttributes(); e.hasMoreElements();) {
                ex = e.nextElement();
                inCertOID = ex.getExtensionId();
                if (inCertOID.equals(findOID)) {
                    return ex;
                }
            }
        } catch (Exception e) {
        }
        return null;
    }

    /**
     * Gets the DER encoded extension identified by the passed
     * in oid String.
     *
     * @param oid the Object Identifier value for the extension.
     */
    public byte[] getExtensionValue(String oid) {
        DerOutputStream out = null;
        try {
            String extAlias = OIDMap.getName(new ObjectIdentifier(oid));
            Extension certExt = null;

            if (extAlias == null) { // may be unknown
                // get the extensions, search thru' for this oid
                CertificateExtensions exts = (CertificateExtensions) info.get(
                                         CertificateExtensions.NAME);
                if (exts == null)
                    return null;

                ObjectIdentifier findOID = new ObjectIdentifier(oid);
                Extension ex = null;
                ;
                ObjectIdentifier inCertOID;
                for (Enumeration<Extension> e = exts.getAttributes(); e.hasMoreElements();) {
                    ex = e.nextElement();
                    inCertOID = ex.getExtensionId();
                    if (inCertOID.equals(findOID)) {
                        certExt = ex;
                        break;
                    }
                }
            } else { // there's sub-class that can handle this extension
                certExt = (Extension) this.get(extAlias);
            }
            if (certExt == null)
                return null;
            byte[] extData = certExt.getExtensionValue();
            if (extData == null)
                return null;

            out = new DerOutputStream();
            out.putOctetString(extData);
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Get a boolean array representing the bits of the KeyUsage extension,
     * (oid = 2.5.29.15).
     *
     * @return the bit values of this extension as an array of booleans.
     */
    public boolean[] getKeyUsage() {
        try {
            String extAlias = OIDMap.getName(new ObjectIdentifier(
                                         KEY_USAGE_OID));
            if (extAlias == null)
                return null;

            KeyUsageExtension certExt = (KeyUsageExtension) this.get(extAlias);
            if (certExt == null)
                return null;

            return certExt.getBits();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get the certificate constraints path length from the
     * the critical BasicConstraints extension, (oid = 2.5.29.19).
     *
     * @return the length of the constraint.
     */
    public int getBasicConstraints() {
        try {
            String extAlias = OIDMap.getName(new ObjectIdentifier(
                                         BASIC_CONSTRAINT_OID));
            if (extAlias == null)
                return -1;
            BasicConstraintsExtension certExt =
                        (BasicConstraintsExtension) this.get(extAlias);
            if (certExt == null)
                return -1;

            if (((Boolean) certExt.get(BasicConstraintsExtension.IS_CA)).booleanValue() == true)
                return ((Integer) certExt.get(
                        BasicConstraintsExtension.PATH_LEN)).intValue();
            else
                return -1;
        } catch (Exception e) {
            return -1;
        }
    }

    public boolean getBasicConstraintsIsCA() {
        boolean isCA = false;
        try {
            String extAlias = OIDMap.getName(new ObjectIdentifier(
                                             BASIC_CONSTRAINT_OID));
            if (extAlias == null)
                return false;

            BasicConstraintsExtension certExt =
                        (BasicConstraintsExtension) this.get(extAlias);
            if (certExt == null)
                return false;

            isCA = ((Boolean) certExt.get(BasicConstraintsExtension.IS_CA)).booleanValue();
        } catch (Exception e) {
            return false;
        }
        return isCA;
    }

    /************************************************************/

    /*
     * Cert is a SIGNED ASN.1 macro, a three elment sequence:
     *
     *	- Data to be signed (ToBeSigned) -- the "raw" cert
     *	- Signature algorithm (SigAlgId)
     *	- The signature bits
     *
     * This routine unmarshals the certificate, saving the signature
     * parts away for later verification.
     */
    private void parse(DerValue val) throws CertificateException, IOException {
        // check if can over write the certificate
        if (readOnly)
            throw new CertificateParsingException(
                      "cannot over-write existing certificate");

        readOnly = true;
        DerValue seq[] = new DerValue[3];

        seq[0] = val.data.getDerValue();
        seq[1] = val.data.getDerValue();
        seq[2] = val.data.getDerValue();

        if (val.data.available() != 0) {
            throw new CertificateParsingException("signed overrun, bytes = "
                                     + val.data.available());
        }
        if (seq[0].tag != DerValue.tag_Sequence) {
            throw new CertificateParsingException("signed fields invalid");
        }

        algId = AlgorithmId.parse(seq[1]);
        signature = seq[2].getBitString();

        if (seq[1].data.available() != 0) {
            throw new CertificateParsingException("algid field overrun");
        }
        if (seq[2].data.available() != 0)
            throw new CertificateParsingException("signed fields overrun");

        // The CertificateInfo
        if (info == null) {
            info = new X509CertInfo(seq[0]);
        }
    }

    /**
     * Serialization write ... X.509 certificates serialize as
     * themselves, and they're parsed when they get read back.
     * (Actually they serialize as some type data from the
     * serialization subsystem, then the cert data.)
     */
    private void writeObject(ObjectOutputStream stream) throws CertificateException, IOException {
        encode(stream);
    }

    /**
     * Serialization read ... X.509 certificates serialize as
     * themselves, and they're parsed when they get read back.
     */
    private void readObject(ObjectInputStream stream) throws CertificateException, IOException {
        decode(stream);
    }

    protected static class CertificateRep1 implements java.io.Serializable {
        /**
         *
         */
        private static final long serialVersionUID = -5207881613631592409L;
        private String type1;
        private byte[] data1;

        /**
         * Construct the alternate Certificate class with the Certificate
         * type and Certificate encoding bytes.
         *
         * <p>
         *
         * @param type the standard name of the Certificate type.
         *            <p>
         *
         * @param data the Certificate data.
         */
        protected CertificateRep1(String type, byte[] data) {
            this.type1 = type;
            this.data1 = data;
        }

        /**
         * Resolve the Certificate Object.
         *
         * <p>
         *
         * @return the resolved Certificate Object.
         *
         * @throws java.io.ObjectStreamException if the Certificate could not
         *             be resolved.
         */
        protected Object readResolve() throws java.io.ObjectStreamException {
            try {
                @SuppressWarnings("unused")
                CertificateFactory cf = CertificateFactory.getInstance(type1); // check for errors
                return new X509CertImpl(data1);

                /*
                                return cf.generateCertificate
                                        (new java.io.ByteArrayInputStream(data1));
                */
            } catch (CertificateException e) {
                throw new java.io.NotSerializableException("java.security.cert.Certificate: " +
                                type1 +
                                ": " +
                                e.getMessage());
            }
        }

    }

    protected Object writeReplace() throws java.io.ObjectStreamException {
        try {
            return new CertificateRep1("X.509", getEncoded());
        } catch (CertificateException e) {
            throw new java.io.NotSerializableException("java.security.cert.Certificate: " +
                                "X.509" +
                                ": " +
                                e.getMessage());
        }
    }
}
