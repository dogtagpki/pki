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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * The X509CertInfo class represents X.509 certificate information.
 *
 * <P>
 * X.509 certificates have several base data elements, including:
 * <UL>
 *
 * <LI>The <em>Subject Name</em>, an X.500 Distinguished Name for the entity (subject) for which the certificate was
 * issued.
 *
 * <LI>The <em>Subject Public Key</em>, the public key of the subject. This is one of the most important parts of the
 * certificate.
 *
 * <LI>The <em>Validity Period</em>, a time period (e.g. six months) within which the certificate is valid (unless
 * revoked).
 *
 * <LI>The <em>Issuer Name</em>, an X.500 Distinguished Name for the Certificate Authority (CA) which issued the
 * certificate.
 *
 * <LI>A <em>Serial Number</em> assigned by the CA, for use in certificate revocation and other applications.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.16
 * @see CertAttrSet
 * @see Serializable
 * @see X509CertImpl
 */
public class X509CertInfo implements CertAttrSet, Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -5094073467876311577L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info";
    // Certificate attribute names
    public static final String NAME = "info";
    public static final String VERSION = CertificateVersion.NAME;
    public static final String SERIAL_NUMBER = CertificateSerialNumber.NAME;
    public static final String ALGORITHM_ID = CertificateAlgorithmId.NAME;
    public static final String ISSUER = CertificateIssuerName.NAME;
    public static final String VALIDITY = CertificateValidity.NAME;
    public static final String SUBJECT = CertificateSubjectName.NAME;
    public static final String KEY = CertificateX509Key.NAME;
    public static final String ISSUER_ID = CertificateIssuerUniqueIdentity.NAME;
    public static final String SUBJECT_ID = CertificateSubjectUniqueIdentity.NAME;
    public static final String EXTENSIONS = CertificateExtensions.NAME;

    // X509.v1 data
    protected CertificateVersion version = new CertificateVersion();
    protected CertificateSerialNumber serialNum = null;
    protected CertificateAlgorithmId algId = null;
    protected CertificateIssuerName issuer = null;
    protected CertificateValidity interval = null;
    protected CertificateSubjectName subject = null;
    protected CertificateX509Key pubKey = null;

    // X509.v2 & v3 extensions
    protected CertificateIssuerUniqueIdentity issuerUniqueId = null;
    protected CertificateSubjectUniqueIdentity subjectUniqueId = null;

    // X509.v3 extensions
    protected CertificateExtensions extensions = null;

    // Attribute numbers for internal manipulation
    private static final int ATTR_VERSION = 1;
    private static final int ATTR_SERIAL = 2;
    private static final int ATTR_ALGORITHM = 3;
    private static final int ATTR_ISSUER = 4;
    private static final int ATTR_VALIDITY = 5;
    private static final int ATTR_SUBJECT = 6;
    private static final int ATTR_KEY = 7;
    private static final int ATTR_ISSUER_ID = 8;
    private static final int ATTR_SUBJECT_ID = 9;
    private static final int ATTR_EXTENSIONS = 10;

    // DER encoded CertificateInfo data
    private byte[] rawCertInfo = null;

    // The certificate attribute name to integer mapping stored here
    private static final Hashtable<String, Integer> map = new Hashtable<String, Integer>();
    static {
        map.put(VERSION, Integer.valueOf(ATTR_VERSION));
        map.put(SERIAL_NUMBER, Integer.valueOf(ATTR_SERIAL));
        map.put(ALGORITHM_ID, Integer.valueOf(ATTR_ALGORITHM));
        map.put(ISSUER, Integer.valueOf(ATTR_ISSUER));
        map.put(VALIDITY, Integer.valueOf(ATTR_VALIDITY));
        map.put(SUBJECT, Integer.valueOf(ATTR_SUBJECT));
        map.put(KEY, Integer.valueOf(ATTR_KEY));
        map.put(ISSUER_ID, Integer.valueOf(ATTR_ISSUER_ID));
        map.put(SUBJECT_ID, Integer.valueOf(ATTR_SUBJECT_ID));
        map.put(EXTENSIONS, Integer.valueOf(ATTR_EXTENSIONS));
    }

    /**
     * Construct an uninitialized X509CertInfo on which <a href="#decode">
     * decode</a> must later be called (or which may be deserialized).
     */
    public X509CertInfo() {
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
     * @param cert the encoded bytes, with no trailing data.
     * @exception CertificateParsingException on parsing errors.
     */
    public X509CertInfo(byte[] cert) throws CertificateParsingException {
        try {
            DerValue in = new DerValue(cert);

            parse(in);
        } catch (IOException e) {
            throw new CertificateParsingException(e.toString());
        }
    }

    /**
     * Unmarshal a certificate from its encoded form, parsing a DER value.
     * This form of constructor is used by agents which need to examine
     * and use certificate contents.
     *
     * @param derVal the der value containing the encoded cert.
     * @exception CertificateParsingException on parsing errors.
     */
    public X509CertInfo(DerValue derVal) throws CertificateParsingException {
        try {
            parse(derVal);
        } catch (IOException e) {
            throw new CertificateParsingException(e.toString());
        }
    }

    /**
     * Decode an X.509 certificate from an input stream.
     *
     * @param in an input stream holding at least one certificate
     * @exception CertificateParsingException on decoding errors.
     * @exception IOException on other errors.
     */
    public void decode(InputStream in)
            throws CertificateParsingException, IOException {
        DerValue val = new DerValue(in);

        parse(val);
    }

    /**
     * Appends the certificate to an output stream.
     *
     * @param out an output stream to which the certificate is appended.
     * @exception CertificateException on encoding errors.
     * @exception IOException on other errors.
     */
    public void encode(OutputStream out)
            throws CertificateException, IOException {
        encode(out, false);
    }

    /**
     * Appends the certificate to an output stream.
     *
     * @param out An output stream to which the certificate is appended.
     * @param ignoreCache Whether to ignore the internal cache when encoding.
     *            (the cache can easily become out of date).
     */
    public void encode(OutputStream out, boolean ignoreCache)
            throws IOException, CertificateException {
        if (ignoreCache || (rawCertInfo == null)) {
            DerOutputStream tmp = new DerOutputStream();
            emit(tmp);
            rawCertInfo = tmp.toByteArray();
        }
        out.write(rawCertInfo);
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(VERSION);
        elements.addElement(SERIAL_NUMBER);
        elements.addElement(ALGORITHM_ID);
        elements.addElement(ISSUER);
        elements.addElement(VALIDITY);
        elements.addElement(SUBJECT);
        elements.addElement(KEY);
        elements.addElement(ISSUER_ID);
        elements.addElement(SUBJECT_ID);
        elements.addElement(EXTENSIONS);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    /**
     * Returns the encoded certificate info.
     *
     * @exception CertificateEncodingException on encoding information errors.
     */
    public byte[] getEncodedInfo() throws CertificateEncodingException {
        return getEncodedInfo(false);
    }

    public byte[] getEncodedInfo(boolean ignoreCache) throws CertificateEncodingException {
        try {
            if (ignoreCache || (rawCertInfo == null)) {
                DerOutputStream tmp = new DerOutputStream();
                emit(tmp);
                rawCertInfo = tmp.toByteArray();
            }
            byte[] dup = new byte[rawCertInfo.length];
            System.arraycopy(rawCertInfo, 0, dup, 0, dup.length);
            return dup;
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        } catch (CertificateException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    /**
     * Compares two X509CertInfo objects. This is false if the
     * certificates are not both X.509 certs, otherwise it
     * compares them as binary data.
     *
     * @param other the object being compared with this one
     * @return true iff the certificates are equivalent
     */
    public boolean equals(Object other) {
        if (other instanceof X509CertInfo) {
            return equals((X509CertInfo) other);
        } else {
            return false;
        }
    }

    /**
     * Compares two certificates, returning false if any data
     * differs between the two.
     *
     * @param other the object being compared with this one
     * @return true iff the certificates are equivalent
     */
    public boolean equals(X509CertInfo other) {
        if (this == other) {
            return (true);
        } else if (rawCertInfo == null || other.rawCertInfo == null) {
            return (false);
        } else if (rawCertInfo.length != other.rawCertInfo.length) {
            return (false);
        }
        for (int i = 0; i < rawCertInfo.length; i++) {
            if (rawCertInfo[i] != other.rawCertInfo[i]) {
                return (false);
            }
        }
        return (true);
    }

    /**
     * Calculates a hash code value for the object. Objects
     * which are equal will also have the same hashcode.
     */
    public int hashCode() {
        int retval = 0;

        for (int i = 1; i < rawCertInfo.length; i++) {
            retval += rawCertInfo[i] * i;
        }
        return (retval);
    }

    /**
     * Returns a printable representation of the certificate.
     */
    public String toString() {

        if (subject == null || pubKey == null || interval == null
                || issuer == null || algId == null || serialNum == null) {
            throw new NullPointerException("X.509 cert is incomplete");
        }
        StringBuffer sb = new StringBuffer("[\n" + "  " + version.toString() + "\n" + "  Subject: "
                + subject.toString() + "\n"
                + "  Signature Algorithm: " + algId.toString() + "\n" + "  Key:  " + pubKey.toString() + "\n");

        sb.append("  " + interval.toString() + "\n" + "  Issuer: " + issuer.toString() + "\n"
                + "  " + serialNum.toString() + "\n");
        // optional v2, v3 extras
        if (issuerUniqueId != null) {
            sb.append("  Issuer Id:\n" + issuerUniqueId.toString() + "\n");
        }
        if (subjectUniqueId != null) {
            sb.append("  Subject Id:\n" + subjectUniqueId.toString() + "\n");
        }
        if (extensions != null) {
            netscape.security.util.PrettyPrintFormat pp =
                    new netscape.security.util.PrettyPrintFormat(" ", 20);
            for (int i = 0; i < extensions.size(); i++) {
                sb.append("  Extension[" + i + "] = ");
                Extension ext = extensions.elementAt(i);
                DerOutputStream out = null;
                try {
                    if (OIDMap.getClass(ext.getExtensionId()) == null) {
                        sb.append(ext.toString());
                        byte[] extValue = ext.getExtensionValue();
                        if (extValue != null) {
                            out = new DerOutputStream();
                            out.putOctetString(extValue);
                            extValue = out.toByteArray();
                            String extValuebits = pp.toHexString(extValue);
                            sb.append("Extension unknown: "
                                      + "DER encoded OCTET string =\n"
                                      + extValuebits);
                        }
                    } else
                        sb.append(ext.toString()); //sub-class exists
                } catch (CertificateException e) {
                    sb.append(", Error parsing this extension");
                } catch (IOException e) {
                    sb.append(", Error parsing this extension");
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
        }
        sb.append("\n]");
        return sb.toString();
    }

    /**
     * Set the certificate attribute.
     *
     * @param name the name of the Certificate attribute.
     * @param val the value of the Certificate attribute.
     * @exception CertificateException on invalid attributes.
     * @exception IOException on other errors.
     */
    public void set(String name, Object val)
            throws CertificateException, IOException {
        X509AttributeName attrName = new X509AttributeName(name);

        int attr = attributeMap(attrName.getPrefix());
        if (attr == 0) {
            throw new CertificateException("Attribute name not recognized: "
                                           + name);
        }
        // set rawCertInfo to null, so that we are forced to re-encode
        rawCertInfo = null;

        switch (attr) {
        case ATTR_VERSION:
            if (attrName.getSuffix() == null) {
                setVersion(val);
            } else {
                version.set(attrName.getSuffix(), val);
            }
            break;

        case ATTR_SERIAL:
            if (attrName.getSuffix() == null) {
                setSerialNumber(val);
            } else {
                serialNum.set(attrName.getSuffix(), val);
            }
            break;

        case ATTR_ALGORITHM:
            if (attrName.getSuffix() == null) {
                setAlgorithmId(val);
            } else {
                algId.set(attrName.getSuffix(), val);
            }
            break;

        case ATTR_ISSUER:
            if (attrName.getSuffix() == null) {
                setIssuer(val);
            } else {
                issuer.set(attrName.getSuffix(), val);
            }
            break;

        case ATTR_VALIDITY:
            if (attrName.getSuffix() == null) {
                setValidity(val);
            } else {
                interval.set(attrName.getSuffix(), val);
            }
            break;

        case ATTR_SUBJECT:
            if (attrName.getSuffix() == null) {
                setSubject(val);
            } else {
                subject.set(attrName.getSuffix(), val);
            }
            break;

        case ATTR_KEY:
            if (attrName.getSuffix() == null) {
                setKey(val);
            } else {
                pubKey.set(attrName.getSuffix(), val);
            }
            break;

        case ATTR_ISSUER_ID:
            if (attrName.getSuffix() == null) {
                setIssuerUniqueId(val);
            } else {
                issuerUniqueId.set(attrName.getSuffix(), val);
            }
            break;

        case ATTR_SUBJECT_ID:
            if (attrName.getSuffix() == null) {
                setSubjectUniqueId(val);
            } else {
                subjectUniqueId.set(attrName.getSuffix(), val);
            }
            break;

        case ATTR_EXTENSIONS:
            if (attrName.getSuffix() == null) {
                setExtensions(val);
            } else {
                extensions.set(attrName.getSuffix(), val);
            }
            break;
        }
    }

    /**
     * Delete the certificate attribute.
     *
     * @param name the name of the Certificate attribute.
     * @exception CertificateException on invalid attributes.
     * @exception IOException on other errors.
     */
    public void delete(String name)
            throws CertificateException, IOException {
        X509AttributeName attrName = new X509AttributeName(name);

        int attr = attributeMap(attrName.getPrefix());
        if (attr == 0) {
            throw new CertificateException("Attribute name not recognized: "
                                           + name);
        }
        // set rawCertInfo to null, so that we are forced to re-encode
        rawCertInfo = null;

        switch (attr) {
        case ATTR_VERSION:
            if (attrName.getSuffix() == null) {
                version = null;
            } else {
                version.delete(attrName.getSuffix());
            }
            break;
        case (ATTR_SERIAL):
            if (attrName.getSuffix() == null) {
                serialNum = null;
            } else {
                serialNum.delete(attrName.getSuffix());
            }
            break;
        case (ATTR_ALGORITHM):
            if (attrName.getSuffix() == null) {
                algId = null;
            } else {
                algId.delete(attrName.getSuffix());
            }
            break;
        case (ATTR_ISSUER):
            if (attrName.getSuffix() == null) {
                issuer = null;
            } else {
                issuer.delete(attrName.getSuffix());
            }
            break;
        case (ATTR_VALIDITY):
            if (attrName.getSuffix() == null) {
                interval = null;
            } else {
                interval.delete(attrName.getSuffix());
            }
            break;
        case (ATTR_SUBJECT):
            if (attrName.getSuffix() == null) {
                subject = null;
            } else {
                subject.delete(attrName.getSuffix());
            }
            break;
        case (ATTR_KEY):
            if (attrName.getSuffix() == null) {
                pubKey = null;
            } else {
                pubKey.delete(attrName.getSuffix());
            }
            break;
        case (ATTR_ISSUER_ID):
            if (attrName.getSuffix() == null) {
                issuerUniqueId = null;
            } else {
                issuerUniqueId.delete(attrName.getSuffix());
            }
            break;
        case (ATTR_SUBJECT_ID):
            if (attrName.getSuffix() == null) {
                subjectUniqueId = null;
            } else {
                subjectUniqueId.delete(attrName.getSuffix());
            }
            break;
        case (ATTR_EXTENSIONS):
            if (attrName.getSuffix() == null) {
                extensions = null;
            } else {
                extensions.delete(attrName.getSuffix());
            }
            break;
        }
    }

    /**
     * Get the certificate attribute.
     *
     * @param name the name of the Certificate attribute.
     *
     * @exception CertificateException on invalid attributes.
     * @exception IOException on other errors.
     */
    public Object get(String name)
            throws CertificateException, IOException {
        X509AttributeName attrName = new X509AttributeName(name);

        int attr = attributeMap(attrName.getPrefix());
        if (attr == 0) {
            throw new CertificateParsingException(
                          "Attribute name not recognized: " + name);
        }

        switch (attr) {
        case (ATTR_VERSION):
            if (attrName.getSuffix() == null) {
                return (version);
            } else {
                return (version.get(attrName.getSuffix()));
            }
        case (ATTR_SERIAL):
            if (attrName.getSuffix() == null) {
                return (serialNum);
            } else {
                return (serialNum.get(attrName.getSuffix()));
            }
        case (ATTR_ALGORITHM):
            if (attrName.getSuffix() == null) {
                return (algId);
            } else {
                return (algId.get(attrName.getSuffix()));
            }
        case (ATTR_ISSUER):
            if (attrName.getSuffix() == null) {
                return (issuer);
            } else {
                return (issuer.get(attrName.getSuffix()));
            }
        case (ATTR_VALIDITY):
            if (attrName.getSuffix() == null) {
                return (interval);
            } else {
                return (interval.get(attrName.getSuffix()));
            }
        case (ATTR_SUBJECT):
            if (attrName.getSuffix() == null) {
                return (subject);
            } else {
                return (subject.get(attrName.getSuffix()));
            }
        case (ATTR_KEY):
            if (attrName.getSuffix() == null) {
                return (pubKey);
            } else {
                return (pubKey.get(attrName.getSuffix()));
            }
        case (ATTR_ISSUER_ID):
            if (attrName.getSuffix() == null) {
                return (issuerUniqueId);
            } else {
                if (issuerUniqueId == null)
                    return null;
                else
                    return (issuerUniqueId.get(attrName.getSuffix()));
            }
        case (ATTR_SUBJECT_ID):
            if (attrName.getSuffix() == null) {
                return (subjectUniqueId);
            } else {
                if (subjectUniqueId == null)
                    return null;
                else
                    return (subjectUniqueId.get(attrName.getSuffix()));
            }
        case (ATTR_EXTENSIONS):
            if (attrName.getSuffix() == null) {
                return (extensions);
            } else {
                if (extensions == null)
                    return null;
                else
                    return (extensions.get(attrName.getSuffix()));
            }
        }
        return null;
    }

    /*
     * This routine unmarshals the certificate information.
     */
    private void parse(DerValue val)
            throws CertificateParsingException, IOException {
        DerInputStream in;
        DerValue tmp;

        if (val.tag != DerValue.tag_Sequence) {
            throw new CertificateParsingException("signed fields invalid");
        }
        rawCertInfo = val.toByteArray();

        in = val.data;

        // Version
        tmp = in.getDerValue();
        if (tmp.isContextSpecific((byte) 0)) {
            version = new CertificateVersion(tmp);
            tmp = in.getDerValue();
        }

        // Serial number ... an integer
        serialNum = new CertificateSerialNumber(tmp);

        // Algorithm Identifier
        algId = new CertificateAlgorithmId(in);

        // Issuer name
        issuer = new CertificateIssuerName(in);

        // validity:  SEQUENCE { start date, end date }
        interval = new CertificateValidity(in);

        // subject name
        subject = new CertificateSubjectName(in);

        // public key
        pubKey = new CertificateX509Key(in);

        // If more data available, make sure version is not v1.
        if (in.available() != 0) {
            if (version.compare(CertificateVersion.V1) == 0) {
                throw new CertificateParsingException("excess cert data");
            }
        } else {
            return;
        }

        // Get the issuerUniqueId if present
        tmp = in.getDerValue();
        if (tmp.isContextSpecific((byte) 1)) {
            issuerUniqueId = new CertificateIssuerUniqueIdentity(tmp);
            if (in.available() == 0) {
                return;
            }
            tmp = in.getDerValue();
        }

        // Get the subjectUniqueId if present.
        if (tmp.isContextSpecific((byte) 2)) {
            subjectUniqueId = new CertificateSubjectUniqueIdentity(tmp);
            if (in.available() == 0) {
                return;
            }
            tmp = in.getDerValue();
        }

        // Get the extensions.
        if (version.compare(CertificateVersion.V3) != 0) {
            throw new CertificateParsingException("excess cert data");
        }
        if (tmp.isConstructed() && tmp.isContextSpecific((byte) 3)) {
            extensions = new CertificateExtensions(tmp.data);
        }
    }

    /*
     * Marshal the contents of a "raw" certificate into a DER sequence.
     */
    private void emit(DerOutputStream out)
            throws CertificateException, IOException {
        DerOutputStream tmp = new DerOutputStream();

        // version number, iff not V1
        version.encode(tmp);

        // Encode serial number, issuer signing algorithm, issuer name
        // and validity
        serialNum.encode(tmp);
        algId.encode(tmp);
        issuer.encode(tmp);
        interval.encode(tmp);

        // Encode subject (principal) and associated key
        subject.encode(tmp);
        pubKey.encode(tmp);

        // Encode issuerUniqueId & subjectUniqueId.
        if (issuerUniqueId != null) {
            issuerUniqueId.encode(tmp);
        }
        if (subjectUniqueId != null) {
            subjectUniqueId.encode(tmp);
        }

        // Write all the extensions.
        if (extensions != null) {
            extensions.encode(tmp);
        }

        // Wrap the data; encoding of the "raw" cert is now complete.
        out.write(DerValue.tag_Sequence, tmp);
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

    /**
     * Returns the integer attribute number for the passed attribute name.
     */
    private int attributeMap(String name) {
        Integer num = map.get(name);
        if (num == null) {
            return (0);
        }
        return (num.intValue());
    }

    /**
     * Set the version number of the certificate.
     *
     * @param val the Object class value for the Extensions
     * @exception CertificateException on invalid data.
     */
    private void setVersion(Object val) throws CertificateException {
        if (!(val instanceof CertificateVersion)) {
            throw new CertificateException("Version class type invalid.");
        }
        version = (CertificateVersion) val;
    }

    /**
     * Set the serial number of the certificate.
     *
     * @param val the Object class value for the CertificateSerialNumber
     * @exception CertificateException on invalid data.
     */
    private void setSerialNumber(Object val) throws CertificateException {
        if (!(val instanceof CertificateSerialNumber)) {
            throw new CertificateException("SerialNumber class type invalid.");
        }
        serialNum = (CertificateSerialNumber) val;
    }

    /**
     * Set the algorithm id of the certificate.
     *
     * @param val the Object class value for the AlgorithmId
     * @exception CertificateException on invalid data.
     */
    private void setAlgorithmId(Object val) throws CertificateException {
        if (!(val instanceof CertificateAlgorithmId)) {
            throw new CertificateException(
                    "AlgorithmId class type invalid.");
        }
        algId = (CertificateAlgorithmId) val;
    }

    /**
     * Set the issuer name of the certificate.
     *
     * @param val the Object class value for the issuer
     * @exception CertificateException on invalid data.
     */
    private void setIssuer(Object val) throws CertificateException {
        if (!(val instanceof CertificateIssuerName)) {
            throw new CertificateException(
                    "Issuer class type invalid.");
        }
        issuer = (CertificateIssuerName) val;
    }

    /**
     * Set the validity interval of the certificate.
     *
     * @param val the Object class value for the CertificateValidity
     * @exception CertificateException on invalid data.
     */
    private void setValidity(Object val) throws CertificateException {
        if (!(val instanceof CertificateValidity)) {
            throw new CertificateException(
                    "CertificateValidity class type invalid.");
        }
        interval = (CertificateValidity) val;
    }

    /**
     * Set the subject name of the certificate.
     *
     * @param val the Object class value for the Subject
     * @exception CertificateException on invalid data.
     */
    private void setSubject(Object val) throws CertificateException {
        if (!(val instanceof CertificateSubjectName)) {
            throw new CertificateException(
                    "Subject class type invalid.");
        }
        subject = (CertificateSubjectName) val;
    }

    /**
     * Set the public key in the certificate.
     *
     * @param val the Object class value for the PublicKey
     * @exception CertificateException on invalid data.
     */
    private void setKey(Object val) throws CertificateException {
        if (!(val instanceof CertificateX509Key)) {
            throw new CertificateException(
                    "Key class type invalid.");
        }
        pubKey = (CertificateX509Key) val;
    }

    /**
     * Set the Issuer Unique Identity in the certificate.
     *
     * @param val the Object class value for the IssuerUniqueId
     * @exception CertificateException
     */
    private void setIssuerUniqueId(Object val) throws CertificateException {
        if (version.compare(CertificateVersion.V2) < 0) {
            throw new CertificateException("Invalid version");
        }
        if (!(val instanceof CertificateIssuerUniqueIdentity)) {
            throw new CertificateException(
                    "IssuerUniqueId class type invalid.");
        }
        issuerUniqueId = (CertificateIssuerUniqueIdentity) val;
    }

    /**
     * Set the Subject Unique Identity in the certificate.
     *
     * @param val the Object class value for the SubjectUniqueId
     * @exception CertificateException
     */
    private void setSubjectUniqueId(Object val) throws CertificateException {
        if (version.compare(CertificateVersion.V2) < 0) {
            throw new CertificateException("Invalid version");
        }
        if (!(val instanceof CertificateSubjectUniqueIdentity)) {
            throw new CertificateException(
                    "SubjectUniqueId class type invalid.");
        }
        subjectUniqueId = (CertificateSubjectUniqueIdentity) val;
    }

    /**
     * Set the extensions in the certificate.
     *
     * @param val the Object class value for the Extensions
     * @exception CertificateException
     */
    private void setExtensions(Object val) throws CertificateException {
        if (version.compare(CertificateVersion.V3) < 0) {
            throw new CertificateException("Invalid version");
        }
        if (!(val instanceof CertificateExtensions)) {
            throw new CertificateException(
                    "Extensions class type invalid.");
        }
        extensions = (CertificateExtensions) val;
    }
}
