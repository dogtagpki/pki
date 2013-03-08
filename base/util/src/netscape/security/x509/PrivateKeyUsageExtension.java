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
import java.lang.reflect.Array;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class defines the Private Key Usage Extension.
 *
 * <p>
 * The Private Key Usage Period extension allows the certificate issuer to specify a different validity period for the
 * private key than the certificate. This extension is intended for use with digital signature keys. This extension
 * consists of two optional components notBefore and notAfter. The private key associated with the certificate should
 * not be used to sign objects before or after the times specified by the two components, respectively.
 *
 * <pre>
 * PrivateKeyUsagePeriod ::= SEQUENCE {
 *     notBefore  [0]  GeneralizedTime OPTIONAL,
 *     notAfter   [1]  GeneralizedTime OPTIONAL }
 * </pre>
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.12
 * @see Extension
 * @see CertAttrSet
 */
public class PrivateKeyUsageExtension extends Extension
        implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = -7623695233957629936L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.PrivateKeyUsage";
    /**
     * Sub attributes name for this CertAttrSet.
     */
    public static final String NAME = "PrivateKeyUsage";
    public static final String NOT_BEFORE = "not_before";
    public static final String NOT_AFTER = "not_after";

    // Private data members
    private static final byte TAG_BEFORE = 0;
    private static final byte TAG_AFTER = 1;

    private Date notBefore;
    private Date notAfter;

    // Encode this extension value.
    private void encodeThis() throws IOException {
        try (DerOutputStream seq = new DerOutputStream()) {

            DerOutputStream tagged = new DerOutputStream();
            if (notBefore != null) {
                DerOutputStream tmp = new DerOutputStream();
                tmp.putGeneralizedTime(notBefore);
                tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                        false, TAG_BEFORE), tmp);
            }
            if (notAfter != null) {
                DerOutputStream tmp = new DerOutputStream();
                tmp.putGeneralizedTime(notAfter);
                tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                        false, TAG_AFTER), tmp);
            }
            seq.write(DerValue.tag_Sequence, tagged);
            extensionValue = seq.toByteArray();
        }
    }

    /**
     * The default constructor for PrivateKeyUsageExtension.
     *
     * @param notBefore the date/time before which the private key
     *            should not be used.
     * @param notAfter the date/time after which the private key
     *            should not be used.
     */
    public PrivateKeyUsageExtension(Date notBefore, Date notAfter)
            throws IOException {
        this.notBefore = notBefore;
        this.notAfter = notAfter;

        this.extensionId = PKIXExtensions.PrivateKeyUsage_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create the extension from the passed DER encoded value.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     *
     * @exception CertificateException on certificate parsing errors.
     * @exception IOException on error.
     */
    public PrivateKeyUsageExtension(Boolean critical, Object value)
            throws CertificateException, IOException {
        this.extensionId = PKIXExtensions.PrivateKeyUsage_Id;
        this.critical = critical.booleanValue();

        if (!(value instanceof byte[]))
            throw new CertificateException("Illegal argument type");

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        System.arraycopy(value, 0, extValue, 0, len);

        this.extensionValue = extValue;
        DerInputStream str = new DerInputStream(extValue);
        DerValue[] seq = str.getSequence(2);

        // NB. this is always encoded with the IMPLICIT tag
        // The checks only make sense if we assume implicit tagging,
        // with explicit tagging the form is always constructed.
        for (int i = 0; i < seq.length; i++) {
            DerValue opt = seq[i];

            if (opt.isContextSpecific(TAG_BEFORE) &&
                    !opt.isConstructed()) {
                if (notBefore != null) {
                    throw new CertificateParsingException(
                            "Duplicate notBefore in PrivateKeyUsage.");
                }
                opt.resetTag(DerValue.tag_GeneralizedTime);
                str = new DerInputStream(opt.toByteArray());
                notBefore = str.getGeneralizedTime();

            } else if (opt.isContextSpecific(TAG_AFTER) &&
                       !opt.isConstructed()) {
                if (notAfter != null) {
                    throw new CertificateParsingException(
                            "Duplicate notAfter in PrivateKeyUsage.");
                }
                opt.resetTag(DerValue.tag_GeneralizedTime);
                str = new DerInputStream(opt.toByteArray());
                notAfter = str.getGeneralizedTime();
            } else
                throw new IOException("Invalid encoding of " +
                                      "PrivateKeyUsageExtension");
        }
    }

    /**
     * Return the printable string.
     */
    public String toString() {
        return (super.toString() +
                "PrivateKeyUsage: [From: " +
                ((notBefore == null) ? "" : notBefore.toString()) +
                ", To: " +
                ((notAfter == null) ? "" : notAfter.toString()) + "]\n");
    }

    /**
     * Return notBefore date
     */
    public Date getNotBefore() {
        return (notBefore);
    }

    /**
     * Return notAfter date
     */
    public Date getNotAfter() {
        return (notAfter);
    }

    /**
     * Verify that that the current time is within the validity period.
     *
     * @exception CertificateExpiredException if the certificate has expired.
     * @exception CertificateNotYetValidException if the certificate is not
     *                yet valid.
     */
    public void valid()
            throws CertificateNotYetValidException, CertificateExpiredException {
        Date now = new Date();
        valid(now);
    }

    /**
     * Verify that that the passed time is within the validity period.
     *
     * @exception CertificateExpiredException if the certificate has expired
     *                with respect to the <code>Date</code> supplied.
     * @exception CertificateNotYetValidException if the certificate is not
     *                yet valid with respect to the <code>Date</code> supplied.
     *
     */
    public void valid(Date now)
            throws CertificateNotYetValidException, CertificateExpiredException {
        /*
         * we use the internal Dates rather than the passed in Date
         * because someone could override the Date methods after()
         * and before() to do something entirely different.
         */
        if (notBefore.after(now)) {
            throw new CertificateNotYetValidException("NotBefore: " +
                                                      notBefore.toString());
        }
        if (notAfter.before(now)) {
            throw new CertificateExpiredException("NotAfter: " +
                                                  notAfter.toString());
        }
    }

    /**
     * Write the extension to the OutputStream.
     *
     * @param out the OutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
            extensionId = PKIXExtensions.PrivateKeyUsage_Id;
            critical = false;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Decode the extension from the InputStream.
     *
     * @param in the InputStream to unmarshal the contents from.
     * @exception CertificateException on decoding errors.
     */
    public void decode(InputStream in) throws CertificateException {
        throw new CertificateException("Method not to be called directly.");
    }

    /**
     * Set the attribute value.
     *
     * @exception CertificateException on attribute handling errors.
     */
    public void set(String name, Object obj)
            throws CertificateException {
        clearValue();
        if (!(obj instanceof Date)) {
            throw new CertificateException("Attribute must be of type Date.");
        }
        if (name.equalsIgnoreCase(NOT_BEFORE)) {
            notBefore = (Date) obj;
        } else if (name.equalsIgnoreCase(NOT_AFTER)) {
            notAfter = (Date) obj;
        } else {
            throw new CertificateException("Attribute name not recognized by"
                           + " CertAttrSet:PrivateKeyUsage.");
        }
    }

    /**
     * Get the attribute value.
     *
     * @exception CertificateException on attribute handling errors.
     */
    public Object get(String name) throws CertificateException {
        if (name.equalsIgnoreCase(NOT_BEFORE)) {
            return (new Date(notBefore.getTime()));
        } else if (name.equalsIgnoreCase(NOT_AFTER)) {
            return (new Date(notAfter.getTime()));
        } else {
            throw new CertificateException("Attribute name not recognized by"
                           + " CertAttrSet:PrivateKeyUsage.");
        }
    }

    /**
     * Delete the attribute value.
     *
     * @exception CertificateException on attribute handling errors.
     */
    public void delete(String name) throws CertificateException {
        if (name.equalsIgnoreCase(NOT_BEFORE)) {
            notBefore = null;
        } else if (name.equalsIgnoreCase(NOT_AFTER)) {
            notAfter = null;
        } else {
            throw new CertificateException("Attribute name not recognized by"
                           + " CertAttrSet:PrivateKeyUsage.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(NOT_BEFORE);
        elements.addElement(NOT_AFTER);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
