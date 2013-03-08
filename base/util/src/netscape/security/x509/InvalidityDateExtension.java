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
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * Represent the CRL Invalidity Date Extension.
 *
 * <p>
 * This CRL entry extension, if present, provides the date on which it is known or suspected that the private key was
 * compromised or that the certificate otherwise became invalid. Invalidity date may be earlier than the revocation
 * date.
 *
 * @see Extension
 * @see CertAttrSet
 */

public class InvalidityDateExtension extends Extension
        implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = 2191026017389643053L;
    /**
     * Attribute name.
     */
    public static final String NAME = "InvalidityDate";
    public static final String INVALIDITY_DATE = "value";

    /**
     * The Object Identifier for this extension.
     */
    public static final String OID = "2.5.29.24";

    private Date invalidityDate = null;

    static {
        try {
            OIDMap.addAttribute(InvalidityDateExtension.class.getName(),
                                OID, NAME);
        } catch (CertificateException e) {
        }
    }

    // Encode this extension value
    private void encodeThis() throws IOException {
        if (invalidityDate == null)
            throw new IOException("Unintialized invalidity date extension");
        try (DerOutputStream os = new DerOutputStream()) {
            os.putGeneralizedTime(this.invalidityDate);
            this.extensionValue = os.toByteArray();
        }
    }

    /**
     * Create a InvalidityDateExtension with the date.
     * The criticality is set to false.
     *
     * @param dateOfInvalidity the value to be set for the extension.
     */
    public InvalidityDateExtension(Date dateOfInvalidity)
            throws IOException {
        this.invalidityDate = dateOfInvalidity;
        this.extensionId = PKIXExtensions.InvalidityDate_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create a InvalidityDateExtension with the date.
     * The criticality is set to false.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param dateOfInvalidity the value to be set for the extension.
     */
    public InvalidityDateExtension(Boolean critical, Date dateOfInvalidity)
            throws IOException {
        this.invalidityDate = dateOfInvalidity;
        this.extensionId = PKIXExtensions.InvalidityDate_Id;
        this.critical = critical.booleanValue();
        encodeThis();
    }

    /**
     * Create the extension from the passed DER encoded value of the same.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public InvalidityDateExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.InvalidityDate_Id;
        this.critical = critical.booleanValue();

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        for (int i = 0; i < len; i++) {
            extValue[i] = Array.getByte(value, i);
        }
        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        if (val.tag == DerValue.tag_GeneralizedTime) {
            DerInputStream derInputStream = new DerInputStream(val.toByteArray());
            this.invalidityDate = derInputStream.getGeneralizedTime();
        } else {
            throw new IOException("Invalid encoding for InvalidityDateExtension");
        }
    }

    /**
     * Get the invalidity date.
     */
    public Date getInvalidityDate() {
        return invalidityDate;
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(INVALIDITY_DATE)) {
            if (!(obj instanceof Date)) {
                throw new IOException("Attribute must be of type Date.");
            }
            invalidityDate = (Date) obj;
        } else {
            throw new IOException("Attribute name not recognized by" +
                                  " CertAttrSet:InvalidityDate.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(INVALIDITY_DATE)) {
            if (invalidityDate == null)
                return null;
            else
                return invalidityDate;
        } else {
            throw new IOException("Attribute name not recognized by" +
                                  " CertAttrSet:InvalidityDate.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(INVALIDITY_DATE)) {
            invalidityDate = null;
        } else {
            throw new IOException("Attribute name not recognized by" +
                                  " CertAttrSet:InvalidityDate.");
        }
    }

    /**
     * Returns a printable representation of the InvalidityDateExtension.
     */
    public String toString() {
        String s = super.toString() + "Invalidity Date: " +
                   ((invalidityDate == null) ? "" : invalidityDate.toString())
                   + "\n";
        return (s);
    }

    /**
     * Decode the extension from the InputStream.
     *
     * @param in the InputStream to unmarshal the contents from.
     * @exception IOException on decoding or validity errors.
     */
    public void decode(InputStream in) throws IOException {
        throw new IOException("Method not to be called directly.");
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        if (this.extensionValue == null) {
            this.extensionId = PKIXExtensions.InvalidityDate_Id;
            this.critical = true;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(INVALIDITY_DATE);
        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
