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
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.BigInt;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * Represent the CRL Number Extension.
 *
 * <p>
 * This extension, if present, conveys a monotonically increasing sequence number for each CRL issued by a given CA
 * through a specific CA X.500 Directory entry or CRL distribution point. This extension allows users to easily
 * determine when a particular CRL supersedes another CRL.
 *
 * @author Hemma Prafullchandra
 * @version 1.2
 * @see Extension
 * @see CertAttrSet
 */
public class CRLNumberExtension extends Extension
        implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = 2992307666566322402L;
    /**
     * Attribute name.
     */
    public static final String NAME = "CRLNumber";
    public static final String NUMBER = "value";

    private BigInt crlNumber = null;

    // Encode this extension value
    private void encodeThis() throws IOException {
        if (crlNumber == null)
            throw new IOException("Unintialized CRL number extension");
        try (DerOutputStream os = new DerOutputStream()) {
            os.putInteger(this.crlNumber);
            this.extensionValue = os.toByteArray();
        }
    }

    /**
     * Create a CRLNumberExtension with the integer value .
     * The criticality is set to false.
     *
     * @param crlNum the value to be set for the extension.
     */
    public CRLNumberExtension(int crlNum) throws IOException {
        this.crlNumber = new BigInt(crlNum);
        this.extensionId = PKIXExtensions.CRLNumber_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create a CRLNumberExtension with the BigInteger value .
     * The criticality is set to false.
     *
     * @param crlNum the value to be set for the extension.
     */
    public CRLNumberExtension(BigInteger crlNum) throws IOException {
        this.crlNumber = new BigInt(crlNum);
        this.extensionId = PKIXExtensions.CRLNumber_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create a CRLNumberExtension with the BigInteger value .
     *
     * @param critical true if the extension is to be treated as critical.
     * @param crlNum the value to be set for the extension.
     */
    public CRLNumberExtension(Boolean critical, BigInteger crlNum) throws IOException {
        this.crlNumber = new BigInt(crlNum);
        this.extensionId = PKIXExtensions.CRLNumber_Id;
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
    public CRLNumberExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.CRLNumber_Id;
        this.critical = critical.booleanValue();

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        for (int i = 0; i < len; i++) {
            extValue[i] = Array.getByte(value, i);
        }
        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        this.crlNumber = val.getInteger();
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            if (!(obj instanceof BigInteger)) {
                throw new IOException("Attribute must be of type BigInteger.");
            }
            crlNumber = new BigInt((BigInteger) obj);
        } else {
            throw new IOException("Attribute name not recognized by"
                                + " CertAttrSet:CRLNumber.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            if (crlNumber == null)
                return null;
            else
                return crlNumber.toBigInteger();
        } else {
            throw new IOException("Attribute name not recognized by"
                                + " CertAttrSet:CRLNumber.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            crlNumber = null;
        } else {
            throw new IOException("Attribute name not recognized by"
                                + " CertAttrSet:CRLNumber.");
        }
    }

    /**
     * Returns a printable representation of the CRLNumberExtension.
     */
    public String toString() {
        String s = super.toString() + "CRL Number: " +
                   ((crlNumber == null) ? "" : crlNumber.toString())
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
            this.extensionId = PKIXExtensions.CRLNumber_Id;
            this.critical = false;
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
        elements.addElement(NUMBER);
        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
