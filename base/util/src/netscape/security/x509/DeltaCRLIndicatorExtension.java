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
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.BigInt;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * Represent the Delta CRL Indicator Extension.
 *
 * <p>
 * The delta CRL indicator is a critical CRL extension that identifies a delta-CRL. The value of BaseCRLNumber
 * identifies the CRL number of the base CRL that was used as the starting point in the generation of this delta- CRL.
 * The delta-CRL contains the changes between the base CRL and the current CRL issued along with the delta-CRL.
 *
 * @see Extension
 * @see CertAttrSet
 */
public class DeltaCRLIndicatorExtension extends Extension
        implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = 7182919216525364676L;
    /**
     * Attribute name.
     */
    public static final String NAME = "DeltaCRLIndicator";
    public static final String NUMBER = "value";

    /**
     * The Object Identifier for this extension.
     */
    public static final String OID = "2.5.29.27";

    private BigInt baseCRLNumber = null;

    static {
        try {
            OIDMap.addAttribute(DeltaCRLIndicatorExtension.class.getName(),
                                OID, NAME);
        } catch (CertificateException e) {
        }
    }

    // Encode this extension value
    private void encodeThis() throws IOException {
        if (baseCRLNumber == null)
            throw new IOException("Unintialized delta CRL indicator extension");
        try (DerOutputStream os = new DerOutputStream()) {
            os.putInteger(this.baseCRLNumber);
            this.extensionValue = os.toByteArray();
        }
    }

    /**
     * Create a DeltaCRLIndicatorExtension with the integer value.
     * The criticality is set to true.
     *
     * @param baseCRLNum the value to be set for the extension.
     */
    public DeltaCRLIndicatorExtension(int baseCRLNum) throws IOException {
        this.baseCRLNumber = new BigInt(baseCRLNum);
        this.extensionId = PKIXExtensions.DeltaCRLIndicator_Id;
        this.critical = true;
        encodeThis();
    }

    /**
     * Create a DeltaCRLIndicatorExtension with the BigInteger value.
     * The criticality is set to true.
     *
     * @param baseCRLNum the value to be set for the extension.
     */
    public DeltaCRLIndicatorExtension(BigInteger baseCRLNum) throws IOException {
        this.baseCRLNumber = new BigInt(baseCRLNum);
        this.extensionId = PKIXExtensions.DeltaCRLIndicator_Id;
        this.critical = true;
        encodeThis();
    }

    /**
     * Create a DeltaCRLIndicatorExtension with the BigInteger value.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param baseCRLNum the value to be set for the extension.
     */
    public DeltaCRLIndicatorExtension(Boolean critical, BigInteger baseCRLNum)
            throws IOException {
        this.baseCRLNumber = new BigInt(baseCRLNum);
        this.extensionId = PKIXExtensions.DeltaCRLIndicator_Id;
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
    public DeltaCRLIndicatorExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.DeltaCRLIndicator_Id;
        this.critical = critical.booleanValue();

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        for (int i = 0; i < len; i++) {
            extValue[i] = Array.getByte(value, i);
        }
        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        this.baseCRLNumber = val.getInteger();
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            if (!(obj instanceof BigInteger)) {
                throw new IOException("Attribute must be of type BigInteger.");
            }
            baseCRLNumber = new BigInt((BigInteger) obj);
        } else {
            throw new IOException("Attribute name not recognized by" +
                                  " CertAttrSet:DeltaCRLIndicator.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            if (baseCRLNumber == null)
                return null;
            else
                return baseCRLNumber.toBigInteger();
        } else {
            throw new IOException("Attribute name not recognized by" +
                                  " CertAttrSet:DeltaCRLIndicator.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            baseCRLNumber = null;
        } else {
            throw new IOException("Attribute name not recognized by" +
                                  " CertAttrSet:DeltaCRLIndicator.");
        }
    }

    /**
     * Returns a printable representation of the DeltaCRLIndicatorExtension.
     */
    public String toString() {
        String s = super.toString() + "Delta CRL Indicator: " +
                   ((baseCRLNumber == null) ? "" : baseCRLNumber.toString())
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
            this.extensionId = PKIXExtensions.DeltaCRLIndicator_Id;
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
