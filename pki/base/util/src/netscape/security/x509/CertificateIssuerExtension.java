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
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * Represent the CRL Certificate Issuer Extension.
 * 
 * <p>
 * This CRL entry extension identifies the certificate issuer associated with an entry in an indirect CRL, i.e. a CRL
 * that has the indirectCRL indicator set in its issuing distribution point extension.
 * 
 * @see Extension
 * @see CertAttrSet
 */

public class CertificateIssuerExtension extends Extension
                                        implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = 8643788952936025986L;
    /**
     * Attribute name.
     */
    public static final String NAME = "CertificateIssuer";
    public static final String CERTIFICATE_ISSUER = "value";

    /**
     * The Object Identifier for this extension.
     */
    public static final String OID = "2.5.29.29";

    // private data members
    GeneralNames names = null;

    static {
        try {
            OIDMap.addAttribute(CertificateIssuerExtension.class.getName(),
                                OID, NAME);
        } catch (CertificateException e) {
        }
    }

    // Encode this extension
    private void encodeThis() throws IOException {
        DerOutputStream os = new DerOutputStream();
        try {
            names.encode(os);
        } catch (GeneralNamesException e) {
            throw new IOException(e.toString());
        }
        this.extensionValue = os.toByteArray();
    }

    /**
     * Create a CertificateIssuerExtension with the passed GeneralNames
     * and criticality.
     * 
     * @param critical true if the extension is to be treated as critical.
     * @param names the GeneralNames for the issuer.
     * @exception IOException on error.
     */
    public CertificateIssuerExtension(Boolean critical, GeneralNames names)
            throws IOException {
        this.names = names;
        this.extensionId = PKIXExtensions.CertificateIssuer_Id;
        this.critical = critical.booleanValue();
        encodeThis();
    }

    /**
     * Create a CertificateIssuerExtension with the passed GeneralNames.
     * 
     * @param names the GeneralNames for the issuer.
     * @exception IOException on error.
     */
    public CertificateIssuerExtension(GeneralNames names)
            throws IOException {
        this.names = names;
        this.extensionId = PKIXExtensions.CertificateIssuer_Id;
        this.critical = true;
        encodeThis();
    }

    /**
     * Create a default CertificateIssuerExtension.
     */
    public CertificateIssuerExtension() {
        extensionId = PKIXExtensions.CertificateIssuer_Id;
        critical = false;
        names = new GeneralNames();
    }

    /**
     * Create the extension from the passed DER encoded value.
     * 
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public CertificateIssuerExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.CertificateIssuer_Id;
        this.critical = critical.booleanValue();

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        for (int i = 0; i < len; i++) {
            extValue[i] = Array.getByte(value, i);
        }
        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        try {
            names = new GeneralNames(val);
        } catch (GeneralNamesException e) {
            throw new IOException("CertificateIssuerExtension: " +
                                  e.toString());
        }
    }

    /**
     * Returns a printable representation of the CertificateIssuerName.
     */
    public String toString() {
        if (names == null)
            return "";
        String s = super.toString() + "CertificateIssuerName [\n"
                  + names.toString() + "]\n";
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
     * Write the extension to the OutputStream.
     * 
     * @param out the OutputStream to write the extension to.
     * @exception IOException on encoding error.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
            extensionId = PKIXExtensions.CertificateIssuer_Id;
            critical = false;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(CERTIFICATE_ISSUER)) {
            if (!(obj instanceof GeneralNames)) {
                throw new IOException("Attribute value should be of" +
                                      " type GeneralNames.");
            }
            names = (GeneralNames) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet:CertificateIssuerName.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(CERTIFICATE_ISSUER)) {
            return (names);
        } else {
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet:CertificateIssuerName.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(CERTIFICATE_ISSUER)) {
            names = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet:CertificateIssuerName.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(CERTIFICATE_ISSUER);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
