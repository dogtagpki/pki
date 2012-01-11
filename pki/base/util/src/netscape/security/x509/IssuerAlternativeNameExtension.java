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
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This represents the Issuer Alternative Name Extension.
 * 
 * This extension, if present, allows the issuer to specify multiple
 * alternative names.
 * 
 * <p>
 * Extensions are represented as a sequence of the extension identifier (Object Identifier), a boolean flag stating whether the extension is to be treated as being critical and the extension value itself (this is again a DER encoding of the extension value).
 * 
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.7
 * @see Extension
 * @see CertAttrSet
 */
public class IssuerAlternativeNameExtension
        extends Extension implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = -269518027483586255L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT =
                         "x509.info.extensions.IssuerAlternativeName";
    /**
     * Attribute names.
     */
    public static final String NAME = "IssuerAlternativeName";
    public static final String ISSUER_NAME = "issuer_name";

    // private data members
    GeneralNames names;

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
     * Create a IssuerAlternativeNameExtension with the passed GeneralNames.
     * 
     * @param critical true if the extension is to be treated as critical.
     * @param names the GeneralNames for the issuer.
     * @exception IOException on error.
     */
    public IssuerAlternativeNameExtension(Boolean critical, GeneralNames names)
            throws IOException {
        this.names = names;
        this.extensionId = PKIXExtensions.IssuerAlternativeName_Id;
        this.critical = critical.booleanValue();
        encodeThis();
    }

    /**
     * Create a IssuerAlternativeNameExtension with the passed GeneralNames.
     * 
     * @param names the GeneralNames for the issuer.
     * @exception IOException on error.
     */
    public IssuerAlternativeNameExtension(GeneralNames names)
            throws IOException {
        this.names = names;
        this.extensionId = PKIXExtensions.IssuerAlternativeName_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create a default IssuerAlternativeNameExtension.
     */
    public IssuerAlternativeNameExtension() {
        extensionId = PKIXExtensions.IssuerAlternativeName_Id;
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
    public IssuerAlternativeNameExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.IssuerAlternativeName_Id;
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
            throw new IOException("IssuerAlternativeNameExtension"
                                  + e.toString());
        }
    }

    /**
     * Returns a printable representation of the IssuerAlternativeName.
     */
    public String toString() {
        if (names == null)
            return "";
        String s = super.toString() + "IssuerAlternativeName [\n"
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
            extensionId = PKIXExtensions.IssuerAlternativeName_Id;
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
        clearValue();
        if (name.equalsIgnoreCase(ISSUER_NAME)) {
            if (!(obj instanceof GeneralNames)) {
                throw new IOException("Attribute value should be of" +
                                    " type GeneralNames.");
            }
            names = (GeneralNames) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:IssuerAlternativeName.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(ISSUER_NAME)) {
            return (names);
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:IssuerAlternativeName.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(ISSUER_NAME)) {
            names = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:IssuerAlternativeName.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(ISSUER_NAME);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
