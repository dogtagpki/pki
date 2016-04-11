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
 * This represents the Subject Alternative Name Extension.
 *
 * This extension, if present, allows the subject to specify multiple
 * alternative names.
 *
 * <p>
 * Extensions are represented as a sequence of the extension identifier (Object Identifier), a boolean flag stating
 * whether the extension is to be treated as being critical and the extension value itself (this is again a DER encoding
 * of the extension value).
 * <p>
 * The ASN.1 syntax for this is:
 *
 * <pre>
 * SubjectAltName ::= GeneralNames
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 * </pre>
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.9
 * @see Extension
 * @see CertAttrSet
 */
public class SubjectAlternativeNameExtension extends Extension
        implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = -4022446008355607196L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT =
                         "x509.info.extensions.SubjectAlternativeName";
    /**
     * Attribute names.
     */
    public static final String NAME = "SubjectAlternativeName";
    public static final String SUBJECT_NAME = "subject_name";

    // private data members
    GeneralNames names;

    // Encode this extension
    private void encodeThis() throws IOException {
        DerOutputStream os = new DerOutputStream();
        try {
            names.encode(os);
        } catch (GeneralNamesException e) {
            throw new IOException("SubjectAlternativeName: " + e);
        }
        extensionValue = os.toByteArray();
    }

    /**
     * Create a SubjectAlternativeNameExtension with the passed GeneralNames.
     *
     * @param names the GeneralNames for the subject.
     * @exception IOException on error.
     */
    public SubjectAlternativeNameExtension(boolean critical, GeneralNames names)
            throws IOException {
        this.names = names;
        this.extensionId = PKIXExtensions.SubjectAlternativeName_Id;
        this.critical = critical;
        encodeThis();
    }

    public SubjectAlternativeNameExtension(GeneralNames names)
            throws IOException {
        this.names = names;
        this.extensionId = PKIXExtensions.SubjectAlternativeName_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create a default SubjectAlternativeNameExtension.
     */
    public SubjectAlternativeNameExtension() {
        extensionId = PKIXExtensions.SubjectAlternativeName_Id;
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
    public SubjectAlternativeNameExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.SubjectAlternativeName_Id;
        this.critical = critical.booleanValue();

        if (!(value instanceof byte[]))
            throw new IOException("SubjectAlternativeName: "
                                  + "Illegal argument type");

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        System.arraycopy(value, 0, extValue, 0, len);

        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        try {
            names = new GeneralNames(val);
        } catch (GeneralNamesException e) {
            throw new IOException("SubjectAlternativeName: " + e, e);
        }
    }

    /**
     * Returns a printable representation of the SubjectAlternativeName.
     */
    public String toString() {
        if (names == null)
            return "";
        String s = super.toString() + "SubjectAlternativeName [\n"
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
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
            extensionId = PKIXExtensions.SubjectAlternativeName_Id;
            //critical = false;
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
        if (name.equalsIgnoreCase(SUBJECT_NAME)) {
            if (!(obj instanceof GeneralNames)) {
                throw new IOException("Attribute value should be of " +
                                    "type GeneralNames.");
            }
            names = (GeneralNames) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:SubjectAlternativeName.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(SUBJECT_NAME)) {
            return (names);
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:SubjectAlternativeName.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(SUBJECT_NAME)) {
            names = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:SubjectAlternativeName.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(SUBJECT_NAME);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
