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

import netscape.security.util.*;

/**
 * Represent the Subject Key Identifier Extension.
 *
 * This extension, if present, provides a means of identifying the particular
 * public key used in an application.  This extension by default is marked
 * non-critical.
 *
 * <p>Extensions are addiitonal attributes which can be inserted in a X509
 * v3 certificate. For example a "Driving License Certificate" could have
 * the driving license number as a extension.
 *
 * <p>Extensions are represented as a sequence of the extension identifier
 * (Object Identifier), a boolean flag stating whether the extension is to
 * be treated as being critical and the extension value itself (this is again
 * a DER encoding of the extension value).
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.7
 * @see Extension
 * @see CertAttrSet
 */
public class SubjectKeyIdentifierExtension extends Extension
implements CertAttrSet {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */  
    public static final String IDENT =
                         "x509.info.extensions.SubjectKeyIdentifier";
    /**
     * Attribute names.
     */
    public static final String NAME = "SubjectKeyIdentifier";
    public static final String KEY_ID = "key_id";

    // Private data member
    private KeyIdentifier id;

    // Encode this extension value
    private void encodeThis() throws IOException {
        DerOutputStream os = new DerOutputStream();
        id.encode(os);
        extensionValue = os.toByteArray();
    }

    /**
     * Create a SubjectKeyIdentifierExtension with the passed octet string.
     * The criticality is set to False.
     * @param octetString the octet string identifying the key identifier.
     */
    public SubjectKeyIdentifierExtension (boolean critical, byte[] octetString)
    throws IOException {
        id = new KeyIdentifier(octetString);

        this.extensionId = PKIXExtensions.SubjectKey_Id;
        this.critical = critical;
        encodeThis();
    }
    public SubjectKeyIdentifierExtension (byte[] octetString)
    throws IOException {
        id = new KeyIdentifier(octetString);

        this.extensionId = PKIXExtensions.SubjectKey_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create the extension from the passed DER encoded value.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public SubjectKeyIdentifierExtension(Boolean critical, Object value)
    throws IOException {
        this.extensionId = PKIXExtensions.SubjectKey_Id;
        this.critical = critical.booleanValue();

        int len = Array.getLength(value);
	byte[] extValue = new byte[len];
	for (int i = 0; i < len; i++) {
	  extValue[i] = Array.getByte(value,i);
	}
        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        this.id = new KeyIdentifier(val);
    }

    /**
     * Returns a printable representation.
     */
    public String toString() {
        if (id == null) return "";
        String s = super.toString() + "SubjectKeyIdentifier [\n"
                 + id.toString() + "]\n";
        return (s);
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
            extensionId = PKIXExtensions.SubjectKey_Id;
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
     * @exception IOException on decoding or validity errors.
     */
    public void decode(InputStream in) throws IOException {
        throw new IOException("Method not to be called directly.");
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
	clearValue();
	if (name.equalsIgnoreCase(KEY_ID)) {
	    if (!(obj instanceof KeyIdentifier)) {
	      throw new IOException("Attribute value should be of" +
                                    " type KeyIdentifier.");
	    }
	    id = (KeyIdentifier)obj;
	} else {
	  throw new IOException("Attribute name not recognized by " + 
		"CertAttrSet:SubjectKeyIdentifierExtension.");
	}
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
	if (name.equalsIgnoreCase(KEY_ID)) {
	    return (id);
	} else {
	  throw new IOException("Attribute name not recognized by " + 
		"CertAttrSet:SubjectKeyIdentifierExtension.");
	}
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
	if (name.equalsIgnoreCase(KEY_ID)) {
	    id = null;
	} else {
	  throw new IOException("Attribute name not recognized by " + 
		"CertAttrSet:SubjectKeyIdentifierExtension.");
	}
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration getElements () {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(KEY_ID);

	return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName () {
        return (NAME);
    }
}
