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
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class defines the X509Key attribute for the Certificate.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.5
 * @see CertAttrSet
 */
public class CertificateX509Key implements CertAttrSet, Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 6718749024328681131L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.key";
    /**
     * Sub attributes name for this CertAttrSet.
     */
    public static final String NAME = "key";
    public static final String KEY = "value";

    // Private data member
    private X509Key key;

    /**
     * Default constructor for the certificate attribute.
     *
     * @param key the X509Key
     */
    public CertificateX509Key(X509Key key) {
        this.key = key;
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the X509Key from.
     * @exception IOException on decoding errors.
     */
    public CertificateX509Key(DerInputStream in) throws IOException {
        DerValue val = in.getDerValue();
        key = X509Key.parse(val);
    }

    /**
     * Create the object, decoding the values from the passed stream.
     *
     * @param in the InputStream to read the X509Key from.
     * @exception IOException on decoding errors.
     */
    public CertificateX509Key(InputStream in) throws IOException {
        DerValue val = new DerValue(in);
        key = X509Key.parse(val);
    }

    /**
     * Return the key as printable string.
     */
    public String toString() {
        if (key == null)
            return "";
        return (key.toString());
    }

    /**
     * Decode the key in DER form from the stream.
     *
     * @param in the InputStream to unmarshal the contents from
     * @exception IOException on decoding or validity errors.
     */
    public void decode(InputStream in) throws IOException {
        DerValue val = new DerValue(in);
        key = X509Key.parse(val);
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        encode(stream);
    }

    private void readObject(ObjectInputStream stream) throws IOException {
        decode(stream);
    }

    /**
     * Encode the key in DER form to the stream.
     *
     * @param out the OutputStream to marshal the contents to.
     * @exception IOException on errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        key.encode(tmp);

        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof X509Key)) {
            throw new IOException("Attribute must be of type X509Key.");
        }
        if (name.equalsIgnoreCase(KEY)) {
            this.key = (X509Key) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet: CertificateX509Key.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(KEY)) {
            return (key);
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet: CertificateX509Key.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(KEY)) {
            key = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet: CertificateX509Key.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(KEY);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
