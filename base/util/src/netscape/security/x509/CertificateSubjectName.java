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
 * This class defines the X500Name attribute for the Certificate.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.6
 * @see CertAttrSet
 */
public class CertificateSubjectName implements CertAttrSet, Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 503643453152834350L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.subject";
    /**
     * Sub attributes name for this CertAttrSet.
     */
    public static final String NAME = "subject";
    public static final String DN_NAME = "dname";

    // Private data member
    private X500Name dnName;

    /**
     * Default constructor for the certificate attribute.
     *
     * @param name the X500Name
     */
    public CertificateSubjectName(X500Name name) {
        this.dnName = name;
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the X500Name from.
     * @exception IOException on decoding errors.
     */
    public CertificateSubjectName(DerInputStream in) throws IOException {
        dnName = new X500Name(in);
    }

    /**
     * Create the object, decoding the values from the passed stream.
     *
     * @param in the InputStream to read the X500Name from.
     * @exception IOException on decoding errors.
     */
    public CertificateSubjectName(InputStream in) throws IOException {
        DerValue derVal = new DerValue(in);
        dnName = new X500Name(derVal);
    }

    /**
     * Return the name as user readable string.
     */
    public String toString() {
        if (dnName == null)
            return "";
        return (dnName.toString());
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        encode(stream);
    }

    private void readObject(ObjectInputStream stream) throws IOException {
        decodeEx(stream);
    }

    /**
     * Encode the name in DER form to the stream.
     *
     * @param out the DerOutputStream to marshal the contents to.
     * @exception IOException on errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        dnName.encode(tmp);

        out.write(tmp.toByteArray());
    }

    /**
     * Decode the name in DER form from the stream.
     *
     * @param in the InputStream to marshal the contents from.
     * @exception IOException on errors.
     */
    public void decodeEx(InputStream in) throws IOException {
        DerValue derVal = new DerValue(in);

        // dnName = new X500Name(derVal);
        dnName = new X500Name(derVal.toByteArray());
    }

    /**
     * Decode the name in DER form from the stream.
     *
     * @param in the InputStream to marshal the contents from.
     * @exception IOException on errors.
     */
    public void decode(InputStream in) throws IOException {
        DerValue derVal = new DerValue(in);

        dnName = new X500Name(derVal);
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof X500Name)) {
            throw new IOException("Attribute must be of type X500Name.");
        }
        if (name.equalsIgnoreCase(DN_NAME)) {
            this.dnName = (X500Name) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet:CertificateSubjectName.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(DN_NAME)) {
            return (dnName);
        } else {
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet:CertificateSubjectName.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(DN_NAME)) {
            dnName = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet:CertificateSubjectName.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(DN_NAME);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
