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
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class defines the subject/issuer unique identity attribute
 * for the Certificate.
 * 
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.6
 * @see CertAttrSet
 */
public class CertificateSubjectUniqueIdentity implements CertAttrSet {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.subjectID";
    /**
     * Sub attributes name for this CertAttrSet.
     */
    public static final String NAME = "subjectID";
    public static final String ID = "id";

    private UniqueIdentity id;

    /**
     * Default constructor for the certificate attribute.
     * 
     * @param key the UniqueIdentity
     */
    public CertificateSubjectUniqueIdentity(UniqueIdentity id) {
        this.id = id;
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     * 
     * @param in the DerInputStream to read the UniqueIdentity from.
     * @exception IOException on decoding errors.
     */
    public CertificateSubjectUniqueIdentity(DerInputStream in)
            throws IOException {
        id = new UniqueIdentity(in);
    }

    /**
     * Create the object, decoding the values from the passed stream.
     * 
     * @param in the InputStream to read the UniqueIdentity from.
     * @exception IOException on decoding errors.
     */
    public CertificateSubjectUniqueIdentity(InputStream in)
            throws IOException {
        DerValue val = new DerValue(in);
        id = new UniqueIdentity(val);
    }

    /**
     * Create the object, decoding the values from the passed DER value.
     * 
     * @param in the DerValue to read the UniqueIdentity from.
     * @exception IOException on decoding errors.
     */
    public CertificateSubjectUniqueIdentity(DerValue val)
            throws IOException {
        id = new UniqueIdentity(val);
    }

    /**
     * Return the identity as user readable string.
     */
    public String toString() {
        if (id == null)
            return "";
        return (id.toString());
    }

    /**
     * Decode the identity in DER form from the stream.
     * 
     * @param in the InputStream to unmarshal the contents from.
     * @exception IOException on errors.
     */
    public void decode(InputStream in) throws IOException {
        DerValue val = new DerValue(in);
        id = new UniqueIdentity(val);
    }

    /**
     * Encode the identity in DER form to the stream.
     * 
     * @param out the DerOutputStream to marshal the contents to.
     * @exception IOException on errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        id.encode(tmp, DerValue.createTag(DerValue.TAG_CONTEXT, false, (byte) 2));

        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof UniqueIdentity)) {
            throw new IOException("Attribute must be of type UniqueIdentity.");
        }
        if (name.equalsIgnoreCase(ID)) {
            id = (UniqueIdentity) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                      "CertAttrSet: CertificateSubjectUniqueIdentity.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(ID)) {
            return (id);
        } else {
            throw new IOException("Attribute name not recognized by " +
                      "CertAttrSet: CertificateSubjectUniqueIdentity.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(ID)) {
            id = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                      "CertAttrSet: CertificateSubjectUniqueIdentity.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(ID);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
