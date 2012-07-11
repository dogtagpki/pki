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
 * This class defines the AlgorithmId for the Certificate.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.7
 */
public class CertificateAlgorithmId implements CertAttrSet, Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 6084780721443376563L;

    private AlgorithmId algId;

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.algorithmID";
    /**
     * Sub attributes name for this CertAttrSet.
     */
    public static final String NAME = "algorithmID";
    public static final String ALGORITHM = "algorithm";

    /**
     * Default constructor for the certificate attribute.
     *
     * @param algId the Algorithm identifier
     */
    public CertificateAlgorithmId(AlgorithmId algId) {
        this.algId = algId;
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the serial number from.
     * @exception IOException on decoding errors.
     */
    public CertificateAlgorithmId(DerInputStream in) throws IOException {
        DerValue val = in.getDerValue();
        algId = AlgorithmId.parse(val);
    }

    /**
     * Create the object, decoding the values from the passed stream.
     *
     * @param in the InputStream to read the serial number from.
     * @exception IOException on decoding errors.
     */
    public CertificateAlgorithmId(InputStream in) throws IOException {
        DerValue val = new DerValue(in);
        algId = AlgorithmId.parse(val);
    }

    /**
     * Return the algorithm identifier as user readable string.
     */
    public String toString() {
        if (algId == null)
            return "";
        return (algId.toString() +
                ", OID = " + (algId.getOID()).toString() + "\n");
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        encode(stream);
    }

    private void readObject(ObjectInputStream stream) throws IOException {
        decode(stream);
    }

    /**
     * Encode the algorithm identifier in DER form to the stream.
     *
     * @param out the DerOutputStream to marshal the contents to.
     * @exception IOException on errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        algId.encode(tmp);

        out.write(tmp.toByteArray());
    }

    /**
     * Decode the algorithm identifier from the passed stream.
     *
     * @param in the InputStream to unmarshal the contents from.
     * @exception IOException on errors.
     */
    public void decode(InputStream in) throws IOException {
        DerValue derVal = new DerValue(in);
        algId = AlgorithmId.parse(derVal);
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof AlgorithmId)) {
            throw new IOException("Attribute must be of type AlgorithmId.");
        }
        if (name.equalsIgnoreCase(ALGORITHM)) {
            algId = (AlgorithmId) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                              "CertAttrSet:CertificateAlgorithmId.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(ALGORITHM)) {
            return (algId);
        } else {
            throw new IOException("Attribute name not recognized by " +
                               "CertAttrSet:CertificateAlgorithmId.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(ALGORITHM)) {
            algId = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                               "CertAttrSet:CertificateAlgorithmId.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(ALGORITHM);
        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
