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
package netscape.security.pkcs;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import netscape.security.util.DerEncoder;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class defines the PKCS10 attributes for the request.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.10
 */
public class PKCS10Attributes extends Vector<PKCS10Attribute> implements DerEncoder {

    /**
     *
     */
    private static final long serialVersionUID = 1362260612357629542L;
    private Hashtable<String, PKCS10Attribute> map;

    /**
     * Default constructor for the certificate attribute.
     */
    public PKCS10Attributes() {
        map = new Hashtable<String, PKCS10Attribute>();
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the attributes from.
     * @exception IOException on decoding errors.
     */
    public PKCS10Attributes(DerInputStream in)
            throws IOException {

        map = new Hashtable<String, PKCS10Attribute>();
        DerValue[] attrs = in.getSet(5, true);

        if (attrs != null) {
            for (int i = 0; i < attrs.length; i++) {
                PKCS10Attribute attr = new PKCS10Attribute(attrs[i]);
                addElement(attr);
                map.put(attr.getAttributeValue().getName(), attr);
            }
        }
    }

    /**
     * Encode the attributes in DER form to the stream.
     *
     * @param out the OutputStream to marshal the contents to.
     *
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out)
            throws IOException {
        derEncode(out);
    }

    /**
     * Encode the attributes in DER form to the stream.
     * Implements the <code>DerEncoder</code> interface.
     *
     * @param out the OutputStream to marshal the contents to.
     * @exception IOException on encoding errors.
     */
    public void derEncode(OutputStream out)
            throws IOException {
        try (DerOutputStream attrOut = new DerOutputStream()) {
            // first copy the elements into an array
            PKCS10Attribute[] attribs = new PKCS10Attribute[size()];
            copyInto(attribs);

            attrOut.putOrderedSetOf(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0),
                    attribs);

            out.write(attrOut.toByteArray());
        } catch (IOException e) {
            throw e;
        }
    }

    /**
     * Set the attribute value.
     */
    public void setAttribute(String name, PKCS10Attribute attr) throws IOException {
        map.put(name, attr);
        addElement(attr);
    }

    /**
     * Get the attribute value.
     */
    public PKCS10Attribute getAttribute(String name) throws IOException {
        PKCS10Attribute attr = map.get(name);
        /*
        if (attr == null) {
            throw new IOException("No attribute found with name " + name);
        }
        */
        return (attr);
    }

    /**
     * Delete the attribute value.
     */
    public void deleteAttribute(String name) throws IOException {
        PKCS10Attribute attr = map.get(name);
        if (attr == null) {
            throw new IOException("No attribute found with name " + name);
        }
        map.remove(name);
        removeElement(attr);
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<PKCS10Attribute> getElements() {
        return map.elements();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((map == null) ? 0 : map.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        PKCS10Attributes other = (PKCS10Attributes) obj;
        if (map == null) {
            if (other.map != null)
                return false;
        } else if (!map.equals(other.map))
            return false;
        return true;
    }

}
