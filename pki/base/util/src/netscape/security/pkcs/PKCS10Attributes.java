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
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import netscape.security.util.*;

/**
 * This class defines the PKCS10 attributes for the request.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.10
 */
public class PKCS10Attributes extends Vector implements DerEncoder {

    private Hashtable map;

    /**
     * Default constructor for the certificate attribute.
     */
    public PKCS10Attributes() {
        map = new Hashtable();
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the attributes from.
     * @exception IOException on decoding errors.
     */
    public PKCS10Attributes(DerInputStream in)
    throws IOException {

        map = new Hashtable();
        DerValue [] attrs = in.getSet(5,true);

	if (attrs != null) {
	    for (int i = 0; i < attrs.length; i++) {
	        PKCS10Attribute attr = new PKCS10Attribute(attrs[i]);
		addElement(attr);
		map.put(attr.getAttributeValue().getName(),attr);
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

	// first copy the elements into an array
	PKCS10Attribute[] attribs = new PKCS10Attribute[size()];
	copyInto(attribs);

	DerOutputStream attrOut = new DerOutputStream();
	attrOut.putOrderedSetOf(DerValue.createTag(DerValue.TAG_CONTEXT,true,(byte)0), 
			 attribs);

        out.write(attrOut.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void setAttribute(String name, Object obj) throws IOException {
        map.put(name,obj);
        addElement(obj);
    }

    /**
     * Get the attribute value.
     */
    public Object getAttribute(String name) throws IOException {
        Object obj = map.get(name);
		/*
        if (obj == null) {
            throw new IOException("No attribute found with name " + name);
        }
		*/
        return (obj);
    }

    /**
     * Delete the attribute value.
     */
    public void deleteAttribute(String name) throws IOException {
        Object obj = map.get(name);
        if (obj == null) {
            throw new IOException("No attribute found with name " + name);
        }
        map.remove(name);
        removeElement(obj);
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration getElements () {
        return (map.elements());
    }
}
