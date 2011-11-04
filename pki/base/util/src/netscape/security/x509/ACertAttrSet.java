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
import java.security.cert.CertificateException;
import java.util.Enumeration;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * A plain certattr set used by pkcs10 to parse an unknown attribute.
 * @author Lily Hsiao
 */
public class ACertAttrSet implements CertAttrSet {

	protected DerValue mDerValue = null;

	public ACertAttrSet(DerValue derValue) throws IOException {
		mDerValue = derValue;
	}

	public DerValue getDerValue() {
		return mDerValue;
	}

    /**
     * Returns a short string describing this certificate attribute.
     *
     * @return value of this certificate attribute in
     *         printable form.
     */
    public String toString() {
		return "ACertAttrSet value "+ (mDerValue == null ? "null" : "not null");
	}

    /**
     * Encodes the attribute to the output stream in a format
     * that can be parsed by the <code>decode</code> method.
     *
     * @param out the OutputStream to encode the attribute to.
     * 
     * @exception CertificateException on encoding or validity errors.
     * @exception IOException on other errors.
     */
    public void encode(OutputStream out)
        throws CertificateException, IOException {
		mDerValue.encode((DerOutputStream)out);
	}

    /**
     * Decodes the attribute in the input stream.
     *
     * @param in the InputStream to read the encoded attribute from.
     * 
     * @exception CertificateException on decoding or validity errors.
     * @exception IOException on other errors.
     */
    public void decode(InputStream in)
        throws CertificateException, IOException {
		throw new IOException("not supported");
	}

    /**
     * Sets an attribute value within this CertAttrSet.
     *
     * @param name the name of the attribute (e.g. "x509.info.key")
     * @param obj the attribute object.
     * 
     * @exception CertificateException on attribute handling errors.
     * @exception IOException on other errors.
     */
    public void set(String name, Object obj)
        throws CertificateException, IOException {
		throw new IOException("not supported");
	}

    /**
     * Gets an attribute value for this CertAttrSet.
     *
     * @param name the name of the attribute to return.
     * 
     * @exception CertificateException on attribute handling errors.
     * @exception IOException on other errors.
     */
    public Object get(String name)
        throws CertificateException, IOException {
		throw new IOException("not supported");
	}

    /**
     * Deletes an attribute value from this CertAttrSet.
     *
     * @param name the name of the attribute to delete.
     * 
     * @exception CertificateException on attribute handling errors.
     * @exception IOException on other errors.
     */
    public void delete(String name)
        throws CertificateException, IOException {
		throw new IOException("not supported");
	}

    /**
     * Returns an enumeration of the names of the attributes existing within
     * this attribute.
     * 
     * @return an enumeration of the attribute names.
     */
    public Enumeration getElements() {
		return null;
	}
 
    /**
     * Returns the name (identifier) of this CertAttrSet.
     * 
     * @return the name of this CertAttrSet.
     */
    public String getName() {
		return "Generic Extension";
	}
}
