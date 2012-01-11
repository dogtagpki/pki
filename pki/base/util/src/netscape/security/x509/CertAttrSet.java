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

/**
 * This interface defines the methods required of a certificate attribute.
 * Examples of X.509 certificate attributes are Validity, Issuer_Name, and
 * Subject Name. A CertAttrSet may compromise one attribute or many
 * attributes.
 * <p>
 * A CertAttrSet itself can also be comprised of other sub-sets. In the case of X.509 V3 certificates, for example, the
 * "extensions" attribute has subattributes, such as those for KeyUsage and AuthorityKeyIdentifier.
 * 
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.9
 * @see CertificateException
 */
public interface CertAttrSet {
    /**
     * Returns a short string describing this certificate attribute.
     * 
     * @return value of this certificate attribute in
     *         printable form.
     */
    String toString();

    /**
     * Encodes the attribute to the output stream in a format
     * that can be parsed by the <code>decode</code> method.
     * 
     * @param out the OutputStream to encode the attribute to.
     * 
     * @exception CertificateException on encoding or validity errors.
     * @exception IOException on other errors.
     */
    void encode(OutputStream out)
            throws CertificateException, IOException;

    /**
     * Decodes the attribute in the input stream.
     * 
     * @param in the InputStream to read the encoded attribute from.
     * 
     * @exception CertificateException on decoding or validity errors.
     * @exception IOException on other errors.
     */
    void decode(InputStream in)
            throws CertificateException, IOException;

    /**
     * Sets an attribute value within this CertAttrSet.
     * 
     * @param name the name of the attribute (e.g. "x509.info.key")
     * @param obj the attribute object.
     * 
     * @exception CertificateException on attribute handling errors.
     * @exception IOException on other errors.
     */
    void set(String name, Object obj)
            throws CertificateException, IOException;

    /**
     * Gets an attribute value for this CertAttrSet.
     * 
     * @param name the name of the attribute to return.
     * 
     * @exception CertificateException on attribute handling errors.
     * @exception IOException on other errors.
     */
    Object get(String name)
            throws CertificateException, IOException;

    /**
     * Deletes an attribute value from this CertAttrSet.
     * 
     * @param name the name of the attribute to delete.
     * 
     * @exception CertificateException on attribute handling errors.
     * @exception IOException on other errors.
     */
    void delete(String name)
            throws CertificateException, IOException;

    /**
     * Returns an enumeration of the names of the attributes existing within
     * this attribute.
     * 
     * @return an enumeration of the attribute names.
     */
    Enumeration getElements();

    /**
     * Returns the name (identifier) of this CertAttrSet.
     * 
     * @return the name of this CertAttrSet.
     */
    String getName();
}
