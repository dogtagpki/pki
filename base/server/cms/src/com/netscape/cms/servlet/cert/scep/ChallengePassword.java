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
package com.netscape.cms.servlet.cert.scep;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerValue;
import netscape.security.x509.CertAttrSet;

/**
 * Class for handling the decoding of a SCEP Challenge Password
 * object. Currently this class cannot be used for encoding
 * thus some fo the methods are unimplemented
 */
public class ChallengePassword implements CertAttrSet {

    public static final String NAME = "ChallengePassword";
    public static final String PASSWORD = "password";

    private String cpw;

    /**
     * Get the password marshalled in this object
     *
     * @return the challenge password
     */
    public String toString() {
        return cpw;
    }

    /**
     * Create a ChallengePassword object
     *
     * @param stuff (must be of type byte[]) a DER-encoded by array following
     *            The ASN.1 template for ChallenegePassword specified in the SCEP
     *            documentation
     * @throws IOException if the DER encoded byt array was malformed, or if it
     *             did not match the template
     */

    public ChallengePassword(Object stuff)
            throws IOException {

        ByteArrayInputStream is = new ByteArrayInputStream((byte[]) stuff);
        try {
            decode(is);
        } catch (Exception e) {
            throw new IOException(e.getMessage());
        }

    }

    /**
     * Currently Unimplemented
     */
    public void encode(OutputStream out)
            throws CertificateException, IOException {
    }

    public void decode(InputStream in)
            throws CertificateException, IOException {
        DerValue derVal = new DerValue(in);

        construct(derVal);

    }

    private void construct(DerValue derVal) throws IOException {
        try {
            cpw = derVal.getPrintableString();
        } catch (NullPointerException e) {
            cpw = "";
        }
    }

    /**
     * Currently Unimplemented
     */
    public void set(String name, Object obj)
            throws CertificateException, IOException {
    }

    /**
     * Get an attribute of this object.
     *
     * @param name the name of the attribute of this object to get. The only
     *            supported attribute is "password"
     */
    public Object get(String name)
            throws CertificateException, IOException {
        if (name.equalsIgnoreCase(PASSWORD)) {
            return cpw;
        } else {
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet: ChallengePassword");
        }
    }

    /**
     * Currently Unimplemented
     */
    public void delete(String name)
            throws CertificateException, IOException {
    }

    /**
     * @return an empty set of elements
     */
    public Enumeration<String> getAttributeNames() {
        return (new Vector<String>()).elements();
    }

    /**
     * @return the String "ChallengePassword"
     */
    public String getName() {
        return NAME;
    }

}
