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

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class implements the DNSName as required by the GeneralNames ASN.1
 * object.
 * 
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.4
 */
public class DNSName implements GeneralNameInterface {
    /**
     *
     */
    private static final long serialVersionUID = -2907649488092607056L;
    private String name;

    /**
     * Create the DNSName object from the passed encoded Der value.
     * 
     * @param derValue the encoded DER DNSName.
     * @exception IOException on error.
     */
    public DNSName(DerValue derValue) throws IOException {
        name = derValue.getIA5String();
    }

    /**
     * Create the DNSName object with the specified name.
     * 
     * @param name the DNSName.
     */
    public DNSName(String name) {
        this.name = name;
    }

    /**
     * Return the type of the GeneralName.
     */
    public int getType() {
        return (GeneralNameInterface.NAME_DNS);
    }

    /**
     * Encode the DNS name into the DerOutputStream.
     * 
     * @param out the DER stream to encode the DNSName to.
     * @exception IOException on encoding errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        out.putIA5String(name);
    }

    /**
     * Convert the name into user readable string.
     */
    public String toString() {
        return ("DNSName: " + name);
    }
}
