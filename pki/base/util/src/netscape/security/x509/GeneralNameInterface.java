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

/**
 * This interface specifies the abstract methods which have to be implemented by
 * all the members of the GeneralNames ASN.1 object.
 * 
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.6
 */
public interface GeneralNameInterface extends java.io.Serializable {
    /**
     * The list of names supported.
     */
    public static final int NAME_ANY = 0;
    public static final int NAME_RFC822 = 1;
    public static final int NAME_DNS = 2;
    public static final int NAME_X400 = 3;
    public static final int NAME_DIRECTORY = 4;
    public static final int NAME_EDI = 5;
    public static final int NAME_URI = 6;
    public static final int NAME_IP = 7;
    public static final int NAME_OID = 8;

    /**
     * Return the type of the general name, as defined above.
     */
    int getType();

    /**
     * Encode the name to the specified DerOutputStream.
     * 
     * @param out the DerOutputStream to encode the GeneralName to.
     * @exception IOException thrown if the GeneralName could not be encoded.
     */
    void encode(DerOutputStream out) throws IOException;
}
