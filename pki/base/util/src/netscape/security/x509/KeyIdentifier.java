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
 * Represent the Key Identifier ASN.1 object.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.4
 */
public class KeyIdentifier implements java.io.Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 2412286879441154979L;
    private byte[] octetString;

    /**
     * Create a KeyIdentifier with the passed bit settings.
     *
     * @param octetString the octet string identifying the key identifier.
     */
    public KeyIdentifier(byte[] octetString) {
        this.octetString = octetString;
    }

    /**
     * Create a KeyIdentifier from the DER encoded value.
     *
     * @param val the DerValue
     */
    public KeyIdentifier(DerValue val) throws IOException {
        octetString = val.getOctetString();
    }

    /**
     * Return the value of the KeyIdentifier as byte array.
     */
    public byte[] getIdentifier() {
        return ((byte[])octetString.clone());
    }

    /**
     * Returns a printable representation of the KeyUsage.
     */
    public String toString() {
	netscape.security.util.PrettyPrintFormat pp = 
		new netscape.security.util.PrettyPrintFormat(" ", 20);
	String octetbits = pp.toHexString(octetString);

        String s = "KeyIdentifier [\n";
        s += octetbits;
        s += "]\n";
        return (s);
    }

    /**
     * Write the KeyIdentifier to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the object to.
     * @exception IOException
     */
    void encode (DerOutputStream out) throws IOException {
        out.putOctetString(octetString);
    }
}
