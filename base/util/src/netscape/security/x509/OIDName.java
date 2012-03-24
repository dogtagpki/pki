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
import netscape.security.util.ObjectIdentifier;

/**
 * This class implements the OIDName as required by the GeneralNames
 * ASN.1 object.
 * 
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.3
 * @see GeneralName
 * @see GeneralNames
 * @see GeneralNameInterface
 */
public class OIDName implements GeneralNameInterface {
    /**
     *
     */
    private static final long serialVersionUID = 9198510631835117121L;
    private ObjectIdentifier oid;

    /**
     * Create the OIDName object from the passed encoded Der value.
     * 
     * @param derValue the encoded DER OIDName.
     * @exception IOException on error.
     */
    public OIDName(DerValue derValue) throws IOException {
        oid = derValue.getOID();
    }

    /**
     * Create the OIDName object with the specified name.
     * 
     * @param name the OIDName.
     */
    public OIDName(ObjectIdentifier oid) {
        this.oid = oid;
    }

    public OIDName(String oid) {
        this.oid = new ObjectIdentifier(oid);
    }

    /**
     * Return the type of the GeneralName.
     */
    public int getType() {
        return (GeneralNameInterface.NAME_OID);
    }

    /**
     * Encode the OID name into the DerOutputStream.
     * 
     * @param out the DER stream to encode the OIDName to.
     * @exception IOException on encoding errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        out.putOID(oid);
    }

    /**
     * Convert the name into user readable string.
     */
    public String toString() {
        return ("OIDName: " + oid.toString());
    }
}
