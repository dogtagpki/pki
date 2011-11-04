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
 * Represent the CPSuri Qualifier.
 *
 * CPSuri ::= IA5String;
 *
 * @author Thomas Kwan
 */
public class CPSuri extends Qualifier {

    private String mURI = null;

    /**
     * Create a PolicyQualifierInfo
     *
     * @param id the ObjectIdentifier for the policy id.
     */
    public CPSuri(String uri) {
      mURI = uri;
    }

    public CPSuri(DerValue val) throws IOException {
	mURI = val.getIA5String();
    }

    /**
     * Write the PolicyQualifier to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the object to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
	out.putIA5String(mURI);
    }

    public String getURI() {
        return mURI;
    }
}
