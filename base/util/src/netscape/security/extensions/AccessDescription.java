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
package netscape.security.extensions;

import java.io.IOException;
import java.io.Serializable;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.GeneralName;

public class AccessDescription implements Serializable {
    ObjectIdentifier mOID = null;
    GeneralName mLocation = null;

    AccessDescription(ObjectIdentifier oid, GeneralName location) {
        mOID = oid;
        mLocation = location;
    }

    public ObjectIdentifier getMethod() {
        return mOID;
    }

    public GeneralName getLocation() {
        return mLocation;
    }

    /**
     * For serialization:
     * Note that GeneralName is not serializable. That is
     * why we need to define our own serialization method.
     */
    private void writeObject(java.io.ObjectOutputStream out)
            throws IOException {
        try (DerOutputStream seq = new DerOutputStream();
             DerOutputStream tmp = new DerOutputStream()) {

            tmp.putOID(mOID);
            mLocation.encode(tmp);
            seq.write(DerValue.tag_Sequence, tmp);
            out.write(seq.toByteArray());
        }
    }

    /**
     * For serialization
     * Note that GeneralName is not serializable. That is
     * why we need to define our own serialization method.
     */
    private void readObject(java.io.ObjectInputStream in)
            throws IOException {
        DerValue val = new DerValue(in);
        DerValue seq = val.data.getDerValue();

        mOID = seq.getOID();
        DerValue derLoc = val.data.getDerValue();

        mLocation = new GeneralName(derLoc);
    }
}
