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
import netscape.security.util.*;


/**
 * Represent the PolicyQualifierInfo.
 *
 * policyQualifierInfo ::= SEQUENCE {
 *   policyQualifierId PolicyQualifierId
 *   qualifier ANY  DEFINED BY policyQualifierId
 * }
 *
 * @author Thomas Kwan
 */
public class PolicyQualifierInfo  implements java.io.Serializable {

    public static final int OID_CPS[] = { 1, 3, 6, 1, 5, 5, 7, 2, 1 };
    public static final ObjectIdentifier QT_CPS = new
       ObjectIdentifier(OID_CPS);

    public static final int OID_UNOTICE[] = { 1, 3, 6, 1, 5, 5, 7, 2, 2 };
    public static final ObjectIdentifier QT_UNOTICE = new
       ObjectIdentifier(OID_UNOTICE);

    private ObjectIdentifier mId = null;
    private Qualifier mQualifier = null;

    /**
     * Create a PolicyQualifierInfo
     *
     * @param id the ObjectIdentifier for the policy id.
     */
    public PolicyQualifierInfo(ObjectIdentifier id, Qualifier qualifier) {
	mId = id;
	mQualifier = qualifier;
    }

    /**
     * Create the object from its Der encoded value.
     *
     * @param val the DER encoded value for the same.
     */
    public PolicyQualifierInfo(DerValue val) throws IOException {
       if (val.tag != DerValue.tag_Sequence) {
          throw new IOException("Invalid encoding for PolicyQualifierInfo.");
       }
        DerValue did = val.data.getDerValue();
        mId = did.getOID();
	if (val.data.available() != 0) {
        DerValue qualifier = val.data.getDerValue();
        if (qualifier.tag == DerValue.tag_IA5String) {
		mQualifier = new CPSuri(qualifier);
	} else {
		mQualifier = new UserNotice(qualifier);
	}
	}
    }

    public ObjectIdentifier getId()
    {
      return mId;
    }

    /**
     * Returns object of type CPSuri or UserNotice.
     */
    public Qualifier getQualifier() 
    {
      return mQualifier;
    }

    /**
     * Returns a printable representation of the CertificatePolicyId.
     */
    public String toString() {
        String s = "PolicyQualifierInfo: [";
        s = s + getId() + " " + getQualifier();
        s = s + "]\n";

        return (s);
    }

    /**
     * Write the PolicyQualifier to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the object to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
       DerOutputStream tmp = new DerOutputStream();
       tmp.putOID(mId);
       mQualifier.encode(tmp);
       out.write(DerValue.tag_Sequence,tmp);
    }
}
