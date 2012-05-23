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
import java.util.Vector;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * Represent the PolicyQualifiers.
 *
 * policyQualifiers ::= SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo
 *
 * @author Thomas Kwan
 */
public class PolicyQualifiers implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 6932694408774694516L;
    private Vector<PolicyQualifierInfo> mInfo = new Vector<PolicyQualifierInfo>();

    /**
     * Create a PolicyQualifiers with the ObjectIdentifier.
     *
     * @param id the ObjectIdentifier for the policy id.
     */
    public PolicyQualifiers() {
    }

    /**
     * Create the object from its Der encoded value.
     *
     * @param val the DER encoded value for the same.
     */
    public PolicyQualifiers(DerValue val) throws IOException {
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for " + "PolicyQualifiers.");
        }
        while (val.data.available() != 0) {
            DerValue pq = val.data.getDerValue();
            PolicyQualifierInfo info = new PolicyQualifierInfo(pq);
            add(info);
        }
    }

    public void add(PolicyQualifierInfo info) {
        mInfo.addElement(info);
    }

    public int size() {
        return mInfo.size();
    }

    public PolicyQualifierInfo getInfoAt(int i) {
        return mInfo.elementAt(i);
    }

    /**
     * Returns a printable representation of the CertificatePolicyId.
     */
    public String toString() {
        StringBuffer s = new StringBuffer("PolicyQualifiers: [");
        for (int i = 0; i < mInfo.size(); i++) {
            PolicyQualifierInfo pq = mInfo.elementAt(i);
            s.append(pq.toString());
        }
        s.append("]\n");

        return s.toString();
    }

    /**
     * Write the PolicyQualifiers to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the object to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        for (int i = 0; i < mInfo.size(); i++) {
            PolicyQualifierInfo pq = mInfo.elementAt(i);
            pq.encode(tmp);
        }

        out.write(DerValue.tag_Sequence, tmp);
    }
}
