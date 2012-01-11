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
 * Represent the CertificatePolicyInformation ASN.1 object.
 * 
 * @author Christine Ho
 */
public class CertificatePolicyInfo implements java.io.Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -8516006396099280477L;
    private CertificatePolicyId mPolicyIdentifier;
    private PolicyQualifiers mPolicyQualifiers;

    /**
     * Create a CertificatePolicyInfo with the passed CertificatePolicyId's.
     * 
     * @param id the CertificatePolicyId.
     */
    public CertificatePolicyInfo(CertificatePolicyId id) {
        this.mPolicyIdentifier = id;
        this.mPolicyQualifiers = null;
    }

    public CertificatePolicyInfo(CertificatePolicyId id, PolicyQualifiers qualifiers) {
        this.mPolicyIdentifier = id;
        this.mPolicyQualifiers = qualifiers;
    }

    /**
     * Create the CertificatePolicyInfo from the DER encoded value.
     * 
     * @param val the DER encoded value of the same.
     */
    public CertificatePolicyInfo(DerValue val) throws IOException {
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for CertificatePolicyInfo");
        }
        mPolicyIdentifier = new CertificatePolicyId(val.data.getDerValue());
        // The specification is not clear on whether qualifier is
        // optional or not. GTE CyberTrust Root certificate has
        // no qualifier.
        if (val.data.available() == 0) {
            mPolicyQualifiers = null;
        } else {
            mPolicyQualifiers = new PolicyQualifiers(val.data.getDerValue());
        }
    }

    /**
     * return the policy identifier of the policy info
     */
    public CertificatePolicyId getPolicyIdentifier() {
        return (mPolicyIdentifier);
    }

    public PolicyQualifiers getPolicyQualifiers() {
        return mPolicyQualifiers;
    }

    /**
     * Returns a printable representation of the CertificatePolicyId.
     */
    public String toString() {
        String s = "CertificatePolicyInfo: [\n"
                 + "PolicyIdentifier:" + mPolicyIdentifier.toString()

                 + "]\n";
        return (s);
    }

    /**
     * Write the CertificatePolicyInfo to the DerOutputStream.
     * 
     * @param out the DerOutputStream to write the object to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        mPolicyIdentifier.encode(tmp);
        if (mPolicyQualifiers != null) {
            mPolicyQualifiers.encode(tmp);
        }
        out.write(DerValue.tag_Sequence, tmp);
    }
}
