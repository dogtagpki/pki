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
 * Represent the CertificatePolicyMap ASN.1 object.
 * 
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.5
 */
public class CertificatePolicyMap {
    private CertificatePolicyId issuerDomain;
    private CertificatePolicyId subjectDomain;

    /**
     * Create a CertificatePolicyMap with the passed CertificatePolicyId's.
     * 
     * @param issuer the CertificatePolicyId for the issuer CA.
     * @param subject the CertificatePolicyId for the subject CA.
     */
    public CertificatePolicyMap(CertificatePolicyId issuer,
                                CertificatePolicyId subject) {
        this.issuerDomain = issuer;
        this.subjectDomain = subject;
    }

    /**
     * Create the CertificatePolicyMap from the DER encoded value.
     * 
     * @param val the DER encoded value of the same.
     */
    public CertificatePolicyMap(DerValue val) throws IOException {
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for CertificatePolicyMap");
        }
        issuerDomain = new CertificatePolicyId(val.data.getDerValue());
        subjectDomain = new CertificatePolicyId(val.data.getDerValue());
    }

    /**
     * Return the issuer CA part of the policy map.
     */
    public CertificatePolicyId getIssuerIdentifier() {
        return (issuerDomain);
    }

    /**
     * Return the subject CA part of the policy map.
     */
    public CertificatePolicyId getSubjectIdentifier() {
        return (subjectDomain);
    }

    /**
     * Returns a printable representation of the CertificatePolicyId.
     */
    public String toString() {
        String s = "CertificatePolicyMap: [\n"
                 + "IssuerDomain:" + issuerDomain.toString()
                 + "SubjectDomain:" + subjectDomain.toString()
                 + "]\n";

        return (s);
    }

    /**
     * Write the CertificatePolicyMap to the DerOutputStream.
     * 
     * @param out the DerOutputStream to write the object to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        issuerDomain.encode(tmp);
        subjectDomain.encode(tmp);
        out.write(DerValue.tag_Sequence, tmp);
    }
}
