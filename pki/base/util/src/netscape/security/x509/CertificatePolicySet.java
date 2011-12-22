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

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class defines the certificate policy set ASN.1 object.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.4
 */
public class CertificatePolicySet {
    private Vector<CertificatePolicyId>	ids;

    /**
     * The default constructor for this class.
     *
     * @param ids the sequence of CertificatePolicyId's.
     */
    public CertificatePolicySet(Vector<CertificatePolicyId> ids) {
        this.ids = ids;
    }

    /**
     * Create the object from the DerValue.
     *
     * @param in the passed DerInputStream.
     * @exception IOException on decoding errors.
     */
    public CertificatePolicySet(DerInputStream in) throws IOException {
        ids = new Vector<CertificatePolicyId>(1, 1);
        DerValue[] seq = in.getSequence(5);
 
        for (int i = 0; i < seq.length; i++) {
            CertificatePolicyId id = new CertificatePolicyId(seq[i]);
            ids.addElement(id);
        }
    }

    /**
     * Return printable form of the object.
     */
    public String toString() {
        String s = "CertificatePolicySet:[\n"
                 + ids.toString()
                 + "]\n";

        return (s);
    }

    /**
     * Encode the policy set to the output stream.
     *
     * @param out the DerOutputStream to encode the data to.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        for (int i = 0; i < ids.size(); i++) {
            ((CertificatePolicyId)ids.elementAt(i)).encode(tmp);
        }
        out.write(DerValue.tag_Sequence,tmp);
    }
}
