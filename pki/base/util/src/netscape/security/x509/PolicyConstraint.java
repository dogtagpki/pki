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
import java.security.cert.CertificateException;

import netscape.security.util.*;

/**
 * This class defines the PolicyConstraint ASN.1 object.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.4
 */
public class PolicyConstraint {
    private static final byte TAG_SET = 0;
    private static final byte TAG_REQUIRE = 1;
    private static final byte TAG_INHIBIT = 2;

    private CertificatePolicySet set = null;
    private int require = -1;
    private int inhibit = -1;

    /**
     * The default constructor for this object
     *
     * @param set the CertificatePolicySet (null for optional).
     * @param require require explicit policy (-1 for optional).
     * @param inhibit inhibit policy mapping (-1 for optional).
     */
    public PolicyConstraint(CertificatePolicySet set, int require, int inhibit) {
        this.set = set;
        this.require = require;
        this.inhibit = inhibit;
    }

    /**
     * Create the PolicyConstraint from the DerValue.
     *
     * @param val the DerValue of the PolicyConstraint.
     * @exception IOException on decoding errors.
     */
    public PolicyConstraint(DerValue val) throws IOException {
        if (val.tag != DerValue.tag_Sequence) {
  	    throw new IOException("Sequence tag missing for PolicyConstraint.");
  	}
	DerInputStream in = val.data;
	while (in != null && in.available() != 0) {
  	    DerValue next = in.getDerValue();
  	    switch (next.tag & 0x1f) {
  	    case TAG_SET:
  	        this.set = new CertificatePolicySet(next.data);
  	        break;
  	 
  	    case TAG_REQUIRE:
  	        next = next.data.getDerValue();
  	        this.require = (next.getInteger()).toInt();
  	        break;
  
  	    case TAG_INHIBIT:
  	        next = next.data.getDerValue();
  	        this.inhibit = (next.getInteger()).toInt();
  	        break;
  
  	    default:
  	        throw new IOException("Invalid tag option for PolicyConstraint.");
  	    }
        }
    }

    /**
     * Return user readable form of the object.
     */
    public String toString() {
	String s = ((set != null) ? 
        	"PolicyConstraint: [\n"
		    + "  PolicySet:[" + set.toString() + "]\n"
		    + "  Require:" + require + "\n"
		    + "  Inhibit:" + inhibit + "\n"
		    + "]\n" :
        	"PolicyConstraint: [\n"
		    + "  PolicySet:[null]\n"
		    + "  Require:" + require + "\n"
		    + "  Inhibit:" + inhibit + "\n"
		    + "]\n");
        return (s);
    }

    /**
     * Encode the object to the output stream.
     *
     * @param out the DerOutputStream to encode the object to.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tagged = new DerOutputStream();

        if (set != null) {
            DerOutputStream tmp = new DerOutputStream();
            set.encode(tmp);
            tagged.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                                            true, TAG_SET), tmp);
        }
        if (require != -1) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(new BigInt(require));
            tagged.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                                            true, TAG_REQUIRE), tmp);
        }
        if (inhibit != -1) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(new BigInt(inhibit));
            tagged.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                                            true, TAG_INHIBIT), tmp);
        }
        out.write(DerValue.tag_Sequence,tagged);
    }
}
