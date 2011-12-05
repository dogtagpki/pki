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
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.BitArray;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * Represent the CRL Reason Flags.
 *
 * <p>This extension, if present, defines the identifies
 * the reason for the certificate revocation.
 *
 * @author Hemma Prafullchandra
 * @version 1.3
 * @see Extension
 * @see CertAttrSet
 */
public class ReasonFlags {

    /**
     * Reasons
     */
    public static final String UNUSED = "unused";
    public static final String KEY_COMPROMISE = "key_compromise";
    public static final String CA_COMPROMISE = "ca_compromise";
    public static final String AFFLIATION_CHANGED = "affliation_changed";
    public static final String SUPERSEDED = "superseded";
    public static final String CESSATION_OF_OPERATION
                                   = "cessation_of_operation";
    public static final String CERTIFICATION_HOLD = "certification_hold";
    public static final String PRIVILEGE_WITHDRAWN = "privilege_withdrawn";
    public static final String AA_COMPROMISE = "aa_compromise";


    // Private data members
    private boolean[] bitString;

    /**
     * Check if bit is set.
     *
     * @param position the position in the bit string to check.
     */
    private boolean isSet(int position) {
        return bitString[position];
    }

    /**
     * Set the bit at the specified position.
     */
    private void set(int position, boolean val) {
	// enlarge bitString if necessary
        if (position >= bitString.length) {
            boolean[] tmp = new boolean[position+1];
            System.arraycopy(bitString, 0, tmp, 0, bitString.length);
            bitString = tmp;
        }
	bitString[position] = val;
    }

    /**
     * Create a ReasonFlags with the passed bit settings.
     *
     * @param reasons the bits to be set for the ReasonFlags.
     */
    public ReasonFlags(byte[] reasons) {
        bitString = new BitArray(reasons.length*8, reasons).toBooleanArray();
    }

    /**
     * Create a ReasonFlags with the passed bit settings.
     *
     * @param reasons the bits to be set for the ReasonFlags.
     */
    public ReasonFlags(boolean[] reasons) {
        this.bitString = reasons;
    }

    /**
     * Create a ReasonFlags with the passed bit settings.
     *
     * @param reasons the bits to be set for the ReasonFlags.
     */
    public ReasonFlags(BitArray reasons) {
        this.bitString = reasons.toBooleanArray();
    }

    /**
     * Create the object from the passed DER encoded value.
     *
     * @param in the DerInputStream to read the ReasonFlags from.
     * @exception IOException on decoding errors.
     */  
    public ReasonFlags(DerInputStream in) throws IOException {
        DerValue derVal = in.getDerValue();
        this.bitString = derVal.getUnalignedBitString(true).toBooleanArray();
    }

    /**
     * Create the object from the passed DER encoded value.
     *   
     * @param derVal the DerValue decoded from the stream.
     * @exception IOException on decoding errors.
     */  
    public ReasonFlags(DerValue derVal) throws IOException {
        this.bitString = derVal.getUnalignedBitString(true).toBooleanArray();
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof Boolean)) {
	    throw new IOException("Attribute must be of type Boolean.");
	}
	boolean val = ((Boolean)obj).booleanValue();
	if (name.equalsIgnoreCase(UNUSED)) {
	    set(0,val);
	} else if (name.equalsIgnoreCase(KEY_COMPROMISE)) {
	    set(1,val);
	} else if (name.equalsIgnoreCase(CA_COMPROMISE)) {
	    set(2,val);
	} else if (name.equalsIgnoreCase(AFFLIATION_CHANGED)) {
	    set(3,val);
	} else if (name.equalsIgnoreCase(SUPERSEDED)) {
	    set(4,val);
	} else if (name.equalsIgnoreCase(CESSATION_OF_OPERATION)) {
	    set(5,val);
	} else if (name.equalsIgnoreCase(CERTIFICATION_HOLD)) {
	    set(6,val);
	} else if (name.equalsIgnoreCase(PRIVILEGE_WITHDRAWN)) {
	    set(7,val);
	} else if (name.equalsIgnoreCase(AA_COMPROMISE)) {
	    set(8,val);
	} else {
	  throw new IOException("Name not recognized by ReasonFlags");
	}
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
	if (name.equalsIgnoreCase(UNUSED)) {
	    return new Boolean(isSet(0));
	} else if (name.equalsIgnoreCase(KEY_COMPROMISE)) {
	    return new Boolean(isSet(1));
	} else if (name.equalsIgnoreCase(CA_COMPROMISE)) {
	    return new Boolean(isSet(2));
	} else if (name.equalsIgnoreCase(AFFLIATION_CHANGED)) {
	    return new Boolean(isSet(3));
	} else if (name.equalsIgnoreCase(SUPERSEDED)) {
	    return new Boolean(isSet(4));
	} else if (name.equalsIgnoreCase(CESSATION_OF_OPERATION)) {
	    return new Boolean(isSet(5));
	} else if (name.equalsIgnoreCase(CERTIFICATION_HOLD)) {
	    return new Boolean(isSet(6));
	} else if (name.equalsIgnoreCase(PRIVILEGE_WITHDRAWN)) {
	    return new Boolean(isSet(7));
	} else if (name.equalsIgnoreCase(AA_COMPROMISE)) {
	    return new Boolean(isSet(8));
	} else {
	  throw new IOException("Name not recognized by ReasonFlags");
	}
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
	if (name.equalsIgnoreCase(UNUSED)) {
	    set(0,false);
	} else if (name.equalsIgnoreCase(KEY_COMPROMISE)) {
	    set(1,false);
	} else if (name.equalsIgnoreCase(CA_COMPROMISE)) {
	    set(2,false);
	} else if (name.equalsIgnoreCase(AFFLIATION_CHANGED)) {
	    set(3,false);
	} else if (name.equalsIgnoreCase(SUPERSEDED)) {
	    set(4,false);
	} else if (name.equalsIgnoreCase(CESSATION_OF_OPERATION)) {
	    set(5,false);
	} else if (name.equalsIgnoreCase(CERTIFICATION_HOLD)) {
	    set(6,false);
	} else if (name.equalsIgnoreCase(PRIVILEGE_WITHDRAWN)) {
	    set(7,false);
	} else if (name.equalsIgnoreCase(AA_COMPROMISE)) {
	    set(8,false);
	} else {
	  throw new IOException("Name not recognized by ReasonFlags");
	}
    }

    /**
     * Returns a printable representation of the ReasonFlags.
     */
    public String toString() {
        String s = super.toString() + "Reason Flags [\n";

	try {
        if (isSet(0)) {
            s += "  Unused\n";
        }
        if (isSet(1)) {
            s += "  Key Compromise\n";
        }
        if (isSet(2)) {
            s += "  CA_Compromise\n";
        }
        if (isSet(3)) {
            s += "  Affiliation_Changed\n";
        }
        if (isSet(4)) {
            s += "  Superseded\n";
        }
        if (isSet(5)) {
            s += "  Cessation Of Operation\n";
        }
        if (isSet(6)) {
            s += "  Certificate Hold\n";
        }
        if (isSet(7)) {
            s += "  Privilege Withdrawn\n";
        }
        if (isSet(8)) {
            s += "  AA Compromise\n";
        }
	} catch (ArrayIndexOutOfBoundsException ex) {}

        s += "]\n";

        return (s);
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        out.putUnalignedBitString(new BitArray(this.bitString));
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements () {
        Vector<String> elements = new Vector<String>();
        elements.addElement(UNUSED);
        elements.addElement(KEY_COMPROMISE);
        elements.addElement(CA_COMPROMISE);
        elements.addElement(AFFLIATION_CHANGED);
        elements.addElement(SUPERSEDED);
        elements.addElement(CESSATION_OF_OPERATION);
        elements.addElement(CERTIFICATION_HOLD);
        elements.addElement(PRIVILEGE_WITHDRAWN);
        elements.addElement(AA_COMPROMISE);

	return (elements.elements());
    }
}
