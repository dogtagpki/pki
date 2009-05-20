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
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.util.Enumeration;

import netscape.security.util.*;

/**
 * Represent the enumerated type used in CRLReason Extension of CRL entry.
 *
 *
 * @author galperin
 * @version $Revision: 14564 $, $Date: 2007-05-01 10:40:13 -0700 (Tue, 01 May 2007) $
 */

public final class RevocationReason {
    /**
     * Reasons
     */
    public static final RevocationReason UNSPECIFIED = new RevocationReason(0);
    public static final RevocationReason KEY_COMPROMISE = new RevocationReason(1);
    public static final RevocationReason CA_COMPROMISE = new RevocationReason(2);
    public static final RevocationReason AFFILIATION_CHANGED = new RevocationReason(3);
    public static final RevocationReason SUPERSEDED = new RevocationReason(4);
    public static final RevocationReason CESSATION_OF_OPERATION = new RevocationReason(5);
    public static final RevocationReason CERTIFICATE_HOLD = new RevocationReason(6);
    public static final RevocationReason REMOVE_FROM_CRL = new RevocationReason(8);
    public static final RevocationReason PRIVILEGE_WITHDRAWN = new RevocationReason(9);
    public static final RevocationReason AA_COMPROMISE = new RevocationReason(10);

    // Private data members
    private int mReason;

    /**
     * Create a RevocationReason with the passed integer value.
     *
     * @param reason integer value of the enumeration alternative.
     */
    private RevocationReason(int reason){
        this.mReason = reason;
    }

    public int toInt() {
        return mReason;
    }

	public static RevocationReason fromInt(int reason) {
	    if (reason == UNSPECIFIED.mReason) return UNSPECIFIED;
	    if (reason == KEY_COMPROMISE.mReason) return KEY_COMPROMISE;
	    if (reason == CA_COMPROMISE.mReason) return CA_COMPROMISE;
	    if (reason == AFFILIATION_CHANGED.mReason) return AFFILIATION_CHANGED;
	    if (reason == SUPERSEDED.mReason) return SUPERSEDED;
	    if (reason == CESSATION_OF_OPERATION.mReason) return CESSATION_OF_OPERATION;
	    if (reason == CERTIFICATE_HOLD.mReason) return CERTIFICATE_HOLD;
	    if (reason == REMOVE_FROM_CRL.mReason) return REMOVE_FROM_CRL;
	    if (reason == PRIVILEGE_WITHDRAWN.mReason) return PRIVILEGE_WITHDRAWN;
	    if (reason == AA_COMPROMISE.mReason) return AA_COMPROMISE;
    	return null;
    }

	public boolean equals(Object other) {
		if (this == other)
		  return true;
		else if (other instanceof RevocationReason)
		  return ((RevocationReason)other).mReason == mReason;
		else
		  return false;
	}

	public int hashCode() {
		return mReason;
	}

	public String toString() {
	    if (equals(UNSPECIFIED)) return "Unspecified";
	    if (equals(KEY_COMPROMISE)) return "Key_Compromise";
	    if (equals(CA_COMPROMISE)) return "CA_Compromise";
	    if (equals(AFFILIATION_CHANGED)) return "Affiliation_Changed";
	    if (equals(SUPERSEDED)) return "Superseded";
	    if (equals(CESSATION_OF_OPERATION)) return "Cessation_of_Operation";
	    if (equals(CERTIFICATE_HOLD)) return "Certificate_Hold";
	    if (equals(REMOVE_FROM_CRL)) return "Remove_from_CRL";
	    if (equals(PRIVILEGE_WITHDRAWN)) return "Privilege_Withdrawn";
	    if (equals(AA_COMPROMISE)) return "AA_Compromise";
    	return "[UNDEFINED]";
	}
}
