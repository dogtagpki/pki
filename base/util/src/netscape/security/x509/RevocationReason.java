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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represent the enumerated type used in CRLReason Extension of CRL entry.
 *
 *
 * @author galperin
 * @version $Revision$, $Date$
 */

public final class RevocationReason implements Serializable {
    private static final long serialVersionUID = -2582403666913588806L;

    public static final Collection<RevocationReason> INSTANCES = new ArrayList<RevocationReason>();
    public static final Map<Integer, RevocationReason> CODES = new LinkedHashMap<Integer, RevocationReason>();
    public static final Map<String, RevocationReason> LABELS = new LinkedHashMap<String, RevocationReason>();

    /**
     * Reasons
     */
    public static final RevocationReason UNSPECIFIED = new RevocationReason(0, "Unspecified");
    public static final RevocationReason KEY_COMPROMISE = new RevocationReason(1, "Key_Compromise");
    public static final RevocationReason CA_COMPROMISE = new RevocationReason(2, "CA_Compromise");
    public static final RevocationReason AFFILIATION_CHANGED = new RevocationReason(3, "Affiliation_Changed");
    public static final RevocationReason SUPERSEDED = new RevocationReason(4, "Superseded");
    public static final RevocationReason CESSATION_OF_OPERATION = new RevocationReason(5, "Cessation_of_Operation");
    public static final RevocationReason CERTIFICATE_HOLD = new RevocationReason(6, "Certificate_Hold");
    public static final RevocationReason REMOVE_FROM_CRL = new RevocationReason(8, "Remove_from_CRL");
    public static final RevocationReason PRIVILEGE_WITHDRAWN = new RevocationReason(9, "Privilege_Withdrawn");
    public static final RevocationReason AA_COMPROMISE = new RevocationReason(10, "AA_Compromise");

    // Private data members
    private int code;
    private String label;

    /**
     * Create a RevocationReason with the passed integer value and string label.
     *
     * @param reason integer value of the enumeration alternative.
     * @param label string value of the enumeration alternative.
     */
    private RevocationReason(int reason, String label) {
        this.code = reason;
        this.label = label;

        INSTANCES.add(this);
        CODES.put(reason, this);
        LABELS.put(label.toLowerCase(), this);
    }

    public int getCode() {
        return code;
    }

    public String getLabel() {
        return label;
    }

    public static RevocationReason fromInt(int reason) {
        return valueOf(reason);
    }

    public static RevocationReason valueOf(int reason) {
        return CODES.get(reason);
    }

    public static RevocationReason valueOf(String string) {
        return LABELS.get(string.toLowerCase());
    }

    public int toInt() {
        return code;
    }

    public String toString() {
        return label;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        RevocationReason other = (RevocationReason) obj;
        if (code != other.code)
            return false;
        if (label == null) {
            if (other.label != null)
                return false;
        } else if (!label.equals(other.label))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + code;
        result = prime * result + ((label == null) ? 0 : label.hashCode());
        return result;
    }
}
