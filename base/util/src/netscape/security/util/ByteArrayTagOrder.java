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
package netscape.security.util;

import java.util.Comparator;

public class ByteArrayTagOrder implements Comparator<byte[]>, java.io.Serializable {

    private static final long serialVersionUID = -2027007556858126443L;

    /**
     * Compare two byte arrays, by the order of their tags,
     * as defined in ITU-T X.680, sec. 6.4. (First compare
     * tag classes, then tag numbers, ignoring the constructivity bit.)
     *
     * @param obj1 first byte array to compare.
     * @param obj2 second byte array to compare.
     * @return negative number if obj1 < obj2, 0 if obj1 == obj2,
     *         positive number if obj1 > obj2.
     *
     * @exception <code>ClassCastException</code> if either argument is not a byte array.
     */

    public final int compare(byte[] bytes1, byte[] bytes2) {

        // tag order is same as byte order ignoring any difference in
        // the constructivity bit (0x02)
        return (bytes1[0] | 0x20) - (bytes2[0] | 0x20);
    }

}
