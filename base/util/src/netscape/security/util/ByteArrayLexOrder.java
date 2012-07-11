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

/**
 * Compare two byte arrays in lexicographical order.
 *
 * @version 1.4 97/12/10
 * @author D. N. Hoover
 */
public class ByteArrayLexOrder implements Comparator<byte[]>, java.io.Serializable {

    private static final long serialVersionUID = 1897537410212918669L;

    /**
     * Perform lexicographical comparison of two byte arrays,
     * regarding each byte as unsigned. That is, compare array entries
     * in order until they differ--the array with the smaller entry
     * is "smaller". If array entries are
     * equal till one array ends, then the longer array is "bigger".
     *
     * @param obj1 first byte array to compare.
     * @param obj2 second byte array to compare.
     * @return negative number if obj1 < obj2, 0 if obj1 == obj2,
     *         positive number if obj1 > obj2.
     *
     * @exception <code>ClassCastException</code> if either argument is not a byte array.
     */
    public final int compare(byte[] bytes1, byte[] bytes2) {

        int diff;
        for (int i = 0; i < bytes1.length && i < bytes2.length; i++) {
            diff = (bytes1[i] & 0xFF) - (bytes2[i] & 0xFF);
            if (diff != 0) {
                return diff;
            }
        }
        // if array entries are equal till the first ends, then the
        // longer is "bigger"
        return bytes1.length - bytes2.length;
    }

}
