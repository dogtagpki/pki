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

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * A low-overhead arbitrary-precision <em>unsigned</em> integer.
 * This is intended for use with ASN.1 parsing, and printing of
 * such parsed values. Convert to "BigInteger" if you need to do
 * arbitrary precision arithmetic, rather than just represent
 * the number as a wrapped array of bytes.
 *
 * <P>
 * <em><b>NOTE:</b>  This class may eventually disappear, to
 * be supplanted by big-endian byte arrays which hold both signed
 * and unsigned arbitrary-precision integers.
 *
 * @version 1.23
 * @author David Brownell
 */
public final class BigInt implements Serializable {

    private static final long serialVersionUID = 705094142021888265L;
    // Big endian -- MSB first.
    private byte[] places;

    /**
     * Constructs a "Big" integer from a set of (big-endian) bytes.
     * Leading zeroes should be stripped off.
     *
     * @param data a sequence of bytes, most significant bytes/digits
     *            first. CONSUMED.
     */
    public BigInt(byte[] data) {
        places = data.clone();
    }

    /**
     * Constructs a "Big" integer from a "BigInteger", which must be
     * positive (or zero) in value.
     */
    public BigInt(BigInteger i) {
        byte[] temp = i.toByteArray();

        if ((temp[0] & 0x80) != 0)
            throw new IllegalArgumentException("negative BigInteger");

        // XXX we assume exactly _one_ sign byte is used...

        if (temp[0] != 0)
            places = temp;
        else {
            // Note that if i = new BigInteger("0"),
            // i.toByteArray() contains only 1 zero.
            if (temp.length == 1) {
                places = new byte[1];
                places[0] = (byte) 0;
            } else {
                places = new byte[temp.length - 1];
                for (int j = 1; j < temp.length; j++)
                    places[j - 1] = temp[j];
            }
        }
    }

    /**
     * Constructs a "Big" integer from a normal Java integer.
     *
     * @param i the java primitive integer
     */
    public BigInt(int i) {
        if (i < (1 << 8)) {
            places = new byte[1];
            places[0] = (byte) i;
        } else if (i < (1 << 16)) {
            places = new byte[2];
            places[0] = (byte) (i >> 8);
            places[1] = (byte) i;
        } else if (i < (1 << 24)) {
            places = new byte[3];
            places[0] = (byte) (i >> 16);
            places[1] = (byte) (i >> 8);
            places[2] = (byte) i;
        } else {
            places = new byte[4];
            places[0] = (byte) (i >> 24);
            places[1] = (byte) (i >> 16);
            places[2] = (byte) (i >> 8);
            places[3] = (byte) i;
        }
    }

    /**
     * Converts the "big" integer to a java primitive integer.
     *
     * @exception NumberFormatException if 32 bits is insufficient.
     */
    public int toInt() {
        if (places.length > 4)
            throw new NumberFormatException("BigInt.toInt, too big");
        int retval = 0, i = 0;
        for (; i < places.length; i++)
            retval = (retval << 8) + (places[i] & 0xff);
        return retval;
    }

    /**
     * Returns a hexadecimal printed representation. The value is
     * formatted to fit on lines of at least 75 characters, with
     * embedded newlines. Words are separated for readability,
     * with eight words (32 bytes) per line.
     */
    public String toString() {
        return hexify();
    }

    /**
     * Returns a BigInteger value which supports many arithmetic
     * operations. Assumes negative values will never occur.
     */
    public BigInteger toBigInteger() {
        return new BigInteger(1, places);
    }

    /**
     * Returns the length of the data as a byte array.
     */
    public int byteLength() {
        return places.length;
    }

    /**
     * Returns the data as a byte array. The most significant bit
     * of the array is bit zero (as in <code>java.math.BigInteger</code>).
     */
    public byte[] toByteArray() {
        if (places.length == 0) {
            byte zero[] = new byte[1];
            zero[0] = (byte) 0;
            return zero;
        } else {
            return places.clone();
        }
    }

    private static final String digits = "0123456789abcdef";

    private String hexify() {
        if (places.length == 0)
            return "  0  ";

        StringBuffer buf = new StringBuffer(places.length * 2);
        buf.append("    "); // four spaces
        for (int i = 0; i < places.length; i++) {
            buf.append(digits.charAt((places[i] >> 4) & 0x0f));
            buf.append(digits.charAt(places[i] & 0x0f));
            if (((i + 1) % 32) == 0) {
                if ((i + 1) != places.length)
                    buf.append("\n    "); // line after four words
            } else if (((i + 1) % 4) == 0)
                buf.append(' '); // space between words
        }
        return buf.toString();
    }

    /**
     * Returns true iff the parameter is a numerically equivalent
     * BigInt.
     *
     * @param other the object being compared with this one.
     */
    public boolean equals(Object other) {
        if (other instanceof BigInt)
            return equals((BigInt) other);
        return false;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(places);
        return result;
    }

    /**
     * Returns true iff the parameter is numerically equivalent.
     *
     * @param other the BigInt being compared with this one.
     */
    public boolean equals(BigInt other) {
        if (this == other)
            return true;

        byte[] otherPlaces = other.toByteArray();
        if (places.length != otherPlaces.length)
            return false;
        for (int i = 0; i < places.length; i++)
            if (places[i] != otherPlaces[i])
                return false;
        return true;
    }
}
