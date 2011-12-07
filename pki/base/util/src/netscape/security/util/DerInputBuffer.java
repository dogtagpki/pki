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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * DER input buffer ... this is the main abstraction in the DER library which
 * actively works with the "untyped byte stream" abstraction. It does so with
 * impunity, since it's not intended to be exposed to the anyone who could
 * violate the "typed value stream" DER model and hence corrupt the input stream
 * of DER values.
 * 
 * @version 1.11
 * @author David Brownell
 */
class DerInputBuffer extends ByteArrayInputStream implements Cloneable {

    DerInputBuffer(byte[] buf) {
        super(buf);
    }

    DerInputBuffer(byte[] buf, int offset, int len) {
        super(buf, offset, len);
    }

    DerInputBuffer dup() {
        try {
            DerInputBuffer retval = (DerInputBuffer) clone();

            retval.mark(Integer.MAX_VALUE);
            return retval;
        } catch (CloneNotSupportedException e) {
            throw new IllegalArgumentException(e.toString());
        }
    }

    byte[] toByteArray() {
        int len = available();
        if (len <= 0)
            return null;
        byte[] retval = new byte[len];

        System.arraycopy(buf, pos, retval, 0, len);
        return retval;
    }

    int peek() throws IOException {
        if (pos >= count)
            throw new IOException("out of data");
        else
            return buf[pos];
    }

    /**
     * Compares this DerInputBuffer for equality with the specified object.
     */
    public boolean equals(Object other) {
        if (other instanceof DerInputBuffer)
            return equals((DerInputBuffer) other);
        else
            return false;
    }

    boolean equals(DerInputBuffer other) {
        if (this == other)
            return true;

        int max = this.available();
        if (other.available() != max)
            return false;
        for (int i = 0; i < max; i++) {
            if (this.buf[this.pos + i] != other.buf[other.pos + i]) {
                return false;
            }
        }
        return true;
    }

    void truncate(int len) throws IOException {
        if (len > available())
            throw new IOException("insufficient data");
        count = pos + len;
    }

    /**
     * Returns the unsigned integer which takes up the specified number of bytes
     * in this buffer.
     */
    BigInt getUnsigned(int len) throws IOException {
        if (len > available())
            throw new IOException("short read, getInteger");

        /*
         * A prepended zero is used to ensure that the integer is interpreted as
         * unsigned even when the high order bit is zero. We don't support
         * signed BigInts.
         * 
         * Fix this here ... BigInts aren't expected to have these, and stuff
         * like signing (sigsize = f(modulus)) misbehaves.
         */
        if (len > 1 && buf[pos] == 0) {
            len--;
            skip(1);
        }

        /*
         * Consume the rest of the buffer, returning its value as an unsigned
         * integer.
         */
        byte[] bytes = new byte[len];

        System.arraycopy(buf, pos, bytes, 0, len);
        skip(len);
        return new BigInt(bytes);
    }

    /**
     * Returns the bit string which takes up the rest of this buffer. This bit
     * string must be byte-aligned.
     */
    byte[] getBitString() {
        if (pos >= count || buf[pos] != 0)
            return null;
        /*
         * Just copy the data into an aligned, padded octet buffer, and consume
         * the rest of the buffer.
         */
        int len = available();
        byte[] retval = new byte[len - 1];

        System.arraycopy(buf, pos + 1, retval, 0, len - 1);
        pos = count;
        return retval;
    }

    /**
     * Returns the bit string which takes up the rest of this buffer. The bit
     * string need not be byte-aligned.
     */
    BitArray getUnalignedBitString() {
        if (pos >= count)
            return null;
        /*
         * Just copy the data into an aligned, padded octet buffer, and consume
         * the rest of the buffer.
         */
        int len = available();
        byte[] bits = new byte[len - 1];
        int length = bits.length * 8 - buf[pos]; // number of valid bits

        System.arraycopy(buf, pos + 1, bits, 0, len - 1);

        BitArray bitArray = new BitArray(length, bits);
        pos = count;
        return bitArray;
    }

    /**
     * Package-access method to optimize output operations
     */
    void dump(OutputStream out, int length) throws IOException {
        if (count < mark + length)
            throw new IOException("short DER value (encode)");
        out.write(buf, mark, length);
    }

}
