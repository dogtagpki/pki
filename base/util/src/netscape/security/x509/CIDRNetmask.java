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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package netscape.security.x509;

import java.nio.ByteBuffer;

/**
 * Netmask that is the number of significant bits.
 */
public class CIDRNetmask {
    private int n;

    public CIDRNetmask(String s) {
        this(Integer.parseInt(s));
    }

    public CIDRNetmask(int n) {
        if (n < 0)
            throw new InvalidNetmaskException("cannot be negative");
        this.n = n;
    }

    /**
     * Write the netmask into a byte buffer.
     *
     * Throw InvalidNetmaskException if negative or if the
     * size exceeds the size of the address type inferred
     * from the remaining buffer space (which must be 4
     * bytes for IPv4 and 16 bytes for IPv6).
     *
     * exceeds the size of the buffer
     */
    protected void write(ByteBuffer buf) {
        // determine type of addr based on bytes left in buffer
        int remaining = buf.remaining();
        int bits = 0;
        if (remaining == 4)
            bits = 32;
        else if (remaining == 16)
            bits = 128;
        else
            throw new InvalidNetmaskException(
                "cannot determine type of address for netmask");

        if (n > bits)
            throw new InvalidNetmaskException("netmask exceed address size");

        int maskSigBits = n;
        for (; remaining > 0; remaining--) {
            int maskByteSigBits = Math.min(8, maskSigBits);
            byte maskByte = (byte) (0xff - (0xff >> maskByteSigBits));
            buf.put(maskByte);
            maskSigBits = Math.max(maskSigBits - 8, 0);
        }
    }

    public String toString() {
        return "/" + n;
    }

}
