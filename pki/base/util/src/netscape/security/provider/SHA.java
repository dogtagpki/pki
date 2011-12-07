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
package netscape.security.provider;

import java.security.DigestException;
import java.security.MessageDigestSpi;

/**
 * This class implements the Secure Hash Algorithm (SHA) developed by the
 * National Institute of Standards and Technology along with the National
 * Security Agency. This is the updated version of SHA fip-180 as superseded by
 * fip-180-1.
 * 
 * <p>
 * It implement JavaSecurity MessageDigest, and can be used by in the Java
 * Security framework, as a pluggable implementation, as a filter for the digest
 * stream classes.
 * 
 * @version 1.30 97/12/10
 * @author Roger Riggs
 * @author Benjamin Renaud
 */

public class SHA extends MessageDigestSpi implements Cloneable {

    /*
     * This private hookm controlled by the appropriate constructor, causes this
     * class to implement the first version of SHA, as defined in FIPS 180, as
     * opposed to FIPS 180-1. This was useful for DSA testing.
     */
    private int version = 1;

    private static final int SHA_LENGTH = 20;

    // Buffer of int's and count of characters accumulated
    // 64 bytes are included in each hash block so the low order
    // bits of count are used to know how to pack the bytes into ints
    // and to know when to compute the block and start the next one.
    private int W[] = new int[80];
    private long count = 0;
    private final int countmax = 64;
    private final int countmask = (countmax - 1);

    private int AA, BB, CC, DD, EE;

    /**
     * Creates a SHA object.with state (for cloning)
     */
    private SHA(SHA sha) {
        this();
        this.version = sha.version;
        System.arraycopy(sha.W, 0, this.W, 0, W.length);
        this.count = sha.count;
        this.AA = sha.AA;
        this.BB = sha.BB;
        this.CC = sha.CC;
        this.DD = sha.DD;
        this.EE = sha.EE;
    }

    SHA(int version) {
        this();
        this.version = version;
    }

    /**
     * Creates a new SHA object.
     */
    public SHA() {
        init();
    }

    /**
     * Return the length of the digest in bytes
     */
    protected int engineGetDigestLength() {
        return (SHA_LENGTH);
    }

    public void engineUpdate(byte b) {
        engineUpdate((int) b);
    }

    /**
     * Update a byte.
     * 
     * @param b the byte
     */
    private void engineUpdate(int b) {
        int word;
        int offset;

        /*
         * compute word offset and bit offset within word the low bits of count
         * are inverted to make put the bytes in the write order
         */
        word = ((int) count & countmask) >>> 2;
        offset = (~(int) count & 3) << 3;

        W[word] = (W[word] & ~(0xff << offset)) | ((b & 0xff) << offset);

        /* If this is the last byte of a block, compute the partial hash */
        if (((int) count & countmask) == countmask) {
            computeBlock();
        }
        count++;
    }

    /**
     * Update a buffer.
     * 
     * @param b the data to be updated.
     * @param off the start offset in the data
     * @param len the number of bytes to be updated.
     */
    public void engineUpdate(byte b[], int off, int len) {
        int word;
        int offset;

        if ((off < 0) || (len < 0) || (off + len > b.length))
            throw new ArrayIndexOutOfBoundsException();

        // Use single writes until integer aligned
        while ((len > 0) && ((int) count & 3) != 0) {
            engineUpdate(b[off]);
            off++;
            len--;
        }

        /* Assemble groups of 4 bytes to be inserted in integer array */
        for (; len >= 4; len -= 4, off += 4) {

            word = ((int) count & countmask) >> 2;

            W[word] = ((b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16)
                    | ((b[off + 2] & 0xff) << 8) | ((b[off + 3] & 0xff));

            count += 4;
            if (((int) count & countmask) == 0) {
                computeBlock();
            }
        }

        /* Use single writes for last few bytes */
        for (; len > 0; len--, off++) {
            engineUpdate(b[off]);
        }
    }

    /**
     * Resets the buffers and hash value to start a new hash.
     */
    public void init() {
        AA = 0x67452301;
        BB = 0xefcdab89;
        CC = 0x98badcfe;
        DD = 0x10325476;
        EE = 0xc3d2e1f0;

        for (int i = 0; i < 80; i++)
            W[i] = 0;
        count = 0;
    }

    /**
     * Resets the buffers and hash value to start a new hash.
     */
    public void engineReset() {
        init();
    }

    /**
     * Computes the final hash and returns the final value as a byte[20] array.
     * The object is reset to be ready for further use, as specified in the
     * JavaSecurity MessageDigest specification.
     */
    public byte[] engineDigest() {
        byte hashvalue[] = new byte[SHA_LENGTH];

        try {
            int outLen = engineDigest(hashvalue, 0, hashvalue.length);
        } catch (DigestException e) {
            throw new InternalError("");
        }
        return hashvalue;
    }

    /**
     * Computes the final hash and returns the final value as a byte[20] array.
     * The object is reset to be ready for further use, as specified in the
     * JavaSecurity MessageDigest specification.
     */
    public int engineDigest(byte[] hashvalue, int offset, int len)
            throws DigestException {

        if (len < SHA_LENGTH)
            throw new DigestException("partial digests not returned");
        if (hashvalue.length - offset < SHA_LENGTH)
            throw new DigestException("insufficient space in the output "
                    + "buffer to store the digest");

        /* The number of bits before padding occurs */
        long bits = count << 3;

        engineUpdate(0x80);

        /*
         * Pad with zeros until length is a multiple of 448 (the last two 32
         * ints are used a holder for bits (see above).
         */
        while ((int) (count & countmask) != 56) {
            engineUpdate(0);
        }

        W[14] = (int) (bits >>> 32);
        W[15] = (int) (bits & 0xffffffff);

        count += 8;
        computeBlock();

        // Copy out the result
        hashvalue[offset + 0] = (byte) (AA >>> 24);
        hashvalue[offset + 1] = (byte) (AA >>> 16);
        hashvalue[offset + 2] = (byte) (AA >>> 8);
        hashvalue[offset + 3] = (byte) (AA >>> 0);

        hashvalue[offset + 4] = (byte) (BB >>> 24);
        hashvalue[offset + 5] = (byte) (BB >>> 16);
        hashvalue[offset + 6] = (byte) (BB >>> 8);
        hashvalue[offset + 7] = (byte) (BB >>> 0);

        hashvalue[offset + 8] = (byte) (CC >>> 24);
        hashvalue[offset + 9] = (byte) (CC >>> 16);
        hashvalue[offset + 10] = (byte) (CC >>> 8);
        hashvalue[offset + 11] = (byte) (CC >>> 0);

        hashvalue[offset + 12] = (byte) (DD >>> 24);
        hashvalue[offset + 13] = (byte) (DD >>> 16);
        hashvalue[offset + 14] = (byte) (DD >>> 8);
        hashvalue[offset + 15] = (byte) (DD >>> 0);

        hashvalue[offset + 16] = (byte) (EE >>> 24);
        hashvalue[offset + 17] = (byte) (EE >>> 16);
        hashvalue[offset + 18] = (byte) (EE >>> 8);
        hashvalue[offset + 19] = (byte) (EE >>> 0);

        engineReset(); // remove the evidence

        return SHA_LENGTH;
    }

    // Constants for each round
    private final int round1_kt = 0x5a827999;
    private final int round2_kt = 0x6ed9eba1;
    private final int round3_kt = 0x8f1bbcdc;
    private final int round4_kt = 0xca62c1d6;

    /**
     * Compute a the hash for the current block.
     * 
     * This is in the same vein as Peter Gutmann's algorithm listed in the back
     * of Applied Cryptography, Compact implementation of "old" NIST Secure Hash
     * Algorithm.
     * 
     */
    private void computeBlock() {
        int temp, a, b, c, d, e;

        // The first 16 ints have the byte stream, compute the rest of
        // the buffer
        for (int t = 16; t <= 79; t++) {
            if (version == 0) {
                W[t] = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
            } else {
                temp = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
                W[t] = ((temp << 1) | (temp >>> (32 - 1)));
            }
        }

        a = AA;
        b = BB;
        c = CC;
        d = DD;
        e = EE;

        // Round 1
        for (int i = 0; i < 20; i++) {
            temp = ((a << 5) | (a >>> (32 - 5))) + ((b & c) | ((~b) & d)) + e
                    + W[i] + round1_kt;
            e = d;
            d = c;
            c = ((b << 30) | (b >>> (32 - 30)));
            b = a;
            a = temp;
        }

        // Round 2
        for (int i = 20; i < 40; i++) {
            temp = ((a << 5) | (a >>> (32 - 5))) + (b ^ c ^ d) + e + W[i]
                    + round2_kt;
            e = d;
            d = c;
            c = ((b << 30) | (b >>> (32 - 30)));
            b = a;
            a = temp;
        }

        // Round 3
        for (int i = 40; i < 60; i++) {
            temp = ((a << 5) | (a >>> (32 - 5)))
                    + ((b & c) | (b & d) | (c & d)) + e + W[i] + round3_kt;
            e = d;
            d = c;
            c = ((b << 30) | (b >>> (32 - 30)));
            b = a;
            a = temp;
        }

        // Round 4
        for (int i = 60; i < 80; i++) {
            temp = ((a << 5) | (a >>> (32 - 5))) + (b ^ c ^ d) + e + W[i]
                    + round4_kt;
            e = d;
            d = c;
            c = ((b << 30) | (b >>> (32 - 30)));
            b = a;
            a = temp;
        }
        AA += a;
        BB += b;
        CC += c;
        DD += d;
        EE += e;
    }

    /*
     * Clones this object.
     */
    public Object clone() {
        SHA that = null;
        try {
            that = (SHA) super.clone();
            that.W = new int[80];
            System.arraycopy(this.W, 0, that.W, 0, W.length);
            return that;
        } catch (CloneNotSupportedException e) {
        }
        return that;
    }
}
