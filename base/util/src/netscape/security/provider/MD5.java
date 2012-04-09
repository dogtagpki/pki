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
 * The MD5 class is used to compute an MD5 message digest over a given
 * buffer of bytes. It is an implementation of the RSA Data Security Inc
 * MD5 algorithim as described in internet RFC 1321.
 *
 * @version 1.24 97/12/10
 * @author Chuck McManis
 * @author Benjamin Renaud
 */

public final class MD5 extends MessageDigestSpi implements Cloneable {

    /** contains the computed message digest */
    private byte[] digestBits;

    private int state[];
    private long count; // bit count AND buffer[] index aid
    private byte buffer[];
    private int transformBuffer[];

    private static final int S11 = 7;
    private static final int S12 = 12;
    private static final int S13 = 17;
    private static final int S14 = 22;
    private static final int S21 = 5;
    private static final int S22 = 9;
    private static final int S23 = 14;
    private static final int S24 = 20;
    private static final int S31 = 4;
    private static final int S32 = 11;
    private static final int S33 = 16;
    private static final int S34 = 23;
    private static final int S41 = 6;
    private static final int S42 = 10;
    private static final int S43 = 15;
    private static final int S44 = 21;

    private static final int MD5_LENGTH = 16;

    /**
     * Standard constructor, creates a new MD5 instance, allocates its
     * buffers from the heap.
     */
    public MD5() {
        init();
    }

    /* **********************************************************
     * The MD5 Functions. These are copied verbatim from
     * the RFC to insure accuracy. The results of this
     * implementation were checked against the RSADSI version.
     * **********************************************************
     */

    private int F(int x, int y, int z) {
        return ((x & y) | ((~x) & z));
    }

    private int G(int x, int y, int z) {
        return ((x & z) | (y & (~z)));
    }

    private int H(int x, int y, int z) {
        return ((x ^ y) ^ z);
    }

    private int I(int x, int y, int z) {
        return (y ^ (x | (~z)));
    }

    private int rotateLeft(int a, int n) {
        return ((a << n) | (a >>> (32 - n)));
    }

    private int FF(int a, int b, int c, int d, int x, int s, int ac) {
        a += F(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        a += b;
        return a;
    }

    private int GG(int a, int b, int c, int d, int x, int s, int ac) {
        a += G(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        a += b;
        return a;
    }

    private int HH(int a, int b, int c, int d, int x, int s, int ac) {
        a += H(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        a += b;
        return a;
    }

    private int II(int a, int b, int c, int d, int x, int s, int ac) {
        a += I(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        a += b;
        return a;
    }

    /**
     * This is where the functions come together as the generic MD5
     * transformation operation, it is called by update() which is
     * synchronized (to protect transformBuffer). It consumes sixteen
     * bytes from the buffer, beginning at the specified offset.
     */
    void transform(byte buf[], int offset) {
        int a, b, c, d;
        int x[] = transformBuffer;

        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];

        for (int i = 0; i < 16; i++) {
            x[i] = buf[i * 4 + offset] & 0xff;
            for (int j = 1; j < 4; j++) {
                x[i] += (buf[i * 4 + j + offset] & 0xff) << (j * 8);
            }
        }

        /* Round 1 */
        a = FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
        d = FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
        c = FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
        b = FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
        a = FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
        d = FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
        c = FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
        b = FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
        a = FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
        d = FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
        c = FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
        b = FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
        a = FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
        d = FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
        c = FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
        b = FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

        /* Round 2 */
        a = GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
        d = GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
        c = GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
        b = GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
        a = GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
        d = GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
        c = GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
        b = GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
        a = GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
        d = GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
        c = GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
        b = GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
        a = GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
        d = GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
        c = GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
        b = GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

        /* Round 3 */
        a = HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
        d = HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
        c = HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
        b = HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
        a = HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
        d = HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
        c = HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
        b = HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
        a = HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
        d = HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
        c = HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
        b = HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
        a = HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
        d = HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
        c = HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
        b = HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

        /* Round 4 */
        a = II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
        d = II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
        c = II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
        b = II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
        a = II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
        d = II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
        c = II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
        b = II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
        a = II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
        d = II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
        c = II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
        b = II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
        a = II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
        d = II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
        c = II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
        b = II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    /**
     * Initialize the MD5 state information and reset the bit count
     * to 0. Given this implementation you are constrained to counting
     * 2^64 bits.
     */
    public void init() {
        state = new int[4];
        transformBuffer = new int[16];
        buffer = new byte[64];
        digestBits = new byte[16];
        count = 0;
        // Load magic initialization constants.
        state[0] = 0x67452301;
        state[1] = 0xefcdab89;
        state[2] = 0x98badcfe;
        state[3] = 0x10325476;
        for (int i = 0; i < digestBits.length; i++)
            digestBits[i] = 0;
    }

    protected void engineReset() {
        init();
    }

    /**
     * Return the digest length in bytes
     */
    protected int engineGetDigestLength() {
        return (MD5_LENGTH);
    }

    /**
     * Update adds the passed byte to the digested data.
     */
    protected synchronized void engineUpdate(byte b) {
        int index;

        index = (int) ((count >>> 3) & 0x3f);
        count += 8;
        buffer[index] = b;
        if (index >= 63) {
            transform(buffer, 0);
        }
    }

    /**
     * Update adds the selected part of an array of bytes to the digest.
     * This version is more efficient than the byte-at-a-time version;
     * it avoids data copies and reduces per-byte call overhead.
     */
    protected synchronized void engineUpdate(byte input[], int offset,
                         int len) {
        int i;

        for (i = offset; len > 0;) {
            int index = (int) ((count >>> 3) & 0x3f);

            if (index == 0 && len > 64) {
                count += (64 * 8);
                transform(input, i);
                len -= 64;
                i += 64;
            } else {
                count += 8;
                buffer[index] = input[i];
                if (index >= 63)
                    transform(buffer, 0);
                i++;
                len--;
            }
        }
    }

    /**
     * Perform the final computations, any buffered bytes are added
     * to the digest, the count is added to the digest, and the resulting
     * digest is stored. After calling final you will need to call
     * init() again to do another digest.
     */
    private void finish() {
        byte bits[] = new byte[8];
        byte padding[];
        int i, index, padLen;

        for (i = 0; i < 8; i++) {
            bits[i] = (byte) ((count >>> (i * 8)) & 0xff);
        }

        index = (int) (count >> 3) & 0x3f;
        padLen = (index < 56) ? (56 - index) : (120 - index);
        padding = new byte[padLen];
        padding[0] = (byte) 0x80;
        engineUpdate(padding, 0, padding.length);
        engineUpdate(bits, 0, bits.length);

        for (i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                digestBits[i * 4 + j] = (byte) ((state[i] >>> (j * 8)) & 0xff);
            }
        }
    }

    /**
     */
    protected byte[] engineDigest() {
        finish();

        byte[] result = new byte[MD5_LENGTH];
        System.arraycopy(digestBits, 0, result, 0, MD5_LENGTH);

        init();

        return result;
    }

    /**
     */
    protected int engineDigest(byte[] buf, int offset, int len)
                        throws DigestException {
        finish();

        if (len < MD5_LENGTH)
            throw new DigestException("partial digests not returned");
        if (buf.length - offset < MD5_LENGTH)
            throw new DigestException("insufficient space in the output " +
                    "buffer to store the digest");

        System.arraycopy(digestBits, 0, buf, offset, MD5_LENGTH);

        init();

        return MD5_LENGTH;
    }

    /*
     * Clones this object.
     */
    public Object clone() {
        MD5 that = null;
        try {
            that = (MD5) super.clone();
            that.state = this.state.clone();
            that.transformBuffer = this.transformBuffer.clone();
            that.buffer = this.buffer.clone();
            that.digestBits = this.digestBits.clone();
            that.count = this.count;
            return that;
        } catch (CloneNotSupportedException e) {
        }
        return that;
    }
}
