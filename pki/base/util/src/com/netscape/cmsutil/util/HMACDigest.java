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
package com.netscape.cmsutil.util;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * This class implements the HMAC algorithm specified in RFC 2104 using
 * any MessageDigest.
 *
 * @author mikep
 * @version $Revision: 14564 $, $Date: 2007-05-01 10:40:13 -0700 (Tue, 01 May 2007) $
 * @see java.security.MessageDigest
 */
public class HMACDigest implements Cloneable {
    public static final int PAD_BYTES = 64;
    public static final int IPAD = 0x36;
    public static final int OPAD = 0x5C;

    /**
     * inner padding - key XORd with ipad
     */
    private byte[] mKeyIpad = new byte[PAD_BYTES];

    /**
     * outer padding - key XORd with opad
     */
    private byte[] mKeyOpad = new byte[PAD_BYTES];

    /**
     * The real MessageDigest
     */
    private MessageDigest mMD = null;

    /**
     * Creates an HMACDigest
     *
     * @param md The MessageDigest to be used for the HMAC calculation.  It
     * must be clonable.
     */
    public HMACDigest(MessageDigest md) {
        mMD = md;
    }

    /**
     * Creates an HMACDigest and initializes the HMAC function
     * with the given key.
     *
     * @param md The MessageDigest to be used for the HMAC calculation.  It
     * must be clonable.
     * @param key The key value to be used in the HMAC calculation
     */
    public HMACDigest(MessageDigest md, byte[] key) {
        this(md);
        init(key);
    }

    /**
     * Return the MessageDigest used for this HMAC
     */
    public MessageDigest getMessageDigest() {
        return mMD;
    }

    /**
     * Initialize the HMAC function
     *
     * The HMAC transform looks like:
     *
     *      hash(key XOR opad, hash(key XOR ipad, text))
     *
     * where key is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     *
     * This routine must be called after every reset.
     *
     * @param key The password used to protect the hash value
     */
    public void init(byte[] key) {
        int i;

        reset();

        // If the key is longer than 64 bytes, just hash it down
        if (key.length > 64) {
            key = mMD.digest(key);
            mMD.reset(); // Redundant?
        }

        // Copy the key.  Truncate if key is too long
        for (i = 0; i < key.length && i < PAD_BYTES; i++) {
            mKeyIpad[i] = key[i];
            mKeyOpad[i] = key[i];
        }

        // XOR in the pads
        for (i = 0; i < PAD_BYTES; i++) {
            mKeyIpad[i] ^= IPAD;
            mKeyOpad[i] ^= OPAD;
        }

        mMD.update(mKeyIpad);

        // Hmmm, we really shouldn't key Opad around in memory for so
        // long, but it would just force the user to key their key around
        // until digest() time. Oh well, at least clear the key and Ipad
        for (i = 0; i < PAD_BYTES; i++) {
            mKeyIpad[i] = 0;
        }
        for (i = 0; i < key.length; i++) {
            key[0] = 0;
        }
    }

    /**
     * Updates the digest using the specified array of bytes.
     *
     * @param input the array of bytes.
     */
    public void update(byte[] input) {
        mMD.update(input);
    }

    /**
     * Completes the HMAC computation with the outer pad
     * The digest is reset after this call is made.
     *
     * @return the array of bytes for the resulting hash value.
     */
    public byte[] digest() {
        byte[] finalDigest;
        byte[] innerDigest = mMD.digest();

        mMD.reset(); // Redundant?
        mMD.update(mKeyOpad);
        mMD.update(innerDigest);
        finalDigest = mMD.digest();
        reset(); // Clear pad arrays
        return finalDigest;
    }

    /**
     * Resets the digest for further use.
     */
    public void reset() {
        int i;

        mMD.reset();

        // Clear out the pads
        for (i = 0; i < PAD_BYTES; i++) {
            mKeyIpad[i] = 0;
            mKeyOpad[i] = 0;
        }
    }

    /**
     * Clone the HMACDigest
     *
     * @return a clone if the implementation is cloneable.
     * @exception CloneNotSupportedException if this is called on a 
     * MessageDigest implementation that does not support 
     * <code>Cloneable</code>.
     */
    public Object clone() throws CloneNotSupportedException {
        int i;

        HMACDigest hd = (HMACDigest) super.clone();	

        hd.mKeyOpad = new byte[PAD_BYTES];
        hd.mKeyIpad = new byte[PAD_BYTES];

        for (i = 0; i < PAD_BYTES; i++) {
            hd.mKeyOpad[i] = mKeyOpad[i];
            hd.mKeyIpad[i] = mKeyIpad[i];
        }

        hd.mMD = (MessageDigest) mMD.clone();
        return hd;
    }

}
