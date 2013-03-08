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

import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;

import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * The Digital Signature Standard (using the Digital Signature
 * Algorithm), as described in fips186 of the National Instute of
 * Standards and Technology (NIST), using fips180-1 (SHA-1).
 *
 * @author Benjamin Renaud
 *
 * @version 1.86, 97/09/17
 *
 * @see DSAPublicKey
 * @see DSAPrivateKey
 */

public final class DSA extends Signature {

    /* Are we debugging? */
    private static boolean debug = false;

    /* The parameter object */
    @SuppressWarnings("unused")
    private DSAParams params;

    /* algorithm parameters */
    private BigInteger presetP, presetQ, presetG;

    /* The public key, if any */
    private BigInteger presetY;

    /* The private key, if any */
    private BigInteger presetX;

    /* The SHA hash for the data */
    private MessageDigest dataSHA;

    /* The random seed used to generate k */
    private int[] Kseed;

    /* The random seed used to generate k (specified by application) */
    private byte[] KseedAsByteArray;

    /*
     * The random seed used to generate k
     * (prevent the same Kseed from being used twice in a row
     */
    private int[] previousKseed;

    /* The RNG used to output a seed for generating k */
    private SecureRandom signingRandom;

    /**
     * Construct a blank DSA object. It can generate keys, but must be
     * initialized before being usable for signing or verifying.
     */
    public DSA() throws NoSuchAlgorithmException {
        super("SHA/DSA");
        dataSHA = MessageDigest.getInstance("SHA");
    }

    /**
     * Initialize the DSA object with a DSA private key.
     *
     * @param privateKey the DSA private key
     *
     * @exception InvalidKeyException if the key is not a valid DSA private
     *                key.
     */
    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        if (!(privateKey instanceof java.security.interfaces.DSAPrivateKey)) {
            throw new InvalidKeyException("not a DSA private key: " +
                      privateKey);
        }
        java.security.interfaces.DSAPrivateKey priv =
                (java.security.interfaces.DSAPrivateKey) privateKey;

        this.presetX = priv.getX();
        initialize(priv.getParams());
    }

    /**
     * Initialize the DSA object with a DSA public key.
     *
     * @param publicKey the DSA public key.
     *
     * @exception InvalidKeyException if the key is not a valid DSA public
     *                key.
     */
    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        if (!(publicKey instanceof java.security.interfaces.DSAPublicKey)) {
            throw new InvalidKeyException("not a DSA public key: " +
                      publicKey);
        }
        java.security.interfaces.DSAPublicKey pub =
                (java.security.interfaces.DSAPublicKey) publicKey;
        this.presetY = pub.getY();
        initialize(pub.getParams());
    }

    private void initialize(DSAParams params) {
        dataSHA.reset();
        setParams(params);
    }

    /**
     * Sign all the data thus far updated. The signature is formatted
     * according to the Canonical Encoding Rules, returned as a DER
     * sequence of Integer, r and s.
     *
     * @return a signature block formatted according to the Canonical
     *         Encoding Rules.
     *
     * @exception SignatureException if the signature object was not
     *                properly initialized, or if another exception occurs.
     *
     * @see netscape.security.provider.DSA#engineUpdate
     * @see netscape.security.provider.DSA#engineVerify
     */
    protected byte[] engineSign() throws SignatureException {
        BigInteger k = generateK(presetQ);
        BigInteger r = generateR(presetP, presetQ, presetG, k);
        BigInteger s = generateS(presetX, presetQ, r, k);

        // got to convert to BigInt...
        BigInt rAsBigInt = new BigInt(r.toByteArray());
        BigInt sAsBigInt = new BigInt(s.toByteArray());

        try (DerOutputStream outseq = new DerOutputStream(100)) {
            outseq.putInteger(rAsBigInt);
            outseq.putInteger(sAsBigInt);
            DerValue result = new DerValue(DerValue.tag_Sequence,
                       outseq.toByteArray());

            return result.toByteArray();

        } catch (IOException e) {
            throw new SignatureException("error encoding signature");
        }
    }

    /**
     * Verify all the data thus far updated.
     *
     * @param signature the alledged signature, encoded using the
     *            Canonical Encoding Rules, as a sequence of integers, r and s.
     *
     * @exception SignatureException if the signature object was not
     *                properly initialized, or if another exception occurs.
     *
     * @see netscape.security.provider.DSA#engineUpdate
     * @see netscape.security.provider.DSA#engineSign
     */
    protected boolean engineVerify(byte[] signature)
            throws SignatureException {

        BigInteger r = null;
        BigInteger s = null;
        // first decode the signature.
        try {
            DerInputStream in = new DerInputStream(signature);
            DerValue[] values = in.getSequence(2);

            r = values[0].getInteger().toBigInteger();
            s = values[1].getInteger().toBigInteger();

        } catch (IOException e) {
            throw new SignatureException("invalid encoding for signature");
        }
        BigInteger w = generateW(presetP, presetQ, presetG, s);
        BigInteger v = generateV(presetY, presetP, presetQ, presetG, w, r);

        return v.equals(r);
    }

    BigInteger generateR(BigInteger p, BigInteger q, BigInteger g,
             BigInteger k) {
        BigInteger temp = g.modPow(k, p);
        return temp.remainder(q);

    }

    BigInteger generateS(BigInteger x, BigInteger q,
                 BigInteger r, BigInteger k) {

        byte[] s2 = dataSHA.digest();
        BigInteger temp = new BigInteger(1, s2);
        BigInteger k1 = k.modInverse(q);

        BigInteger s = x.multiply(r);
        s = temp.add(s);
        s = k1.multiply(s);
        return s.remainder(q);
    }

    BigInteger generateW(BigInteger p, BigInteger q,
             BigInteger g, BigInteger s) {
        return s.modInverse(q);
    }

    BigInteger generateV(BigInteger y, BigInteger p,
             BigInteger q, BigInteger g,
             BigInteger w, BigInteger r) {

        byte[] s2 = dataSHA.digest();
        BigInteger temp = new BigInteger(1, s2);

        temp = temp.multiply(w);
        BigInteger u1 = temp.remainder(q);

        BigInteger u2 = (r.multiply(w)).remainder(q);

        BigInteger t1 = g.modPow(u1, p);
        BigInteger t2 = y.modPow(u2, p);
        BigInteger t3 = t1.multiply(t2);
        BigInteger t5 = t3.remainder(p);
        return t5.remainder(q);
    }

    /*
     * Please read bug report 4044247 for an alternative, faster,
     * NON-FIPS approved method to generate K
     */
    BigInteger generateK(BigInteger q) {

        BigInteger k = null;

        // The application specified a Kseed for us to use.
        // Note that we do not allow usage of the same Kseed twice in a row
        if (Kseed != null && compareSeeds(Kseed, previousKseed) != 0) {
            k = generateK(Kseed, q);
            if (k.signum() > 0 && k.compareTo(q) < 0) {
                previousKseed = new int[Kseed.length];
                System.arraycopy(Kseed, 0, previousKseed, 0, Kseed.length);
                return k;
            }
        }

        // The application did not specify a Kseed for us to use.
        // We'll generate a new Kseed by getting random bytes from
        // a SecureRandom object.
        SecureRandom random = getSigningRandom();

        while (true) {
            int[] seed = new int[5];

            for (int i = 0; i < 5; i++)
                seed[i] = random.nextInt();
            k = generateK(seed, q);
            if (k.signum() > 0 && k.compareTo(q) < 0) {
                previousKseed = new int[seed.length];
                System.arraycopy(seed, 0, previousKseed, 0, seed.length);
                return k;
            }
        }
    }

    // Use the application-specified SecureRandom Object if provided.
    // Otherwise, use our default SecureRandom Object.
    private SecureRandom getSigningRandom() {
        if (signingRandom == null) {
            if (appRandom != null)
                signingRandom = appRandom;
            else
                signingRandom = new SecureRandom();
        }
        return signingRandom;
    }

    /*
     * return 0 if equal
     * return 1 if not equal
     */
    private int compareSeeds(int[] seed1, int[] seed2) {

        if (seed1 == null || seed2 == null) {
            return 1;
        }
        if (seed1.length != seed2.length) {
            return 1;
        }

        for (int i = 0; i < seed1.length; i++) {
            if (seed1[i] != seed2[i])
                return 1;
        }

        return 0;

    }

    /**
     * Compute k for a DSA signature.
     *
     * @param seed the seed for generating k. This seed should be
     *            secure. This is what is refered to as the KSEED in the DSA
     *            specification.
     *
     * @param g the g parameter from the DSA key pair.
     */
    BigInteger generateK(int[] seed, BigInteger q) {

        // check out t in the spec.
        int[] t = { 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                0xC3D2E1F0, 0x67452301 };
        //
        int[] tmp = DSA.SHA_7(seed, t);
        byte[] tmpBytes = new byte[tmp.length * 4];
        for (int i = 0; i < tmp.length; i++) {
            int k = tmp[i];
            for (int j = 0; j < 4; j++) {
                tmpBytes[(i * 4) + j] = (byte) (k >>> (24 - (j * 8)));
            }
        }
        BigInteger k = new BigInteger(1, tmpBytes).mod(q);
        return k;
    }

    // Constants for each round
    private static final int round1_kt = 0x5a827999;
    private static final int round2_kt = 0x6ed9eba1;
    private static final int round3_kt = 0x8f1bbcdc;
    private static final int round4_kt = 0xca62c1d6;

    /**
     * Computes set 1 thru 7 of SHA-1 on m1.
     */
    static int[] SHA_7(int[] m1, int[] h) {

        int[] W = new int[80];
        System.arraycopy(m1, 0, W, 0, m1.length);
        int temp = 0;

        for (int t = 16; t <= 79; t++) {
            temp = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
            W[t] = ((temp << 1) | (temp >>> (32 - 1)));
        }

        int a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 20; i++) {
            temp = ((a << 5) | (a >>> (32 - 5))) +
                    ((b & c) | ((~b) & d)) + e + W[i] + round1_kt;
            e = d;
            d = c;
            c = ((b << 30) | (b >>> (32 - 30)));
            b = a;
            a = temp;
        }

        // Round 2
        for (int i = 20; i < 40; i++) {
            temp = ((a << 5) | (a >>> (32 - 5))) +
                    (b ^ c ^ d) + e + W[i] + round2_kt;
            e = d;
            d = c;
            c = ((b << 30) | (b >>> (32 - 30)));
            b = a;
            a = temp;
        }

        // Round 3
        for (int i = 40; i < 60; i++) {
            temp = ((a << 5) | (a >>> (32 - 5))) +
                    ((b & c) | (b & d) | (c & d)) + e + W[i] + round3_kt;
            e = d;
            d = c;
            c = ((b << 30) | (b >>> (32 - 30)));
            b = a;
            a = temp;
        }

        // Round 4
        for (int i = 60; i < 80; i++) {
            temp = ((a << 5) | (a >>> (32 - 5))) +
                    (b ^ c ^ d) + e + W[i] + round4_kt;
            e = d;
            d = c;
            c = ((b << 30) | (b >>> (32 - 30)));
            b = a;
            a = temp;
        }
        int[] md = new int[5];
        md[0] = h[0] + a;
        md[1] = h[1] + b;
        md[2] = h[2] + c;
        md[3] = h[3] + d;
        md[4] = h[4] + e;
        return md;
    }

    /**
     * This implementation recognizes the following parameter:
     * <dl>
     *
     * <dt><tt>Kseed</tt>
     *
     * <dd>a byte array.
     *
     * </dl>
     *
     * @deprecated
     */
    protected void engineSetParameter(String key, Object param) {

        if (key.equals("KSEED")) {

            if (param instanceof byte[]) {

                Kseed = byteArray2IntArray((byte[]) param);
                KseedAsByteArray = (byte[]) param;

            } else {
                debug("unrecognized param: " + key);
                throw new InvalidParameterException("Kseed not a byte array");
            }

        } else {
            throw new InvalidParameterException("invalid parameter");
        }
    }

    /**
     * Return the value of the requested parameter. Recognized
     * parameters are:
     *
     * <dl>
     *
     * <dt><tt>Kseed</tt>
     *
     * <dd>a byte array.
     *
     * </dl>
     *
     * @return the value of the requested parameter.
     *
     * @deprecated
     */
    protected Object engineGetParameter(String key) {
        if (key.equals("KSEED")) {
            return KseedAsByteArray;
        } else {
            return null;
        }
    }

    /**
     * Set the algorithm object.
     */
    private void setParams(DSAParams params) {
        this.params = params;
        this.presetP = params.getP();
        this.presetQ = params.getQ();
        this.presetG = params.getG();
    }

    /**
     * Update a byte to be signed or verified.
     *
     * @param b the byte to updated.
     */
    protected void engineUpdate(byte b) {
        dataSHA.update(b);
    }

    /**
     * Update an array of bytes to be signed or verified.
     *
     * @param data the bytes to be updated.
     */
    protected void engineUpdate(byte[] data, int off, int len) {
        dataSHA.update(data, off, len);
    }

    /**
     * Return a human readable rendition of the engine.
     */
    public String toString() {
        String printable = "DSA Signature";
        if (presetP != null && presetQ != null && presetG != null) {
            printable += "\n\tp: " + presetP.toString(16);
            printable += "\n\tq: " + presetQ.toString(16);
            printable += "\n\tg: " + presetG.toString(16);
        } else {
            printable += "\n\t P, Q or G not initialized.";
        }
        if (presetY != null) {
            printable += "\n\ty: " + presetY.toString(16);
        }
        if (presetY == null && presetX == null) {
            printable += "\n\tUNINIIALIZED";
        }
        return printable;
    }

    /*
     * Utility routine for converting a byte array into an int array
     */
    private int[] byteArray2IntArray(byte[] byteArray) {

        int j = 0;
        byte[] newBA;
        int mod = byteArray.length % 4;

        // guarantee that the incoming byteArray is a multiple of 4
        // (pad with 0's)
        switch (mod) {
        case 3:
            newBA = new byte[byteArray.length + 1];
            break;
        case 2:
            newBA = new byte[byteArray.length + 2];
            break;
        case 1:
            newBA = new byte[byteArray.length + 3];
            break;
        default:
            newBA = new byte[byteArray.length + 0];
            break;
        }
        System.arraycopy(byteArray, 0, newBA, 0, byteArray.length);

        // copy each set of 4 bytes in the byte array into an integer
        int[] newSeed = new int[newBA.length / 4];
        for (int i = 0; i < newBA.length; i += 4) {
            newSeed[j] = newBA[i + 3] & 0xFF;
            newSeed[j] |= (newBA[i + 2] << 8) & 0xFF00;
            newSeed[j] |= (newBA[i + 1] << 16) & 0xFF0000;
            newSeed[j] |= (newBA[i + 0] << 24) & 0xFF000000;
            j++;
        }

        return newSeed;
    }

    /* We include the test vectors from the DSA specification, FIPS
       186, and the FIPS 186 Change No 1, which updates the test
       vector using SHA-1 instead of SHA (for both the G function and
       the message hash.  */

    static void testDSA() throws Exception {
        PrintStream p = System.out;

        DSA dsa = new DSA();
        int[] Kseed = { 0x687a66d9, 0x0648f993, 0x867e121f,
                0x4ddf9ddb, 0x1205584 };
        BigInteger k = dsa.generateK(Kseed, q512);
        p.println("k: " + k.toString(16));
        BigInteger r = dsa.generateR(p512, q512, g512, k);
        p.println("r: " + r.toString(16));
        byte[] abc = { 0x61, 0x62, 0x63 };
        dsa.dataSHA.update(abc);
        BigInteger s = dsa.generateS(x512, q512, r, k);
        p.println("s: " + s.toString(16));

        dsa.dataSHA.update(abc);
        BigInteger w = dsa.generateW(p512, q512, g512, s);
        p.println("w: " + w.toString(16));
        BigInteger v = dsa.generateV(y512, p512, q512, g512, w, r);
        p.println("v: " + v.toString(16));
        if (v.equals(r)) {
            p.println("signature verifies.");
        } else {
            p.println("signature does not verify.");
        }
    }

    /* Test vector: 512-bit keys generated by our key generator. */

    static BigInteger p512 =
            new BigInteger("fca682ce8e12caba26efccf7110e526db078b05edecb" +
                    "cd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e1" +
                    "2ed0899bcd132acd50d99151bdc43ee737592e17", 16);

    static BigInteger q512 =
            new BigInteger("962eddcc369cba8ebb260ee6b6a126d9346e38c5", 16);

    static BigInteger g512 =
            new BigInteger("678471b27a9cf44ee91a49c5147db1a9aaf244f05a43" +
                    "4d6486931d2d14271b9e35030b71fd73da179069b32e" +
                    "2935630e1c2062354d0da20a6c416e50be794ca4", 16);

    static BigInteger x512 =
            new BigInteger("3406c2d71b04b5fc0db62afcad58a6607d3de688", 16);

    static BigInteger y512 =
            new BigInteger("2d335d76b8ec9d610aa8f2cbb4b149fd96fdd" +
                    "3a9a6e62bd6c2e01d406be4d1d72718a2fe08bea6d12f5e452474461f70f4" +
                    "dea60508e9fe2eaec23d2ec5d1a866", 16);

    /* Official NIST 512-bit test keys */

    static String pString = "8df2a494492276aa3d25759bb06869cbeac0d83afb8d0" +
            "cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec" +
            "0736ee31c80291";

    static BigInteger testP = new BigInteger(pString, 16);

    static String gString = "626d027839ea0a13413163a55b4cb500299d5522956ce" +
            "fcb3bff10f399ce2c2e71cb9de5fa24babf58e5b79521925c9cc42e9f6f464b088cc5" +
            "72af53e6d78802";

    static BigInteger testG = new BigInteger(gString, 16);

    static BigInteger testQ = new BigInteger("c773218c737ec8ee993b4f2ded30" +
                         "f48edace915f", 16);

    static BigInteger testX = new BigInteger("2070b3223dba372fde1c0ffc7b2e" +
                         "3b498b260614", 16);

    static String yString = "19131871d75b1612a819f29d78d1b0d7346f7aa77" +
            "bb62a859bfd6c5675da9d212d3a36ef1672ef660b8c7c255cc0ec74858fba33f44c06" +
            "699630a76b030ee333";

    static BigInteger testY = new BigInteger(yString, 16);

    /* End test vector values */

    private static void debug(String s) {
        if (debug) {
            System.err.println(s);
        }
    }

}
