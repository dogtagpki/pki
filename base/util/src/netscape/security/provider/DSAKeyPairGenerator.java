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

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.interfaces.DSAParams;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Hashtable;

import netscape.security.x509.AlgIdDSA;

/**
 * This class generates DSA key parameters and public/private key
 * pairs according to the DSS standard NIST FIPS 186. It uses the
 * updated version of SHA, SHA-1 as described in FIPS 180-1.
 *
 * @author Benjamin Renaud
 *
 * @version 1.23, 97/12/10
 */

public class DSAKeyPairGenerator extends KeyPairGenerator
        implements java.security.interfaces.DSAKeyPairGenerator {

    private static Hashtable<Integer, AlgIdDSA> precomputedParams;

    static {

        /* We support precomputed parameter for 512, 768 and 1024 bit
           moduli. In this file we provide both the seed and counter
           value of the generation process for each of these seeds,
           for validation purposes. We also include the test vectors
           from the DSA specification, FIPS 186, and the FIPS 186
           Change No 1, which updates the test vector using SHA-1
           instead of SHA (for both the G function and the message
           hash.
           */

        precomputedParams = new Hashtable<Integer, AlgIdDSA>();

        /*
         * L = 512
         * SEED = b869c82b35d70e1b1ff91b28e37a62ecdc34409b
         * counter = 123
         */
        BigInteger p512 =
                new BigInteger("fca682ce8e12caba26efccf7110e526db078b05edecb" +
                        "cd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e1" +
                        "2ed0899bcd132acd50d99151bdc43ee737592e17", 16);

        BigInteger q512 =
                new BigInteger("962eddcc369cba8ebb260ee6b6a126d9346e38c5", 16);

        BigInteger g512 =
                new BigInteger("678471b27a9cf44ee91a49c5147db1a9aaf244f05a43" +
                        "4d6486931d2d14271b9e35030b71fd73da179069b32e" +
                        "2935630e1c2062354d0da20a6c416e50be794ca4", 16);

        /*
         * L = 768
         * SEED = 77d0f8c4dad15eb8c4f2f8d6726cefd96d5bb399
         * counter = 263
         */
        BigInteger p768 =
                new BigInteger("e9e642599d355f37c97ffd3567120b8e25c9cd43e" +
                        "927b3a9670fbec5d890141922d2c3b3ad24800937" +
                        "99869d1e846aab49fab0ad26d2ce6a22219d470bc" +
                        "e7d777d4a21fbe9c270b57f607002f3cef8393694" +
                        "cf45ee3688c11a8c56ab127a3daf", 16);

        BigInteger q768 =
                new BigInteger("9cdbd84c9f1ac2f38d0f80f42ab952e7338bf511",
                        16);

        BigInteger g768 =
                new BigInteger("30470ad5a005fb14ce2d9dcd87e38bc7d1b1c5fac" +
                        "baecbe95f190aa7a31d23c4dbbcbe06174544401a" +
                        "5b2c020965d8c2bd2171d3668445771f74ba084d2" +
                        "029d83c1c158547f3a9f1a2715be23d51ae4d3e5a" +
                        "1f6a7064f316933a346d3f529252", 16);

        /*
         * L = 1024
         * SEED = 8d5155894229d5e689ee01e6018a237e2cae64cd
         * counter = 92
         */
        BigInteger p1024 =
                new BigInteger("fd7f53811d75122952df4a9c2eece4e7f611b7523c" +
                        "ef4400c31e3f80b6512669455d402251fb593d8d58" +
                        "fabfc5f5ba30f6cb9b556cd7813b801d346ff26660" +
                        "b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c6" +
                        "1bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554" +
                        "135a169132f675f3ae2b61d72aeff22203199dd148" +
                        "01c7", 16);

        BigInteger q1024 =
                new BigInteger("9760508f15230bccb292b982a2eb840bf0581cf5",
                        16);

        BigInteger g1024 =
                new BigInteger("f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa" +
                        "3aea82f9574c0b3d0782675159578ebad4594fe671" +
                        "07108180b449167123e84c281613b7cf09328cc8a6" +
                        "e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f" +
                        "0bfa213562f1fb627a01243bcca4f1bea8519089a8" +
                        "83dfe15ae59f06928b665e807b552564014c3bfecf" +
                        "492a", 16);

        try {
            AlgIdDSA alg512 = new AlgIdDSA(p512, q512, g512);
            AlgIdDSA alg768 = new AlgIdDSA(p768, q768, g768);
            AlgIdDSA alg1024 = new AlgIdDSA(p1024, q1024, g1024);

            precomputedParams.put(Integer.valueOf(512), alg512);
            precomputedParams.put(Integer.valueOf(768), alg768);
            precomputedParams.put(Integer.valueOf(1024), alg1024);

        } catch (Exception e) {
            throw new InternalError("initializing precomputed " +
                     "algorithm parameters for Sun DSA");
        }
    }

    /* The modulus length */
    private int modlen = 1024;

    /* Generate new parameters, even if we have precomputed ones. */
    boolean generateNewParameters = false;

    /* preset algorithm parameters. */
    private BigInteger presetP, presetQ, presetG;

    /* The source of random bits to use */
    SecureRandom random;

    public DSAKeyPairGenerator() {
        super("DSA");
    }

    public void initialize(int strength, SecureRandom random) {
        if ((strength < 512) || (strength > 1024) || (strength % 64 != 0)) {
            throw new InvalidParameterException("Modulus size must range from 512 to 1024 "
                    + "and be a multiple of 64");
        }

        /* Set the random */
        this.random = random;
        if (this.random == null) {
            this.random = new SecureRandom();
        }

        this.modlen = strength;
        DSAParams params = null;

        /* Find the precomputed parameters, if any */
        if (!generateNewParameters) {
            Integer mod = Integer.valueOf(this.modlen);
            params = precomputedParams.get(mod);
        }
        if (params != null) {
            setParams(params);
        }
    }

    /**
     * Initializes the DSA key pair generator. If <code>genParams</code> is false, a set of pre-computed parameters is
     * used. In this case, <code>modelen</code> must be 512, 768, or 1024.
     */
    public void initialize(int modlen, boolean genParams, SecureRandom random)
            throws InvalidParameterException {
        if (genParams == false && modlen != 512 && modlen != 768
                && modlen != 1024) {
            throw new InvalidParameterException("No precomputed parameters for requested modulus size "
                    + "available");
        }
        this.generateNewParameters = genParams;
        initialize(modlen, random);
    }

    /**
     * Initializes the DSA object using a DSA parameter object.
     *
     * @param params a fully initialized DSA parameter object.
     */
    public void initialize(DSAParams params, SecureRandom random)
            throws InvalidParameterException {
        initialize(params.getP().bitLength(), random);
        setParams(params);
    }

    /**
     * Initializes the DSA object using a parameter object.
     *
     * @param params the parameter set to be used to generate
     *            the keys.
     * @param random the source of randomness for this generator.
     *
     * @exception InvalidAlgorithmParameterException if the given parameters
     *                are inappropriate for this key pair generator
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof DSAParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Inappropriate parameter");
        }
        initialize(((DSAParameterSpec) params).getP().bitLength(),
                random);
        setParams((DSAParameterSpec) params);
    }

    /**
     * Generates a pair of keys usable by any JavaSecurity compliant
     * DSA implementation.
     *
     * @param rnd the source of random bits from which the random key
     *            generation parameters are drawn. In particular, this includes
     *            the XSEED parameter.
     *
     * @exception InvalidParameterException if the modulus is not
     *                between 512 and 1024.
     */
    public KeyPair generateKeyPair() {

        // set random if initialize() method has been skipped
        if (this.random == null) {
            this.random = new SecureRandom();
        }

        if (presetP == null || presetQ == null || presetG == null ||
                generateNewParameters) {

            AlgorithmParameterGenerator dsaParamGen;

            try {
                dsaParamGen = AlgorithmParameterGenerator.getInstance("DSA",
                                      "SUN");
            } catch (NoSuchAlgorithmException e) {
                // this should never happen, because we provide it
                throw new RuntimeException(e.getMessage());
            } catch (NoSuchProviderException e) {
                // this should never happen, because we provide it
                throw new RuntimeException(e.getMessage());
            }

            dsaParamGen.init(modlen, random);

            DSAParameterSpec dsaParamSpec;
            try {
                dsaParamSpec = dsaParamGen.generateParameters().getParameterSpec
                        (DSAParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                // this should never happen
                throw new RuntimeException(e.getMessage());
            }
            presetP = dsaParamSpec.getP();
            presetQ = dsaParamSpec.getQ();
            presetG = dsaParamSpec.getG();
        }

        return generateKeyPair(presetP, presetQ, presetG, random);
    }

    public KeyPair generateKeyPair(BigInteger p, BigInteger q, BigInteger g,
                   SecureRandom random) {

        BigInteger x = generateX(random, q);
        BigInteger y = generateY(x, p, g);

        try {
            DSAPublicKey pub = new DSAPublicKey(y, p, q, g);
            DSAPrivateKey priv = new DSAPrivateKey(x, p, q, g);

            KeyPair pair = new KeyPair(pub, priv);
            return pair;

        } catch (InvalidKeyException e) {
            throw new ProviderException(e.getMessage());
        }
    }

    /* Test vectors from the DSA specs. */

    private static int[] testXSeed = { 0xbd029bbe, 0x7f51960b, 0xcf9edb2b,
                       0x61f06f0f, 0xeb5a38b6 };

    private int[] x_t = { 0x67452301, 0xefcdab89, 0x98badcfe,
              0x10325476, 0xc3d2e1f0 };

    /**
     * Generate the private key component of the key pair using the
     * provided source of random bits. This method uses the random but
     * source passed to generate a seed and then calls the seed-based
     * generateX method.
     */
    private BigInteger generateX(SecureRandom random, BigInteger q) {
        BigInteger x = null;
        while (true) {
            int[] seed = new int[5];
            for (int i = 0; i < 5; i++) {
                seed[i] = random.nextInt();
            }
            x = generateX(seed, q);
            if (x.signum() > 0 && (x.compareTo(q) < 0)) {
                break;
            }
        }
        return x;
    }

    /**
     * Given a seed, generate the private key component of the key
     * pair. In the terminology used in the DSA specification
     * (FIPS-186) seed is the XSEED quantity.
     *
     * @param seed the seed to use to generate the private key.
     */
    BigInteger generateX(int[] seed, BigInteger q) {

        /* Test vector
        int[] tseed = { 0xbd029bbe, 0x7f51960b, 0xcf9edb2b,
        		 0x61f06f0f, 0xeb5a38b6 };
        seed = tseed;
        */
        // check out t in the spec.
        int[] t = { 0x67452301, 0xEFCDAB89, 0x98BADCFE,
                0x10325476, 0xC3D2E1F0 };
        //

        int[] tmp = DSA.SHA_7(seed, t);
        byte[] tmpBytes = new byte[tmp.length * 4];
        for (int i = 0; i < tmp.length; i++) {
            int k = tmp[i];
            for (int j = 0; j < 4; j++) {
                tmpBytes[(i * 4) + j] = (byte) (k >>> (24 - (j * 8)));
            }
        }
        BigInteger x = new BigInteger(1, tmpBytes).mod(q);
        return x;
    }

    /**
     * Generate the public key component y of the key pair.
     *
     * @param x the private key component.
     *
     * @param p the base parameter.
     */
    BigInteger generateY(BigInteger x, BigInteger p, BigInteger g) {
        BigInteger y = g.modPow(x, p);
        return y;
    }

    /**
     * Set the parameters.
     */
    private void setParams(DSAParams params) {
        presetP = params.getP();
        presetQ = params.getQ();
        presetG = params.getG();
    }

    /**
     * Set the parameters.
     */
    private void setParams(DSAParameterSpec params) {
        presetP = params.getP();
        presetQ = params.getQ();
        presetG = params.getG();
    }
}
