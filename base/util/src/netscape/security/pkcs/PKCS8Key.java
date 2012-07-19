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
package netscape.security.pkcs;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import netscape.security.util.BigInt;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.x509.AlgorithmId;

/**
 * Holds a PKCS#8 key, for example a private key
 *
 * @version 1.30, 97/12/10
 * @author Dave Brownell
 * @author Benjamin Renaud
 */
public class PKCS8Key implements PrivateKey {

    /** use serialVersionUID from JDK 1.1. for interoperability */
    private static final long serialVersionUID = -3836890099307167124L;

    /* The algorithm information (name, parameters, etc). */
    protected AlgorithmId algid;

    /* The key bytes, without the algorithm information */
    protected byte[] key;

    /* The encoded for the key. */
    protected byte[] encodedKey;

    /* The version for this key */
    public static final BigInteger VERSION = BigInteger.valueOf(0);

    /**
     * Default constructor. The key constructed must have its key
     * and algorithm initialized before it may be used, for example
     * by using <code>decode</code>.
     */
    public PKCS8Key() {
    }

    /**
     * Construct PKCS#8 subject public key from a DER value. If
     * the runtime environment is configured with a specific class for
     * this kind of key, a subclass is returned. Otherwise, a generic
     * PKCS8Key object is returned.
     *
     * <P>
     * This mechanism gurantees that keys (and algorithms) may be freely manipulated and transferred, without risk of
     * losing information. Also, when a key (or algorithm) needs some special handling, that specific need can be
     * accomodated.
     *
     * @param in the DER-encoded SubjectPublicKeyInfo value
     * @exception IOException on data format errors
     */
    public static PKCS8Key parse(DerValue in) throws IOException {
        AlgorithmId algorithm;
        PKCS8Key subjectKey;

        if (in.tag != DerValue.tag_Sequence)
            throw new IOException("corrupt private key");

        BigInteger parsedVersion = in.data.getInteger().toBigInteger();
        if (!VERSION.equals(parsedVersion)) {
            throw new IOException("version mismatch: (supported: " +
                    VERSION + ", parsed: " +
                    parsedVersion);
        }

        algorithm = AlgorithmId.parse(in.data.getDerValue());

        try {
            subjectKey = buildPKCS8Key(algorithm, in.data.getOctetString());

        } catch (InvalidKeyException e) {
            throw new IOException("corrupt private key");
        }

        if (in.data.available() != 0)
            throw new IOException("excess private key");
        return subjectKey;
    }

    /**
     * Parse the key bits. This may be redefined by subclasses to take
     * advantage of structure within the key. For example, RSA public
     * keys encapsulate two unsigned integers (modulus and exponent) as
     * DER values within the <code>key</code> bits; Diffie-Hellman and
     * DSS/DSA keys encapsulate a single unsigned integer.
     *
     * <P>
     * This function is called when creating PKCS#8 SubjectPublicKeyInfo values using the PKCS8Key member functions,
     * such as <code>parse</code> and <code>decode</code>.
     *
     * @exception IOException if a parsing error occurs.
     * @exception InvalidKeyException if the key encoding is invalid.
     */
    protected void parseKeyBits() throws IOException, InvalidKeyException {
        encode();
    }

    /*
     * Factory interface, building the kind of key associated with this
     * specific algorithm ID or else returning this generic base class.
     * See the description above.
     */
    public static PKCS8Key buildPKCS8Key(AlgorithmId algid, byte[] key)
            throws IOException, InvalidKeyException {
        /*
         * Use the algid and key parameters to produce the ASN.1 encoding
         * of the key, which will then be used as the input to the
         * key factory.
         */
        DerOutputStream pkcs8EncodedKeyStream = new DerOutputStream();
        encode(pkcs8EncodedKeyStream, algid, key);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pkcs8EncodedKeyStream.toByteArray());

        try {
            // Instantiate the key factory of the appropriate algorithm
            KeyFactory keyFac = KeyFactory.getInstance(algid.getName());

            // Generate the private key
            PrivateKey privKey = keyFac.generatePrivate(pkcs8KeySpec);

            if (privKey instanceof PKCS8Key) {
                /*
                 * Return specialized PKCS8Key, where the structure within the
                 * key has been parsed
                 */
                return (PKCS8Key) privKey;
            }
        } catch (NoSuchAlgorithmException e) {
            // Return generic PKCS8Key with opaque key data (see below)
        } catch (InvalidKeySpecException e) {
            // Return generic PKCS8Key with opaque key data (see below)
        }

        /*
         * Try again using JDK1.1-style for backwards compatibility.
         */
        String classname = "";
        try {
            Provider sunProvider;

            sunProvider = Security.getProvider("SUN");
            if (sunProvider == null)
                throw new InstantiationException();
            classname = sunProvider.getProperty("PrivateKey.PKCS#8." +
                    algid.getName());
            if (classname == null) {
                throw new InstantiationException();
            }

            Class<?> keyClass = Class.forName(classname);
            Object inst;
            PKCS8Key result;

            inst = keyClass.newInstance();
            if (inst instanceof PKCS8Key) {
                result = (PKCS8Key) inst;
                result.algid = algid;
                result.key = key;
                result.parseKeyBits();
                return result;
            }
        } catch (ClassNotFoundException e) {
        } catch (InstantiationException e) {
        } catch (IllegalAccessException e) {
            // this should not happen.
            throw new IOException(classname + " [internal error]");
        }

        PKCS8Key result = new PKCS8Key();
        result.algid = algid;
        result.key = key;
        return result;
    }

    /**
     * Returns the algorithm to be used with this key.
     */
    public String getAlgorithm() {
        return algid.getName();
    }

    /**
     * Returns the algorithm ID to be used with this key.
     */
    public AlgorithmId getAlgorithmId() {
        return algid;
    }

    /**
     * PKCS#8 sequence on the DER output stream.
     */
    public final void encode(DerOutputStream out) throws IOException {
        encode(out, this.algid, this.key);
    }

    /**
     * Returns the DER-encoded form of the key as a byte array.
     */
    public synchronized byte[] getEncoded() {
        byte[] result = null;
        try {
            result = encode();
        } catch (InvalidKeyException e) {
        }
        return result;
    }

    /**
     * Returns the format for this key: "PKCS#8"
     */
    public String getFormat() {
        return "PKCS#8";
    }

    /**
     * Returns the DER-encoded form of the key as a byte array.
     *
     * @exception InvalidKeyException if an encoding error occurs.
     */
    public byte[] encode() throws InvalidKeyException {
        if (encodedKey == null) {
            try {
                DerOutputStream out;

                out = new DerOutputStream();
                encode(out);
                encodedKey = out.toByteArray();

            } catch (IOException e) {
                throw new InvalidKeyException("IOException : " +
                           e.getMessage());
            }
        }
        return copyEncodedKey(encodedKey);
    }

    /*
     * Returns a printable representation of the key
     */
    public String toString() {
        netscape.security.util.PrettyPrintFormat pp =
                new netscape.security.util.PrettyPrintFormat(" ", 20);
        String keybits = pp.toHexString(key);

        return "algorithm = " + algid.toString()
                + ", unparsed keybits = \n" + keybits;
    }

    /**
     * Initialize an PKCS8Key object from an input stream. The data
     * on that input stream must be encoded using DER, obeying the
     * PKCS#8 format: a sequence consisting of a version, an algorithm
     * ID and a bit string which holds the key. (That bit string is
     * often used to encapsulate another DER encoded sequence.)
     *
     * <P>
     * Subclasses should not normally redefine this method; they should instead provide a <code>parseKeyBits</code>
     * method to parse any fields inside the <code>key</code> member.
     *
     * @param in an input stream with a DER-encoded PKCS#8
     *            SubjectPublicKeyInfo value
     *
     * @exception InvalidKeyException if a parsing error occurs.
     */
    public void decode(InputStream in) throws InvalidKeyException {
        DerValue val;

        try {
            val = new DerValue(in);
            if (val.tag != DerValue.tag_Sequence)
                throw new InvalidKeyException("invalid key format");

            BigInteger version = val.data.getInteger().toBigInteger();
            if (!version.equals(PKCS8Key.VERSION)) {
                throw new IOException("version mismatch: (supported: " +
                        PKCS8Key.VERSION + ", parsed: " +
                        version);
            }
            algid = AlgorithmId.parse(val.data.getDerValue());
            key = val.data.getOctetString();
            parseKeyBits();
            if (val.data.available() != 0)
                throw new InvalidKeyException("excess key data");

        } catch (IOException e) {
            // e.printStackTrace ();
            throw new InvalidKeyException("IOException : " +
                      e.getMessage());
        }
    }

    public void decode(byte[] encodedKey) throws InvalidKeyException {
        decode(new ByteArrayInputStream(encodedKey));
    }

    /**
     * Serialization write ... PKCS#8 keys serialize as
     * themselves, and they're parsed when they get read back.
     */
    private void writeObject(java.io.ObjectOutputStream stream) throws IOException {
        stream.write(getEncoded());
    }

    /**
     * Serialization read ... PKCS#8 keys serialize as
     * themselves, and they're parsed when they get read back.
     */
    private void readObject(ObjectInputStream stream) throws IOException {
        try {
            decode(stream);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new IOException("deserialized key is invalid: " +
                    e.getMessage());
        }
    }

    /*
     * Make a copy of the encoded key.
     */
    private byte[] copyEncodedKey(byte[] encodedKey) {
        int len = encodedKey.length;
        byte[] copy = new byte[len];
        System.arraycopy(encodedKey, 0, copy, 0, len);
        return copy;
    }

    /*
     * Produce PKCS#8 encoding from algorithm id and key material.
     */
    static void encode(DerOutputStream out, AlgorithmId algid, byte[] key)
            throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        tmp.putInteger(new BigInt(VERSION.toByteArray()));
        algid.encode(tmp);
        tmp.putOctetString(key);
        out.write(DerValue.tag_Sequence, tmp);
    }

    /**
     * Compares two private keys. This returns false if the object with which
     * to compare is not of type <code>Key</code>.
     * Otherwise, the encoding of this key object is compared with the
     * encoding of the given key object.
     *
     * @param object the object with which to compare
     * @return <code>true</code> if this key has the same encoding as the
     *         object argument; <code>false</code> otherwise.
     */
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }

        if (object instanceof Key) {

            // this encoding
            byte[] b1;
            if (encodedKey != null) {
                b1 = encodedKey;
            } else {
                b1 = getEncoded();
            }

            // that encoding
            byte[] b2 = ((Key) object).getEncoded();

            // do the comparison
            int i;
            if (b1.length != b2.length)
                return false;
            for (i = 0; i < b1.length; i++) {
                if (b1[i] != b2[i]) {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    /**
     * Calculates a hash code value for this object. Objects
     * which are equal will also have the same hashcode.
     */
    public int hashCode() {
        int retval = 0;
        byte[] b1 = getEncoded();

        for (int i = 1; i < b1.length; i++) {
            retval += b1[i] * i;
        }
        return (retval);
    }
}
