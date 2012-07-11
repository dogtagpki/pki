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
package netscape.security.x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * Holds an X.509 key, for example a public key found in an X.509
 * certificate. Includes a description of the algorithm to be used
 * with the key; these keys normally are used as
 * "SubjectPublicKeyInfo".
 *
 * <P>
 * While this class can represent any kind of X.509 key, it may be desirable to provide subclasses which understand how
 * to parse keying data. For example, RSA public keys have two members, one for the public modulus and one for the prime
 * exponent. If such a class is provided, it is used when parsing X.509 keys. If one is not provided, the key still
 * parses correctly.
 *
 * @version 1.74, 97/12/10
 * @author David Brownell
 */
public class X509Key implements PublicKey {

    /** use serialVersionUID from JDK 1.1. for interoperability */
    private static final long serialVersionUID = -5359250853002055002L;

    /* The algorithm information (name, parameters, etc). */
    protected AlgorithmId algid;

    /* The key bytes, without the algorithm information */
    protected byte[] key;

    /* The encoding for the key. */
    protected byte[] encodedKey;

    /**
     * Default constructor. The key constructed must have its key
     * and algorithm initialized before it may be used, for example
     * by using <code>decode</code>.
     */
    public X509Key() {
    }

    /*
     * Build and initialize as a "default" key.  All X.509 key
     * data is stored and transmitted losslessly, but no knowledge
     * about this particular algorithm is available.
     */
    public X509Key(AlgorithmId algid, byte[] key)
            throws InvalidKeyException {
        this.algid = algid;
        this.key = key;
        encode();
    }

    /**
     * Construct X.509 subject public key from a DER value. If
     * the runtime environment is configured with a specific class for
     * this kind of key, a subclass is returned. Otherwise, a generic
     * X509Key object is returned.
     *
     * <P>
     * This mechanism gurantees that keys (and algorithms) may be freely manipulated and transferred, without risk of
     * losing information. Also, when a key (or algorithm) needs some special handling, that specific need can be
     * accomodated.
     *
     * @param in the DER-encoded SubjectPublicKeyInfo value
     * @exception IOException on data format errors
     */
    public static X509Key parse(DerValue in) throws IOException {
        AlgorithmId algorithm;
        X509Key subjectKey;

        if (in.tag != DerValue.tag_Sequence)
            throw new IOException("corrupt subject key");

        algorithm = AlgorithmId.parse(in.data.getDerValue());
        try {
            subjectKey = buildX509Key(algorithm, in.data.getBitString());

        } catch (InvalidKeyException e) {
            throw new IOException("subject key, " + e.getMessage());
        }

        if (in.data.available() != 0)
            throw new IOException("excess subject key");
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
     * This function is called when creating X.509 SubjectPublicKeyInfo values using the X509Key member functions, such
     * as <code>parse</code> and <code>decode</code>.
     *
     * @exception IOException on parsing errors.
     * @exception InvalidKeyException on invalid key encodings.
     */
    protected void parseKeyBits() throws IOException, InvalidKeyException {
        encode();
    }

    /*
     * Factory interface, building the kind of key associated with this
     * specific algorithm ID or else returning this generic base class.
     * See the description above.
     */
    static X509Key buildX509Key(AlgorithmId algid, byte[] key)
            throws IOException, InvalidKeyException {
        /*
         * Use the algid and key parameters to produce the ASN.1 encoding
         * of the key, which will then be used as the input to the
         * key factory.
         */
        DerOutputStream x509EncodedKeyStream = new DerOutputStream();
        encode(x509EncodedKeyStream, algid, key);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(x509EncodedKeyStream.toByteArray());

        try {
            // Instantiate the key factory of the appropriate algorithm
            KeyFactory keyFac = null;
            if (Security.getProvider("Mozilla-JSS") == null) {
                keyFac = KeyFactory.getInstance(algid.getName());
            } else {
                keyFac = KeyFactory.getInstance(algid.getName(),
                        "Mozilla-JSS");
            }

            // Generate the public key
            PublicKey pubKey = keyFac.generatePublic(x509KeySpec);

            if (pubKey instanceof X509Key) {
                /*
                 * Return specialized X509Key, where the structure within the
                 * key has been parsed
                 */
                return (X509Key) pubKey;
            }
        } catch (NoSuchAlgorithmException e) {
            // Return generic X509Key with opaque key data (see below)
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e.toString());
        } catch (Exception e) {
            throw new InvalidKeyException(e.toString());
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
            classname = sunProvider.getProperty("PublicKey.X.509." +
                    algid.getName());
            if (classname == null) {
                throw new InstantiationException();
            }

            Class<?> keyClass = Class.forName(classname);
            Object inst;
            X509Key result;

            inst = keyClass.newInstance();
            if (inst instanceof X509Key) {
                result = (X509Key) inst;
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

        X509Key result = new X509Key();
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
     * Encode SubjectPublicKeyInfo sequence on the DER output stream.
     *
     * @exception IOException on encoding errors.
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
     * Returns the format for this key: "X.509"
     */
    public String getFormat() {
        return "X.509";
    }

    /**
     * Returns the raw key as a byte array
     */
    public byte[] getKey() {
        return key;
    }

    /**
     * Returns the DER-encoded form of the key as a byte array.
     *
     * @exception InvalidKeyException on encoding errors.
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
     * Initialize an X509Key object from an input stream. The data on that
     * input stream must be encoded using DER, obeying the X.509 <code>SubjectPublicKeyInfo</code> format. That is, the
     * data is a
     * sequence consisting of an algorithm ID and a bit string which holds
     * the key. (That bit string is often used to encapsulate another DER
     * encoded sequence.)
     *
     * <P>
     * Subclasses should not normally redefine this method; they should instead provide a <code>parseKeyBits</code>
     * method to parse any fields inside the <code>key</code> member.
     *
     * <P>
     * The exception to this rule is that since private keys need not be encoded using the X.509
     * <code>SubjectPublicKeyInfo</code> format, private keys may override this method, <code>encode</code>, and of
     * course <code>getFormat</code>.
     *
     * @param in an input stream with a DER-encoded X.509
     *            SubjectPublicKeyInfo value
     * @exception InvalidKeyException on parsing errors.
     */
    public void decode(InputStream in)
            throws InvalidKeyException {
        DerValue val;

        try {
            val = new DerValue(in);
            if (val.tag != DerValue.tag_Sequence)
                throw new InvalidKeyException("invalid key format");

            algid = AlgorithmId.parse(val.data.getDerValue());
            key = val.data.getBitString();
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
     * Serialization write ... X.509 keys serialize as
     * themselves, and they're parsed when they get read back.
     */
    private void writeObject(java.io.ObjectOutputStream stream) throws IOException {
        stream.write(getEncoded());
    }

    /**
     * Serialization read ... X.509 keys serialize as
     * themselves, and they're parsed when they get read back.
     */
    private void readObject(ObjectInputStream stream) throws IOException {
        try {
            decode(stream);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new IOException("deserialized key is invalid: " + e.getMessage());
        }
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }

        if (object instanceof Key) {
            Key key = (Key) object;

            byte[] b1;
            if (encodedKey != null) {
                b1 = encodedKey;
            } else {
                b1 = getEncoded();
            }
            byte[] b2 = key.getEncoded();

            return java.security.MessageDigest.isEqual(b1, b2);
        }

        return false;
    }

    /**
     * Calculates a hash code value for the object. Objects
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
     * Produce SubjectPublicKey encoding from algorithm id and key material.
     */
    static void encode(DerOutputStream out, AlgorithmId algid, byte[] key)
            throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        algid.encode(tmp);
        tmp.putBitString(key);
        out.write(DerValue.tag_Sequence, tmp);
    }

    /*
    *  parsePublicKey returns a PublicKey for use with package JSS from within netscape.security.*.
    *  This function provide an interim solution for migrating from using the netscape.security.* package
     * to using the JSS package.
    */

    public static PublicKey parsePublicKey(DerValue in) throws IOException {
        AlgorithmId algorithm;
        PublicKey subjectKey;

        if (in.tag != DerValue.tag_Sequence)
            throw new IOException("corrupt subject key");

        algorithm = AlgorithmId.parse(in.data.getDerValue());
        try {
            subjectKey = buildPublicKey(algorithm, in.data.getBitString());

        } catch (InvalidKeyException e) {
            throw new IOException("subject key, " + e.getMessage());
        }

        if (in.data.available() != 0)
            throw new IOException("excess subject key");
        return subjectKey;
    }

    /*  buildPublicKey returns a PublicKey for use with  the JSS package  from within netscape.security.*.
     *  This function provide an interim solution for migrating from using the netscape.security.* package
     * to using the JSS package.
     */
    static PublicKey buildPublicKey(AlgorithmId algid, byte[] key)
            throws IOException, InvalidKeyException {
        /*
         * Use the algid and key parameters to produce the ASN.1 encoding
         * of the key, which will then be used as the input to the
         * key factory.
         */
        DerOutputStream x509EncodedKeyStream = new DerOutputStream();
        encode(x509EncodedKeyStream, algid, key);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(x509EncodedKeyStream.toByteArray());

        try {
            // Instantiate the key factory of the appropriate algorithm
            KeyFactory keyFac = null;
            if (Security.getProvider("Mozilla-JSS") == null) {
                keyFac = KeyFactory.getInstance(algid.getName());
            } else {
                keyFac = KeyFactory.getInstance(algid.getName(),
                        "Mozilla-JSS");
            }

            // Generate the public key
            PublicKey pubKey = keyFac.generatePublic(x509KeySpec);

            /*
             * Return specialized X509Key, where the structure within the
             * key has been parsed
             */
            return pubKey;
        } catch (NoSuchAlgorithmException e) {
            // Return generic X509Key with opaque key data (see below)
            throw new InvalidKeyException(e.toString());
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e.toString());
        } catch (Exception e) {
            throw new InvalidKeyException(e.toString());
        }

    }

}
