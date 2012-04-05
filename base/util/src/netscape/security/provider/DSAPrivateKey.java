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
import java.io.Serializable;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.interfaces.DSAParams;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import netscape.security.pkcs.PKCS8Key;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerValue;
import netscape.security.x509.AlgIdDSA;

/**
 * A PKCS#8 private key for the Digital Signature Algorithm.
 *
 * @author Benjamin Renaud
 *
 * @version 1.47, 97/12/10
 *
 * @see DSAPublicKey
 * @see AlgIdDSA
 * @see DSA
 */

public final class DSAPrivateKey extends PKCS8Key
        implements java.security.interfaces.DSAPrivateKey, Serializable {

    /** use serialVersionUID from JDK 1.1. for interoperability */
    private static final long serialVersionUID = -3244453684193605938L;

    /* the private key */
    private BigInteger x;

    /*
     * Keep this constructor for backwards compatibility with JDK1.1.
     */
    public DSAPrivateKey() {
    }

    /**
     * Make a DSA private key out of a private key and three parameters.
     */
    public DSAPrivateKey(BigInteger x, BigInteger p,
             BigInteger q, BigInteger g)
            throws InvalidKeyException {
        this.x = x;
        algid = new AlgIdDSA(p, q, g);

        try {
            key = new DerValue(DerValue.tag_Integer,
                    x.toByteArray()).toByteArray();
            encode();
        } catch (IOException e) {
            throw new InvalidKeyException("could not DER encode x: " +
                      e.getMessage());
        }
    }

    /**
     * Make a DSA private key from its DER encoding (PKCS #8).
     */
    public DSAPrivateKey(byte[] encoded) throws InvalidKeyException {
        clearOldKey();
        decode(encoded);
    }

    /**
     * Returns the DSA parameters associated with this key, or null if the
     * parameters could not be parsed.
     */
    public DSAParams getParams() {
        try {
            if (algid instanceof DSAParams) {
                return (DSAParams) algid;
            } else {
                DSAParameterSpec paramSpec;
                AlgorithmParameters algParams = algid.getParameters();
                if (algParams == null) {
                    return null;
                }
                paramSpec = (DSAParameterSpec) algParams.getParameterSpec
                        (DSAParameterSpec.class);
                return (DSAParams) paramSpec;
            }
        } catch (InvalidParameterSpecException e) {
            return null;
        }
    }

    /**
     * Get the raw private key, x, without the parameters.
     *
     */
    public BigInteger getX() {
        return x;
    }

    private void clearOldKey() {
        int i;
        if (this.encodedKey != null) {
            for (i = 0; i < this.encodedKey.length; i++) {
                this.encodedKey[i] = (byte) 0x00;
            }
        }
        if (this.key != null) {
            for (i = 0; i < this.key.length; i++) {
                this.key[i] = (byte) 0x00;
            }
        }
    }

    public String toString() {
        return "Sun DSA Private Key \nparameters:" + algid + "\nx: " +
                x.toString(16) + "\n";
    }

    protected void parseKeyBits() throws InvalidKeyException {
        DerInputStream in = new DerInputStream(key);

        try {
            x = in.getInteger().toBigInteger();
        } catch (IOException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }
}
