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
import java.security.InvalidKeyException;

import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.X509Key;

/**
 * An X.509 public key for the RSA Algorithm.
 *
 * @author galperin
 *
 * @version $Revision$, $Date$
 *
 */

public final class RSAPublicKey extends X509Key implements Serializable {

    /* XXX This currently understands only PKCS#1 RSA Encryption OID
       and parameter format
       Later we may consider adding X509v3 OID for RSA keys. Besides
       different OID it also has a parameter equal to modulus size
       in bits (redundant!)
       */

    /**
     *
     */
    private static final long serialVersionUID = 7764823589128565374L;

    private static final ObjectIdentifier ALGORITHM_OID =
            AlgorithmId.RSAEncryption_oid;

    private BigInt modulus;
    private BigInt publicExponent;

    /*
     * Keep this constructor for backwards compatibility with JDK1.1.
     */
    public RSAPublicKey() {
    }

    /**
     * Make a RSA public key out of a public exponent and modulus
     */
    public RSAPublicKey(BigInt modulus, BigInt publicExponent)
            throws InvalidKeyException {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.algid = new AlgorithmId(ALGORITHM_OID);

        try (DerOutputStream out = new DerOutputStream()) {
            out.putInteger(modulus);
            out.putInteger(publicExponent);
            key = (new DerValue(DerValue.tag_Sequence,
                            out.toByteArray())).toByteArray();
            encode();
        } catch (IOException ex) {
            throw new InvalidKeyException("could not DER encode : " +
                                      ex.getMessage());
        }
    }

    /**
     * Make a RSA public key from its DER encoding (X.509).
     */
    public RSAPublicKey(byte[] encoded) throws InvalidKeyException {
        decode(encoded);
    }

    /**
     * Get key size as number of bits in modulus
     * (Always rounded up to a multiple of 8)
     *
     */
    public int getKeySize() {
        return this.modulus.byteLength() * 8;
    }

    /**
     * Get the raw public exponent
     *
     */
    public BigInt getPublicExponent() {
        return this.publicExponent;
    }

    /**
     * Get the raw modulus
     *
     */
    public BigInt getModulus() {
        return this.modulus;
    }

    public String toString() {
        return "RSA Public Key\n  Algorithm: " + algid
                + "\n  modulus:\n" + this.modulus.toString() + "\n"
                + "\n  publicExponent:\n" + this.publicExponent.toString()
                + "\n";
    }

    protected void parseKeyBits() throws InvalidKeyException {
        if (!this.algid.getOID().equals(ALGORITHM_OID) &&
                !this.algid.getOID().equals(AlgorithmId.RSA_oid)) {
            throw new InvalidKeyException("Key algorithm OID is not RSA");
        }

        try {
            DerValue val = new DerValue(key);
            if (val.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Invalid RSA public key format:" +
                                            " must be a SEQUENCE");
            }

            DerInputStream in = val.data;

            this.modulus = in.getInteger();
            this.publicExponent = in.getInteger();
        } catch (IOException e) {
            throw new InvalidKeyException("Invalid RSA public key: " +
                                        e.getMessage());
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((modulus == null) ? 0 : modulus.hashCode());
        result = prime * result + ((publicExponent == null) ? 0 : publicExponent.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        RSAPublicKey other = (RSAPublicKey) obj;
        if (modulus == null) {
            if (other.modulus != null)
                return false;
        } else if (!modulus.equals(other.modulus))
            return false;
        if (publicExponent == null) {
            if (other.publicExponent != null)
                return false;
        } else if (!publicExponent.equals(other.publicExponent))
            return false;
        return true;
    }

    public boolean bigIntEquals(BigInt x, BigInt y) {
        if (x == null) {
            if (y != null) {
                return false;
            }
        } else {
            if (!x.equals(y)) {
                return false;
            }
        }
        return true;
    }
}
