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

import java.security.Provider;

/**
 * The SUN Security Provider.
 *
 * @author Benjamin Renaud 
 *
 * @version 1.24, 97/12/10
 */

/**
 * Defines the SUN provider.
 * 
 * Algorithm supported, and their names:
 * 
 * - SHA-1 is the message digest scheme decribed FIPS 180-1. Aliases for SHA-1
 * are SHA.
 * 
 * - DSA is the signature scheme described in FIPS 186. (SHA used in DSA is
 * SHA-1: FIPS 186 with Change No 1.) Aliases for DSA are SHA/DSA, SHA-1/DSA,
 * SHA1/DSA, DSS and the object identifier strings "OID.1.3.14.3.2.13",
 * "OID.1.3.14.3.2.27" and "OID.1.2.840.10040.4.3".
 * 
 * - DSA is the key generation scheme as described in FIPS 186. Aliases for DSA
 * include the OID strings "OID.1.3.14.3.2.12" and "OID.1.2.840.10040.4.1".
 * 
 * - MD5 is the message digest scheme described in RFC 1321. There are no
 * aliases for MD5.
 * 
 * Notes: The name of algorithm described in FIPS-180 is SHA-0, and is not
 * supported by the SUN provider.)
 */
public final class Sun extends Provider {

    /**
     *
     */
    private static final long serialVersionUID = 9134942296334703727L;
    private static String info = "SUN Security Provider v1.0, "
            + "DSA signing and key generation, SHA-1 and MD5 message digests.";

    public Sun() {
        /* We are the SUN provider */
        super("SUN", 1.0, info);

        try {

            // AccessController.beginPrivileged();

            /*
             * Signature engines
             */
            put("Signature.DSA", "netscape.security.provider.DSA");

            put("Alg.Alias.Signature.SHA/DSA", "DSA");
            put("Alg.Alias.Signature.SHA1/DSA", "DSA");
            put("Alg.Alias.Signature.SHA-1/DSA", "DSA");
            put("Alg.Alias.Signature.DSS", "DSA");
            put("Alg.Alias.Signature.OID.1.3.14.3.2.13", "DSA");
            put("Alg.Alias.Signature.OID.1.3.14.3.2.27", "DSA");
            put("Alg.Alias.Signature.OID.1.2.840.10040.4.3", "DSA");
            // the following are not according to our formal spec but
            // are still supported
            put("Alg.Alias.Signature.1.3.14.3.2.13", "DSA");
            put("Alg.Alias.Signature.1.3.14.3.2.27", "DSA");
            put("Alg.Alias.Signature.1.2.840.10040.4.3", "DSA");
            put("Alg.Alias.Signature.SHAwithDSA", "DSA");
            put("Alg.Alias.Signature.SHA1withDSA", "DSA");

            /*
             * Key Pair Generator engines
             */
            put("KeyPairGenerator.DSA",
                    "netscape.security.provider.DSAKeyPairGenerator");

            put("Alg.Alias.KeyPairGenerator.OID.1.3.14.3.2.12", "DSA");
            put("Alg.Alias.KeyPairGenerator.OID.1.2.840.10040.4.1", "DSA");
            // the following are not according to our formal spec but
            // are still supported
            put("Alg.Alias.KeyPairGenerator.1.3.14.3.2.12", "DSA");
            put("Alg.Alias.KeyPairGenerator.1.2.840.10040.4.1", "DSA");

            /*
             * Digest engines
             */
            put("MessageDigest.MD5", "netscape.security.provider.MD5");
            put("MessageDigest.SHA-1", "netscape.security.provider.SHA");

            put("Alg.Alias.MessageDigest.SHA", "SHA-1");
            put("Alg.Alias.MessageDigest.SHA1", "SHA-1");

            /*
             * Algorithm Parameter Generator engines
             */
            put("AlgorithmParameterGenerator.DSA",
                    "netscape.security.provider.DSAParameterGenerator");

            /*
             * Algorithm Parameter engines
             */
            put("AlgorithmParameters.DSA",
                    "netscape.security.provider.DSAParameters");
            put("Alg.Alias.AlgorithmParameters.1.3.14.3.2.12", "DSA");
            put("Alg.Alias.AlgorithmParameters.1.2.840.10040.4.1", "DSA");
            /*
             * Key factories
             */
            put("KeyFactory.DSA", "netscape.security.provider.DSAKeyFactory");

        } finally {
            // AccessController.endPrivileged();
        }
    }
}
