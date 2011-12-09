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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * This class implements the DSA key factory of the Sun provider.
 *
 * @author Jan Luehe
 *
 * @version 1.8, 97/12/10
 *
 * @since JDK1.2
 */

public class DSAKeyFactory extends KeyFactorySpi {

    /**
     * Generates a public key object from the provided key specification
     * (key material).
     *
     * @param keySpec the specification (key material) of the public key
     *
     * @return the public key
     *
     * @exception InvalidKeySpecException if the given key specification
     * is inappropriate for this key factory to produce a public key.
     */
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
    throws InvalidKeySpecException {
	try {
	    if (keySpec instanceof DSAPublicKeySpec) {
		DSAPublicKeySpec dsaPubKeySpec = (DSAPublicKeySpec)keySpec;
		return new DSAPublicKey(dsaPubKeySpec.getY(),
					dsaPubKeySpec.getP(),
					dsaPubKeySpec.getQ(),
					dsaPubKeySpec.getG());

	    } else if (keySpec instanceof X509EncodedKeySpec) {
		return new DSAPublicKey
		    (((X509EncodedKeySpec)keySpec).getEncoded());

	    } else {
		throw new InvalidKeySpecException
		    ("Inappropriate key specification");
	    }
	} catch (InvalidKeyException e) {
	    throw new InvalidKeySpecException
		("Inappropriate key specification: " + e.getMessage());
	}
    }

    /**
     * Generates a private key object from the provided key specification
     * (key material).
     *
     * @param keySpec the specification (key material) of the private key
     *
     * @return the private key
     *
     * @exception InvalidKeySpecException if the given key specification
     * is inappropriate for this key factory to produce a private key.
     */
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
    throws InvalidKeySpecException {
	try {
	    if (keySpec instanceof DSAPrivateKeySpec) {
		DSAPrivateKeySpec dsaPrivKeySpec = (DSAPrivateKeySpec)keySpec;
		return new DSAPrivateKey(dsaPrivKeySpec.getX(),
					 dsaPrivKeySpec.getP(),
					 dsaPrivKeySpec.getQ(),
					 dsaPrivKeySpec.getG());

	    } else if (keySpec instanceof PKCS8EncodedKeySpec) {
		return new DSAPrivateKey
		    (((PKCS8EncodedKeySpec)keySpec).getEncoded());

	    } else {
		throw new InvalidKeySpecException
		    ("Inappropriate key specification");
	    }
	} catch (InvalidKeyException e) {
	    throw new InvalidKeySpecException
		("Inappropriate key specification: " + e.getMessage());
	}
    }

    /**
     * Returns a specification (key material) of the given key object
     * in the requested format.
     *
     * @param key the key 
     *
     * @param keySpec the requested format in which the key material shall be
     * returned
     *
     * @return the underlying key specification (key material) in the
     * requested format
     *
     * @exception InvalidKeySpecException if the requested key specification is
     * inappropriate for the given key, or the given key cannot be processed
     * (e.g., the given key has an unrecognized algorithm or format).
     */
    protected KeySpec engineGetKeySpec(Key key, Class keySpec)
    throws InvalidKeySpecException {
	
	DSAParams params;

	try {

	    if (key instanceof java.security.interfaces.DSAPublicKey) {
		
		// Determine valid key specs
		Class dsaPubKeySpec = Class.forName
		    ("java.security.spec.DSAPublicKeySpec");
		Class x509KeySpec = Class.forName
		    ("java.security.spec.X509EncodedKeySpec");

		if (dsaPubKeySpec.isAssignableFrom(keySpec)) {
		    java.security.interfaces.DSAPublicKey dsaPubKey
			= (java.security.interfaces.DSAPublicKey)key;
		    params = dsaPubKey.getParams();
		    return new DSAPublicKeySpec(dsaPubKey.getY(),
						params.getP(),
						params.getQ(),
						params.getG());

		} else if (x509KeySpec.isAssignableFrom(keySpec)) {
		    return new X509EncodedKeySpec(key.getEncoded());

		} else {
		    throw new InvalidKeySpecException
			("Inappropriate key specification");
		}
		 
	    } else if (key instanceof java.security.interfaces.DSAPrivateKey) {

		// Determine valid key specs
		Class dsaPrivKeySpec = Class.forName
		    ("java.security.spec.DSAPrivateKeySpec");
		Class pkcs8KeySpec = Class.forName
		    ("java.security.spec.PKCS8EncodedKeySpec");

		if (dsaPrivKeySpec.isAssignableFrom(keySpec)) {
		    java.security.interfaces.DSAPrivateKey dsaPrivKey
			= (java.security.interfaces.DSAPrivateKey)key;
		    params = dsaPrivKey.getParams();
		    return new DSAPrivateKeySpec(dsaPrivKey.getX(),
						 params.getP(),
						 params.getQ(),
						 params.getG());

		} else if (pkcs8KeySpec.isAssignableFrom(keySpec)) {
		    return new PKCS8EncodedKeySpec(key.getEncoded());

		} else {
		    throw new InvalidKeySpecException
			("Inappropriate key specification");
		}

	    } else {
		throw new InvalidKeySpecException("Inappropriate key type");
	    }

	} catch (ClassNotFoundException e) {
	    throw new InvalidKeySpecException
		("Unsupported key specification: " + e.getMessage());
	}
    }

    /**
     * Translates a key object, whose provider may be unknown or potentially
     * untrusted, into a corresponding key object of this key factory.
     *
     * @param key the key whose provider is unknown or untrusted
     *
     * @return the translated key
     *
     * @exception InvalidKeyException if the given key cannot be processed by
     * this key factory.
     */
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

	try {

	    if (key instanceof java.security.interfaces.DSAPublicKey) {
		// Check if key originates from this factory
		if (key instanceof netscape.security.provider.DSAPublicKey) {
		    return key;
		}
		// Convert key to spec
		DSAPublicKeySpec dsaPubKeySpec
		    = (DSAPublicKeySpec)engineGetKeySpec
		    (key, DSAPublicKeySpec.class);
		// Create key from spec, and return it
		return engineGeneratePublic(dsaPubKeySpec);

	    } else if (key instanceof java.security.interfaces.DSAPrivateKey) {
		// Check if key originates from this factory
		if (key instanceof netscape.security.provider.DSAPrivateKey) {
		    return key;
		}
		// Convert key to spec
		DSAPrivateKeySpec dsaPrivKeySpec
		    = (DSAPrivateKeySpec)engineGetKeySpec
		    (key, DSAPrivateKeySpec.class);
		// Create key from spec, and return it
		return engineGeneratePrivate(dsaPrivKeySpec);

	    } else {
		throw new InvalidKeyException("Wrong algorithm type");
	    }

	} catch (InvalidKeySpecException e) {
	    throw new InvalidKeyException("Cannot translate key: "
                                          + e.getMessage());
	}
    }
}
