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

import java.util.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import netscape.security.x509.AlgorithmId;
import netscape.security.util.BigInt;

import netscape.security.x509.X509Key;
import netscape.security.util.ObjectIdentifier;
import netscape.security.util.DerValue;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;

/**
 * An X.509 public key for the RSA Algorithm.
 *
 * @author galperin
 *
 * @version $Revision: 14564 $, $Date: 2007-05-01 10:40:13 -0700 (Tue, 01 May 2007) $
 *
 */

public final class RSAPublicKey extends X509Key implements Serializable {

	/* XXX This currently understands only PKCS#1 RSA Encryption OID
	   and parameter format
	   Later we may consider adding X509v3 OID for RSA keys. Besides 
	   different OID it also has a parameter equal to modulus size 
	   in bits (redundant!)
	   */

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

	try {
		DerOutputStream	out = new DerOutputStream ();
		
		out.putInteger (modulus);
		out.putInteger (publicExponent);
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
		  DerValue val = new DerValue (key);
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
	
}
