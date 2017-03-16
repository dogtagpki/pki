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
package com.netscape.certsrv.security;

import java.security.PublicKey;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.SymmetricKey.Type;

import com.netscape.certsrv.base.EBaseException;

/**
 * An interface represents the transport key pair.
 * This key pair is used to protected EE's private
 * key in transit.
 *
 * @version $Revision$, $Date$
 */
public interface ITransportKeyUnit extends IEncryptionUnit {

    /**
     * Retrieves public key.
     *
     * @return certificate
     */
    public org.mozilla.jss.crypto.X509Certificate getCertificate();

    /**
     * Retrieves new transport certificate.
     *
     * @return certificate
     */
    public org.mozilla.jss.crypto.X509Certificate getNewCertificate();

    /**
     * Verifies transport certificate.
     *
     * @return certificate
     */
    public org.mozilla.jss.crypto.X509Certificate verifyCertificate(String transportCert);

    /**
     * Retrieves private key associated with certificate
     *
     * @return certificate
     */
    public PrivateKey getPrivateKey(org.mozilla.jss.crypto.X509Certificate cert);

    /**
     * Returns this Unit's crypto token object.
     * @return CryptoToken object.
     */

    public CryptoToken getToken();

    /**
     * Returns this Unit's signing algorithm in String format.
     * @return String of signing algorithm
     * @throws EBaseException
     */

    public String getSigningAlgorithm() throws EBaseException;

    /**
     * Sets this Unit's signing algorithm.
     * @param str String of signing algorithm to set.
     * @throws EBaseException
     */
    public void setSigningAlgorithm(String str) throws EBaseException;

    /**
     * Decrypts the external private key (private key from the end-user).
     *
     * @param sessionKey session key that protects the user private
     * @param symmAlgOID symmetric algorithm
     * @param symmAlgParams symmetric algorithm parameters
     * @param privateKey private key data
     * @param transportCert transport certificate
     * @return private key data
     * @throws Exception
     */
    public byte[] decryptExternalPrivate(byte sessionKey[],
            String symmAlgOID, byte symmAlgParams[], byte privateKey[],
            org.mozilla.jss.crypto.X509Certificate transportCert)
            throws Exception;

    /**
     * Unwraps symmetric key . This method
     * unwraps the symmetric key.
     *
     * @param sessionKey session key that unwrap the symmetric key
     * @param symmAlgOID symmetric algorithm
     * @param symmAlgParams symmetric algorithm parameters
     * @param symmetricKey  symmetric key data
     * @param type symmetric key algorithm
     * @param strength symmetric key strength in bytes
     * @return Symmetric key object
     * @throws Exception
     */

    public SymmetricKey unwrap_symmetric(byte sessionKey[], String symmAlgOID,
            byte symmAlgParams[], byte symmetricKey[], Type type, int strength)
            throws Exception;

    /**
     * Unwraps data. This method rebuilds the private key by
     * unwrapping the private key data.
     *
     * @param symmAlgOID symmetric algorithm
     * @param symmAlgParams symmetric algorithm parameters
     * @param pubKey public key
     * @param transportCert transport certificate
     * @return private key object
     * @throws Exception
     */
    public PrivateKey unwrap(byte encSymmKey[], String symmAlgOID,
            byte symmAlgParams[], byte encValue[], PublicKey pubKey,
            org.mozilla.jss.crypto.X509Certificate transportCert)
            throws Exception;

    /**
     * Unwraps symmetric key . This method
     * unwraps the symmetric key.
     *
     * @param encSymmKey wrapped symmetric key to be unwrapped
     * @return Symmetric key object
     * @throws Exception
     */

    public SymmetricKey unwrap_sym(byte encSymmKey[], WrappingParams params) throws Exception;


}
