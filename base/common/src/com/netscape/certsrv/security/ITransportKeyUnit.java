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
     * Unwraps symmetric key . This method
     * unwraps the symmetric key.
     *
     * @param encSymmKey wrapped symmetric key to be unwrapped
     * @param usage Key usage for unwrapped key.
     * @return Symmetric key object
     * @exception EBaseException failed to unwrap
     */

    public SymmetricKey unwrap_sym(byte encSymmKey[], SymmetricKey.Usage usage);

    /**
     * Unwraps symmetric key . This method
     * unwraps the symmetric key.
     *
     * @param encSymmKey wrapped symmetric key to be unwrapped
     * @return Symmetric key object
     * @exception EBaseException failed to unwrap
     */

    public SymmetricKey unwrap_sym(byte encSymmKey[]);

    /**
     * Unwraps symmetric key for encrypton . This method
     * unwraps the symmetric key.
     *
     * @param encSymmKey wrapped symmetric key to be unwrapped
     * @return Symmetric key object
     * @exception EBaseException failed to unwrap
     */

    public SymmetricKey unwrap_encrypt_sym(byte encSymmKey[]);

    /**
     * Unwraps temporary private key . This method
     * unwraps the temporary private key.
     *
     * @param wrappedKeyData wrapped private key to be unwrapped
     * @param pubKey public key
     * @return Private key object
     * @exception EBaseException failed to unwrap
     */

    public PrivateKey unwrap_temp(byte wrappedKeyData[], PublicKey
            pubKey) throws EBaseException;
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
}
