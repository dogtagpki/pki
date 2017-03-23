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
import java.util.Enumeration;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;

import com.netscape.certsrv.base.EBaseException;

import netscape.security.util.WrappingParams;

/**
 * An interface represents a storage key unit. This storage
 * unit contains a storage key pair that is used for
 * encrypting the user private key for long term storage.
 *
 * @version $Revision$, $Date$
 */
public interface IStorageKeyUnit extends IEncryptionUnit {

    /**
     * Retrieves total number of recovery agents.
     *
     * @return total number of recovery agents
     */
    public int getNoOfAgents() throws EBaseException;

    /**
     * Retrieves number of recovery agents required to
     * perform recovery operation.
     *
     * @return required number of recovery agents for recovery operation
     */
    public int getNoOfRequiredAgents() throws EBaseException;

    /**
     * Sets the numer of required recovery agents
     *
     * @param number number of required agents
     */
    public void setNoOfRequiredAgents(int number);

    /**
     * Retrieves a list of agents in this unit.
     *
     * @return a list of string-based agent identifiers
     */
    public Enumeration<String> getAgentIdentifiers();

    /**
     * Changes agent password.
     *
     * @param id agent id
     * @param oldpwd old password
     * @param newpwd new password
     * @return true if operation successful
     * @exception EBaseException failed to change password
     */
    public boolean changeAgentPassword(String id, String oldpwd,
            String newpwd) throws EBaseException;

    /**
     * Changes M-N recovery scheme.
     *
     * @param n total number of agents
     * @param m required number of agents for recovery operation
     * @param oldcreds all old credentials
     * @param newcreds all new credentials
     * @return true if operation successful
     * @exception EBaseException failed to change schema
     */
    public boolean changeAgentMN(int n, int m, Credential oldcreds[],
            Credential newcreds[]) throws EBaseException;

    /**
     * Logins to this unit.
     *
     * @param ac agent's credentials
     * @exception EBaseException failed to login
     */
    public void login(Credential ac[]) throws EBaseException;

    public CryptoToken getToken();

    /**
     * Encrypts the internal private key (private key to the KRA's
     * internal storage).
     *
     * @param rawPrivate user's private key (key to be archived)
     * @return encrypted data
     * @exception EBaseException failed to encrypt
     */
    public byte[] encryptInternalPrivate(byte rawPrivate[]) throws Exception;

    /**
     * Wraps data. The given key will be wrapped by the
     * private key in this unit.
     *
     * @param priKey private key to be wrapped
     * @param WrappingParams - wrapping parameters
     * @return wrapped data
     * @exception EBaseException failed to wrap
     */
    public byte[] wrap(PrivateKey priKey) throws Exception;

    /**
     * Wraps data. The given key will be wrapped by the
     * private key in this unit.
     *
     * @param symKey symmetric key to be wrapped
     * @param wrappingParams - wrapping parameters
     * @return wrapped data
     * @exception EBaseException failed to wrap
     */
    public byte[] wrap(SymmetricKey symKey) throws Exception;

    /**
     * Decrypts the internal private key (private key from the KRA's
     * internal storage).
     *
     * @param wrappedPrivateData unwrapped private key data (key to be recovered)
     * @param params - wrapping params
     * @return raw private key
     * @throws Exception
     */
    public byte[] decryptInternalPrivate(byte wrappedPrivateData[], WrappingParams params)
            throws Exception;

    /**
     * Unwraps symmetric key data. This method rebuilds the symmetric key by
     * unwrapping the private data blob.
     *
     * @param wrappedKeyData symmetric key data wrapped up with session key
     * @return Symmetric key object
     * @exception Exception failed to unwrap
     */

    public SymmetricKey unwrap(byte wrappedKeyData[], SymmetricKey.Type algorithm, int keySize,
            WrappingParams params) throws Exception;

    /**
     * Unwraps data. This method rebuilds the private key by
     * unwrapping the private key data.
     *
     * @param privateKey private key data
     * @param pubKey public key object
     * @param temporary - temporary key?
     * @param params - wrapping parameters
     * @return private key object
     * @throws Exception
     */
    public PrivateKey unwrap(byte privateKey[], PublicKey pubKey, boolean temporary,
            WrappingParams params) throws Exception;

}
