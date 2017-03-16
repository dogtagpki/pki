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
 * An interface represents a encryption unit.
 *
 * @version $Revision$, $Date$
 */
public interface IEncryptionUnit extends IToken {

    /**
     * Retrieves the public key in this unit.
     *
     * @return public key
     */
    public PublicKey getPublicKey();

    /**
     * Verifies the given key pair.
     *
     * @param publicKey public key
     * @param privateKey private key
     */
    public void verify(PublicKey publicKey, PrivateKey privateKey) throws
            EBaseException;

    /**
     * Unwraps symmetric key . This method
     * unwraps the symmetric key.
     *
     * @param encSymmKey wrapped symmetric key to be unwrapped
     * @return Symmetric key object
     * @throws Exception
     */

    public SymmetricKey unwrap_session_key(CryptoToken token, byte encSymmKey[],
            SymmetricKey.Usage usage, WrappingParams params) throws Exception;


    public WrappingParams getWrappingParams() throws Exception;

    public WrappingParams getOldWrappingParams();
}
