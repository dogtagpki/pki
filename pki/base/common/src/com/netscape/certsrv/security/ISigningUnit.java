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


import java.security.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.crypto.Signature;
import com.netscape.certsrv.base.*;
import netscape.security.x509.*;

/**
 * A class represents the signing unit which is
 * capable of signing data.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface ISigningUnit {

    public static final String PROP_DEFAULT_SIGNALG = "defaultSigningAlgorithm";
    public static final String PROP_CERT_NICKNAME = "cacertnickname";
    // This signing unit is being used in OCSP and CRL also. So
    // it is better to have a more generic name
    public static final String PROP_RENAMED_CERT_NICKNAME = "certnickname";
    public static final String PROP_TOKEN_NAME = "tokenname";
    public static final String PROP_NEW_NICKNAME = "newNickname";

    /**
     * Retrieves the nickname of the signing certificate.
     */
    public String getNickname(); 

    /**
     * Retrieves the new nickname in the renewal process.
     *
     * @return new nickname
     * @exception EBaseException failed to get new nickname
     */
    public String getNewNickName() throws EBaseException;

    /**
     * Sets new nickname of the signing certificate.
     *
     * @param name nickname
     */
    public void setNewNickName(String name);

    /**
     * Retrieves the signing certificate.
     *
     * @return signing certificate
     */
    public X509Certificate getCert();

    /**
     * Retrieves the signing certificate.
     *
     * @return signing certificate
     */
    public X509CertImpl getCertImpl();

    /**
     * Signs the given data in specific algorithm.
     *
     * @param data data to be signed
     * @param algname signing algorithm to be used
     * @return signed data
     * @exception EBaseException failed to sign
     */
    public byte[] sign(byte[] data, String algname)
        throws EBaseException;
	
    /**
     * Verifies the signed data.
     *
     * @param data signed data
     * @param signature signature
     * @param algname signing algorithm
     * @return true if verification is good
     * @exception EBaseException failed to verify
     */
    public boolean verify(byte[] data, byte[] signature, String algname)
        throws EBaseException;

    /**
     * Retrieves the default algorithm.
     *
     * @return default signing algorithm
     */
    public String getDefaultAlgorithm();

    /**
     * Set default signing algorithm.
     * 
     * @param algorithm signing algorithm
     * @exception EBaseException failed to set default signing algorithm
     */
    public void setDefaultAlgorithm(String algorithm) throws EBaseException;

    /**
     * Retrieves all supported signing algorithm of this unit.
     *
     * @return a list of signing algorithms
     * @exception EBaseException failed to list
     */ 
    public String[] getAllAlgorithms() throws EBaseException;

    /**
     * Retrieves the token name of this unit.
     *
     * @return token name
     * @exception EBaseException failed to retrieve name
     */
    public String getTokenName() throws EBaseException;

    /**
     * Updates new nickname and tokename in the configuration file.
     *
     * @param nickname new nickname
     * @param tokenname new tokenname
     */
    public void updateConfig(String nickname, String tokenname);

    /**
     * Checks if the given algorithm name is supported.
     *
     * @param algname algorithm name
     * @return signing algorithm
     * @exception EBaseException failed to check signing algorithm
     */
    public SignatureAlgorithm checkSigningAlgorithmFromName(String algname)
        throws EBaseException;

    /**
     * Retrieves the public key associated in this unit.
     *
     * @return public key
     */
    public PublicKey getPublicKey();
}

