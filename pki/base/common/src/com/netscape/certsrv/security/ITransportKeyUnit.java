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


import java.util.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import netscape.security.x509.*;
import netscape.security.util.*;
import com.netscape.certsrv.base.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.crypto.PrivateKey;


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
    public SymmetricKey unwrap_sym(byte encSymmKey[]);
    public SymmetricKey unwrap_encrypt_sym(byte encSymmKey[]);
    public PrivateKey unwrap_temp(byte wrappedKeyData[], PublicKey
	  pubKey) throws EBaseException;
    public CryptoToken getToken();
    public String getSigningAlgorithm() throws EBaseException; 
    public void setSigningAlgorithm(String str) throws EBaseException; 
}
