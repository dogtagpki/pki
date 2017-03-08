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
package com.netscape.kra;

import java.security.PublicKey;

import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.security.IEncryptionUnit;
import com.netscape.certsrv.security.WrappingParams;

/**
 * A class represents the transport key pair. This key pair
 * is used to protected EE's private key in transit.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public abstract class EncryptionUnit implements IEncryptionUnit {

    /* Establish one constant IV for base class, to be used for
       internal operations. Constant IV acceptable for symmetric keys.
    */
    public static final byte[] iv = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
    public static final byte[] iv2 = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
    public static final IVParameterSpec IV = new IVParameterSpec(iv);
    public static final IVParameterSpec IV2 = new IVParameterSpec(iv2);

    public EncryptionUnit() {
        CMS.debug("EncryptionUnit.EncryptionUnit this: " + this.toString());
    }

    public abstract CryptoToken getToken();

    public abstract CryptoToken getToken(org.mozilla.jss.crypto.X509Certificate cert);

    public abstract CryptoToken getInternalToken();

    public abstract PublicKey getPublicKey();

    public abstract PrivateKey getPrivateKey();

    public abstract PrivateKey getPrivateKey(org.mozilla.jss.crypto.X509Certificate cert);

    public abstract WrappingParams getWrappingParams() throws EBaseException;

    public WrappingParams getOldWrappingParams() {
        return new WrappingParams(
                SymmetricKey.DES3, KeyGenAlgorithm.DES3, 0,
                KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                KeyWrapAlgorithm.DES3_CBC_PAD, IV, IV);
    }

    public SymmetricKey unwrap_session_key(CryptoToken token, byte encSymmKey[], SymmetricKey.Usage usage,
            WrappingParams params) {
        PrivateKey wrappingKey = getPrivateKey();
        String priKeyAlgo = wrappingKey.getAlgorithm();
        if (priKeyAlgo.equals("EC"))
            params.setSkWrapAlgorithm(KeyWrapAlgorithm.AES_ECB);

        return unwrap_session_key(token, encSymmKey, usage, wrappingKey, params);
    }

    /**
     * Verify the given key pair.
     */
    public void verify(PublicKey publicKey, PrivateKey privateKey) throws
            EBaseException {
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //          Crypto specific methods below here ...
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////

    protected SymmetricKey generate_session_key(CryptoToken token, boolean temporary, WrappingParams params,
            SymmetricKey.Usage[] usages) throws Exception {
        org.mozilla.jss.crypto.KeyGenerator kg = token.getKeyGenerator(params.getSkKeyGenAlgorithm());
        if (usages != null)
            kg.setKeyUsages(usages);
        kg.temporaryKeys(temporary);
        if (params.getSkLength() > 0)
            kg.initialize(params.getSkLength());
        SymmetricKey sk = kg.generate();
        CMS.debug("EncryptionUnit:generate_session_key() session key generated on slot: " + token.getName());
        return sk;
    }

    protected byte[] wrap_session_key(CryptoToken token, PublicKey wrappingKey, SymmetricKey sessionKey,
            WrappingParams params) throws Exception {
        KeyWrapper rsaWrap = token.getKeyWrapper(params.getSkWrapAlgorithm());
        rsaWrap.initWrap(wrappingKey, null);
        byte session[] = rsaWrap.wrap(sessionKey);
        return session;
    }

    protected SymmetricKey unwrap_session_key(CryptoToken token, byte[] wrappedSessionKey, SymmetricKey.Usage usage,
            PrivateKey wrappingKey, WrappingParams params) {
        try {
            KeyWrapper keyWrapper = token.getKeyWrapper(params.getSkWrapAlgorithm());
            keyWrapper.initUnwrap(wrappingKey, null);

            SymmetricKey sk = keyWrapper.unwrapSymmetric(
                    wrappedSessionKey,
                    params.getSkType(),
                    usage,
                    0);
            CMS.debug("EncryptionUnit::unwrap_sym() unwrapped on slot: "
                    + token.getName());
            return sk;
        } catch (Exception e) {
            CMS.debug("EncryptionUnit::unwrap_session_key() error:" + e.toString());
            return null;
        }
    }

    protected byte[] wrap_symmetric_key(CryptoToken token, SymmetricKey sessionKey, SymmetricKey data,
            WrappingParams params) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(params.getPayloadWrapAlgorithm());
        wrapper.initWrap(sessionKey, params.getPayloadWrappingIV());
        return wrapper.wrap(data);
    }

    protected SymmetricKey unwrap_symmetric_key(CryptoToken token, IVParameterSpec iv, SymmetricKey.Type algorithm,
            int strength, SymmetricKey.Usage usage, SymmetricKey sessionKey, byte[] wrappedData,
            WrappingParams params) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(params.getPayloadWrapAlgorithm());
        wrapper.initUnwrap(sessionKey, iv);
        SymmetricKey symKey = wrapper.unwrapSymmetric(wrappedData, algorithm, usage, strength);
        return symKey;
    }

    protected byte[] wrap_private_key(CryptoToken token, SymmetricKey sessionKey, PrivateKey data,
            WrappingParams params) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(params.getPayloadWrapAlgorithm());
        wrapper.initWrap(sessionKey, params.getPayloadWrappingIV());
        return wrapper.wrap(data);
    }

    protected PrivateKey unwrap_private_key(CryptoToken token, PublicKey pubKey,
            boolean temporary, SymmetricKey sessionKey, byte[] wrappedData, WrappingParams params)
            throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(params.getPayloadWrapAlgorithm());
        wrapper.initUnwrap(sessionKey, params.getPayloadWrappingIV());

        // Get the key type for unwrapping the private key.
        PrivateKey.Type keyType = null;
        if (pubKey.getAlgorithm().equalsIgnoreCase(KeyRequestResource.RSA_ALGORITHM)) {
            keyType = PrivateKey.RSA;
        } else if (pubKey.getAlgorithm().equalsIgnoreCase(KeyRequestResource.DSA_ALGORITHM)) {
            keyType = PrivateKey.DSA;
        } else if (pubKey.getAlgorithm().equalsIgnoreCase(KeyRequestResource.EC_ALGORITHM)) {
            keyType = PrivateKey.EC;
        }

        PrivateKey pk = null;
        if (temporary) {
            pk = wrapper.unwrapTemporaryPrivate(wrappedData,
                    keyType, pubKey);
        } else {
            pk = wrapper.unwrapPrivate(wrappedData,
                    keyType, pubKey);
        }
        return pk;
    }

    protected byte[] encrypt_private_key(CryptoToken token, SymmetricKey sessionKey, byte[] data, WrappingParams params)
            throws Exception {
        Cipher cipher = token.getCipherContext(params.getPayloadEncryptionAlgorithm());
        cipher.initEncrypt(sessionKey, params.getPayloadEncryptionIV());
        byte pri[] = cipher.doFinal(data);
        return pri;
    }

    protected byte[] decrypt_private_key(CryptoToken token, SymmetricKey sessionKey,
            byte[] encryptedData, WrappingParams params) throws Exception {
        Cipher cipher = token.getCipherContext(params.getPayloadEncryptionAlgorithm());
        cipher.initDecrypt(sessionKey, params.getPayloadEncryptionIV());
        return cipher.doFinal(encryptedData);
    }

}
