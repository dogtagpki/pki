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

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

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
    private byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
    protected IVParameterSpec IV = null;

    public EncryptionUnit() {
        CMS.debug("EncryptionUnit.EncryptionUnit this: " + this.toString());

        IV = new IVParameterSpec(iv);
    }

    public abstract CryptoToken getToken();

    public abstract CryptoToken getToken(org.mozilla.jss.crypto.X509Certificate cert);

    public abstract CryptoToken getInternalToken();

    public abstract PublicKey getPublicKey();

    public abstract PrivateKey getPrivateKey();

    public abstract PrivateKey getPrivateKey(org.mozilla.jss.crypto.X509Certificate cert);

    /**
     * Protects the private key so that it can be stored in
     * internal database.
     */
    public byte[] encryptInternalPrivate(byte priKey[]) throws Exception {
        try (DerOutputStream out = new DerOutputStream()) {
            CMS.debug("EncryptionUnit.encryptInternalPrivate");
            CryptoToken internalToken = getInternalToken();

            WrappingParams params = new WrappingParams(
                    SymmetricKey.DES3, null, KeyGenAlgorithm.DES3, 0,
                    KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                    KeyWrapAlgorithm.DES3_CBC_PAD);

            params = new WrappingParams(
                    SymmetricKey.AES.AES, null, KeyGenAlgorithm.AES, 256,
                    KeyWrapAlgorithm.RSA, EncryptionAlgorithm.AES_256_CBC_PAD,
                    KeyWrapAlgorithm.AES_KEY_WRAP);

            // (1) generate session key
            SymmetricKey sk = generate_session_key(internalToken, false, params);

            // (2) wrap private key with session key
            byte[] pri = encrypt_private_key(internalToken, sk, priKey, params);

            // (3) wrap session with transport public
            byte[] session = wrap_session_key(internalToken, getPublicKey(), sk, params);

            // use MY own structure for now:
            // SEQUENCE {
            //     encryptedSession OCTET STRING,
            //     encryptedPrivate OCTET STRING
            // }

            DerOutputStream tmp = new DerOutputStream();

            tmp.putOctetString(session);
            tmp.putOctetString(pri);
            out.write(DerValue.tag_Sequence, tmp);

            return out.toByteArray();
        }
    }

    public byte[] wrap(PrivateKey privKey) throws Exception {
        return _wrap(privKey,null);
    }

    public byte[] wrap(SymmetricKey symmKey) throws Exception {
        return _wrap(null,symmKey);
    }

    public SymmetricKey unwrap_session_key(CryptoToken token, byte encSymmKey[], SymmetricKey.Usage usage,
            WrappingParams params) {
        PrivateKey wrappingKey = getPrivateKey();
        String priKeyAlgo = wrappingKey.getAlgorithm();
        if (priKeyAlgo.equals("EC"))
            params.setSkWrapAlgorithm(KeyWrapAlgorithm.AES_ECB);

        return unwrap_session_key(token, encSymmKey, usage, wrappingKey, params);
    }

    public SymmetricKey unwrap_sym(byte encSymmKey[], WrappingParams params) {
        return unwrap_session_key(getToken(), encSymmKey, SymmetricKey.Usage.WRAP, params);
    }

    /**
     * Decrypts the user private key.
     */
    public byte[] decryptExternalPrivate(byte encSymmKey[],
            String symmAlgOID, byte symmAlgParams[], byte encValue[])
            throws Exception {
        return decryptExternalPrivate(encSymmKey, symmAlgOID, symmAlgParams,
                                      encValue, null);
    }

    /**
     * Decrypts the user private key.
     */
    public byte[] decryptExternalPrivate(byte encSymmKey[],
            String symmAlgOID, byte symmAlgParams[], byte encValue[],
            org.mozilla.jss.crypto.X509Certificate transCert)
            throws Exception {

        CMS.debug("EncryptionUnit.decryptExternalPrivate");
        CryptoToken token = getToken(transCert);

        WrappingParams params = new WrappingParams(
                SymmetricKey.DES3, null, KeyGenAlgorithm.DES3, 0,
                KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                KeyWrapAlgorithm.DES3_CBC_PAD);

        PrivateKey wrappingKey = getPrivateKey(transCert);
        String priKeyAlgo = wrappingKey.getAlgorithm();
        if (priKeyAlgo.equals("EC"))
            params.setSkWrapAlgorithm(KeyWrapAlgorithm.AES_ECB);

        SymmetricKey sk = unwrap_session_key(
                token,
                encSymmKey,
                SymmetricKey.Usage.DECRYPT,
                wrappingKey,
                params);

        return decrypt_private_key(token, new IVParameterSpec(symmAlgParams), sk, encValue, params);
    }

    /**
     * External unwrapping. Unwraps the symmetric key using
     * the transport private key.
     */
    public SymmetricKey unwrap_symmetric(byte encSymmKey[],
            String symmAlgOID, byte symmAlgParams[],
            byte encValue[], SymmetricKey.Type algorithm, int strength)
            throws Exception {
        WrappingParams params = new WrappingParams(
                SymmetricKey.DES3, null, KeyGenAlgorithm.DES3, 0,
                KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                KeyWrapAlgorithm.DES3_CBC_PAD);

        CryptoToken token = getToken();
        // (1) unwrap the session key
        SymmetricKey sk = unwrap_session_key(token, encSymmKey, SymmetricKey.Usage.UNWRAP, params);

        // (2) unwrap the session-wrapped-symmetric-key
        SymmetricKey symKey = unwrap_symmetric_key(
                token,
                new IVParameterSpec(symmAlgParams),
                algorithm,
                strength,
                SymmetricKey.Usage.DECRYPT,
                sk,
                encValue,
                params);

        return symKey;
    }

    /**
     * External unwrapping. Unwraps the data using
     * the transport private key.
     */
    public PrivateKey unwrap(byte encSymmKey[],
        String symmAlgOID, byte symmAlgParams[],
        byte encValue[], PublicKey pubKey)
        throws Exception {
        return unwrap (encSymmKey, symmAlgOID, symmAlgParams,
                       encValue, pubKey, null);
    }

    /**
     * External unwrapping. Unwraps the data using
     * the transport private key.
     */
    public PrivateKey unwrap(byte encSymmKey[],
            String symmAlgOID, byte symmAlgParams[],
            byte encValue[], PublicKey pubKey,
            org.mozilla.jss.crypto.X509Certificate transCert)
            throws Exception {
        CryptoToken token = getToken(transCert);

        WrappingParams params = new WrappingParams(
                SymmetricKey.DES3, null, KeyGenAlgorithm.DES3, 0,
                KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                KeyWrapAlgorithm.DES3_CBC_PAD);

        PrivateKey wrappingKey = getPrivateKey(transCert);
        String priKeyAlgo = wrappingKey.getAlgorithm();
        if (priKeyAlgo.equals("EC"))
            params.setSkWrapAlgorithm(KeyWrapAlgorithm.AES_ECB);

        // (1) unwrap the session key
        SymmetricKey sk = unwrap_session_key(
                token,
                encSymmKey,
                SymmetricKey.Usage.UNWRAP,
                wrappingKey,
                params);

        // (2) unwrap the session-wrapped-private key
        return unwrap_private_key(
                token,
                pubKey,
                new IVParameterSpec(symmAlgParams),
                true /*temporary*/,
                sk,
                encValue,
                params);
    }

    /**
     * External unwrapping. Unwraps the data using
     * the transport private key.
     */

    public byte[] decryptInternalPrivate(byte wrappedKeyData[])
            throws Exception {
        CMS.debug("EncryptionUnit.decryptInternalPrivate");
        DerValue val = new DerValue(wrappedKeyData);
        // val.tag == DerValue.tag_Sequence
        DerInputStream in = val.data;
        DerValue dSession = in.getDerValue();
        byte session[] = dSession.getOctetString();
        DerValue dPri = in.getDerValue();
        byte pri[] = dPri.getOctetString();

        CryptoToken token = getToken();

        WrappingParams params = new WrappingParams(
                SymmetricKey.DES3, null, KeyGenAlgorithm.DES3, 0,
                KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                KeyWrapAlgorithm.DES3_CBC_PAD);

        params = new WrappingParams(
                SymmetricKey.AES.AES, null, KeyGenAlgorithm.AES, 256,
                KeyWrapAlgorithm.RSA, EncryptionAlgorithm.AES_256_CBC_PAD,
                KeyWrapAlgorithm.AES_KEY_WRAP);

        // (1) unwrap the session key
        CMS.debug("decryptInternalPrivate(): getting key wrapper on slot:" + token.getName());
        SymmetricKey sk = unwrap_session_key(token, session, SymmetricKey.Usage.DECRYPT, params);

        // (2) decrypt the private key
        return decrypt_private_key(token, IV, sk, pri, params);
    }

    /**
     * External unwrapping of stored symmetric key.
     */
    public SymmetricKey unwrap(byte wrappedKeyData[], SymmetricKey.Type algorithm, int keySize)
            throws Exception {
        DerValue val = new DerValue(wrappedKeyData);
        // val.tag == DerValue.tag_Sequence
        DerInputStream in = val.data;
        DerValue dSession = in.getDerValue();
        byte session[] = dSession.getOctetString();
        DerValue dPri = in.getDerValue();
        byte pri[] = dPri.getOctetString();

        WrappingParams params = new WrappingParams(
                SymmetricKey.DES3, null, KeyGenAlgorithm.DES3, 0,
                KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                KeyWrapAlgorithm.DES3_CBC_PAD);

        CryptoToken token = getToken();
        // (1) unwrap the session key
        SymmetricKey sk = unwrap_session_key(token, session, SymmetricKey.Usage.UNWRAP, params);

        // (2) unwrap the session-wrapped-symmetric key
        return unwrap_symmetric_key(token, IV, algorithm, keySize, SymmetricKey.Usage.UNWRAP, sk, pri, params);
    }

    /**
     * Internal unwrapping.
     */
    public PrivateKey unwrap_temp(byte wrappedKeyData[], PublicKey pubKey)
            throws Exception {
        return _unwrap(wrappedKeyData, pubKey, true);
    }

    /**
     * Internal unwrapping.
     */
    public PrivateKey unwrap(byte wrappedKeyData[], PublicKey pubKey)
            throws Exception {
        return _unwrap(wrappedKeyData, pubKey, false);
    }

    /**
     * Internal unwrapping.
     */
    private PrivateKey _unwrap(byte wrappedKeyData[], PublicKey pubKey, boolean temporary)
            throws Exception {
        DerValue val = new DerValue(wrappedKeyData);
        // val.tag == DerValue.tag_Sequence
        DerInputStream in = val.data;
        DerValue dSession = in.getDerValue();
        byte session[] = dSession.getOctetString();
        DerValue dPri = in.getDerValue();
        byte pri[] = dPri.getOctetString();

        WrappingParams params = new WrappingParams(
                SymmetricKey.DES3, null, KeyGenAlgorithm.DES3, 0,
                KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                KeyWrapAlgorithm.DES3_CBC_PAD);

        params = new WrappingParams(
                SymmetricKey.AES.AES, null, KeyGenAlgorithm.AES, 256,
                KeyWrapAlgorithm.RSA, EncryptionAlgorithm.AES_256_CBC_PAD,
                KeyWrapAlgorithm.AES_KEY_WRAP);

        CryptoToken token = getToken();
        // (1) unwrap the session key
        SymmetricKey sk = unwrap_session_key(token, session, SymmetricKey.Usage.UNWRAP, params);

        // (2) unwrap the private key
        return unwrap_private_key(token, pubKey, IV, temporary, sk, pri, params);
    }

    /***
     * Internal wrap, accounts for either private or symmetric key
     */
    private byte[] _wrap(PrivateKey priKey, SymmetricKey symmKey) throws Exception {
        try (DerOutputStream out = new DerOutputStream()) {
            if ((priKey == null && symmKey == null) || (priKey != null && symmKey != null)) {
                return null;
            }
            CMS.debug("EncryptionUnit.wrap interal.");
            CryptoToken token = getToken();

            SymmetricKey.Usage usages[] = new SymmetricKey.Usage[2];
            usages[0] = SymmetricKey.Usage.WRAP;
            usages[1] = SymmetricKey.Usage.UNWRAP;

            WrappingParams params = new WrappingParams(
                    SymmetricKey.DES3, usages, KeyGenAlgorithm.DES3, 0,
                    KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                    KeyWrapAlgorithm.DES3_CBC_PAD);

            params = new WrappingParams(
                    SymmetricKey.AES.AES, null, KeyGenAlgorithm.AES, 256,
                    KeyWrapAlgorithm.RSA, EncryptionAlgorithm.AES_256_CBC_PAD,
                    KeyWrapAlgorithm.AES_KEY_WRAP);

            // (1) generate session key
            SymmetricKey sk = generate_session_key(token, true, params);

            // (2) wrap private key with session key
            // KeyWrapper wrapper = internalToken.getKeyWrapper(

            byte pri[] = null;

            if (priKey != null) {
                pri = wrap_private_key(token, sk, priKey, params);
            } else if (symmKey != null) {
                pri = wrap_symmetric_key(token, sk, symmKey, params);
            }

            CMS.debug("EncryptionUnit:wrap() privKey wrapped");

            byte[] session = wrap_session_key(token, getPublicKey(), sk, params);
            CMS.debug("EncryptionUnit:wrap() session key wrapped");

            // use MY own structure for now:
            // SEQUENCE {
            //     encryptedSession OCTET STRING,
            //     encryptedPrivate OCTET STRING
            // }

            DerOutputStream tmp = new DerOutputStream();

            tmp.putOctetString(session);
            tmp.putOctetString(pri);
            out.write(DerValue.tag_Sequence, tmp);

            return out.toByteArray();
        }
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

    private SymmetricKey generate_session_key(CryptoToken token, boolean temporary, WrappingParams params)
            throws Exception{
        org.mozilla.jss.crypto.KeyGenerator kg = token.getKeyGenerator(params.getSkKeyGenAlgorithm());
        SymmetricKey.Usage[] usages = params.getSkUsages();
        if (usages != null)
            kg.setKeyUsages(usages);
        kg.temporaryKeys(temporary);
        if (params.getSkLength() > 0)
            kg.initialize(params.getSkLength());
        SymmetricKey sk = kg.generate();
        CMS.debug("EncryptionUnit:generate_session_key() session key generated on slot: " + token.getName());
        return sk;
    }

    private byte[] wrap_session_key(CryptoToken token, PublicKey wrappingKey, SymmetricKey sessionKey,
            WrappingParams params) throws Exception {
        KeyWrapper rsaWrap = token.getKeyWrapper(params.getSkWrapAlgorithm());
        rsaWrap.initWrap(wrappingKey, null);
        byte session[] = rsaWrap.wrap(sessionKey);
        return session;
    }

    public SymmetricKey unwrap_session_key(CryptoToken token, byte[] wrappedSessionKey, SymmetricKey.Usage usage,
            PrivateKey wrappingKey, WrappingParams params) {
        try {
            KeyWrapper keyWrapper = token.getKeyWrapper(params.getSkWrapAlgorithm());
            keyWrapper.initUnwrap(wrappingKey, null);

            SymmetricKey sk = keyWrapper.unwrapSymmetric(
                    wrappedSessionKey,
                    params.getSkTyoe(),
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

    private byte[] wrap_symmetric_key(CryptoToken token, SymmetricKey sessionKey, SymmetricKey data,
            WrappingParams params) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(params.getPayloadWrapAlgorithm());

        wrapper.initWrap(sessionKey, IV);
        return wrapper.wrap(data);
    }

    private SymmetricKey unwrap_symmetric_key(CryptoToken token, IVParameterSpec iv, SymmetricKey.Type algorithm,
            int strength, SymmetricKey.Usage usage, SymmetricKey sessionKey, byte[] wrappedData,
            WrappingParams params) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(params.getPayloadWrapAlgorithm());
        wrapper.initUnwrap(sessionKey, iv);
        SymmetricKey symKey = wrapper.unwrapSymmetric(wrappedData, algorithm, usage, strength);
        return symKey;
    }

    private byte[] wrap_private_key(CryptoToken token, SymmetricKey sessionKey, PrivateKey data,
            WrappingParams params) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(params.getPayloadWrapAlgorithm());
        wrapper.initWrap(sessionKey, IV);
        return wrapper.wrap(data);
    }

    private PrivateKey unwrap_private_key(CryptoToken token, PublicKey pubKey, IVParameterSpec iv,
            boolean temporary, SymmetricKey sessionKey, byte[] wrappedData, WrappingParams params)
            throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(params.getPayloadWrapAlgorithm());
        wrapper.initUnwrap(sessionKey, iv);

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

    private byte[] encrypt_private_key(CryptoToken token, SymmetricKey sessionKey, byte[] data, WrappingParams params)
            throws Exception {
        Cipher cipher = token.getCipherContext(params.getPayloadEncryptionAlgorithm());

        cipher.initEncrypt(sessionKey, IV);
        byte pri[] = cipher.doFinal(data);
        return pri;
    }

    private byte[] decrypt_private_key(CryptoToken token, IVParameterSpec iv, SymmetricKey sessionKey,
            byte[] encryptedData, WrappingParams params) throws Exception {
        Cipher cipher = token.getCipherContext(params.getPayloadEncryptionAlgorithm());
        cipher.initDecrypt(sessionKey, iv);
        return cipher.doFinal(encryptedData);
    }

}
