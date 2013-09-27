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

import java.io.CharConversionException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

import org.mozilla.jss.crypto.BadPaddingException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.security.IEncryptionUnit;
import com.netscape.cmscore.util.Debug;

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
    public byte[] encryptInternalPrivate(byte priKey[])
            throws EBaseException {
        try (DerOutputStream out = new DerOutputStream()) {
            CMS.debug("EncryptionUnit.encryptInternalPrivate");
            CryptoToken internalToken = getInternalToken();

            // (1) generate session key
            org.mozilla.jss.crypto.KeyGenerator kg =
                    internalToken.getKeyGenerator(KeyGenAlgorithm.DES3);
            SymmetricKey sk = kg.generate();

            // (2) wrap private key with session key
            Cipher cipher = internalToken.getCipherContext(
                    EncryptionAlgorithm.DES3_CBC_PAD);

            cipher.initEncrypt(sk, IV);
            byte pri[] = cipher.doFinal(priKey);

            // (3) wrap session with transport public
            KeyWrapper rsaWrap = internalToken.getKeyWrapper(
                    KeyWrapAlgorithm.RSA);

            rsaWrap.initWrap(getPublicKey(), null);
            byte session[] = rsaWrap.wrap(sk);

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
        } catch (TokenException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_INTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::encryptInternalPrivate " + e.toString());
            return null;
        } catch (NoSuchAlgorithmException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_INTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::encryptInternalPrivate " + e.toString());
            return null;
        } catch (CharConversionException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_INTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::encryptInternalPrivate " + e.toString());
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_INTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::encryptInternalPrivate " + e.toString());
            return null;
        } catch (InvalidKeyException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_INTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::encryptInternalPrivate " + e.toString());
            return null;
        } catch (BadPaddingException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_INTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::encryptInternalPrivate " + e.toString());
            return null;
        } catch (IllegalBlockSizeException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_INTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::encryptInternalPrivate " + e.toString());
            return null;
        } catch (IOException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_INTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::encryptInternalPrivate " + e.toString());
            return null;
        } catch (Exception e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_INTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::encryptInternalPrivate " + e.toString());
            return null;
        }
    }

    public byte[] wrap(PrivateKey privKey) throws EBaseException {
        return _wrap(privKey,null);
    }

    public byte[] wrap(SymmetricKey symmKey) throws EBaseException {
        return _wrap(null,symmKey);
    }
    /**
     * External unwrapping. Unwraps the data using
     * the transport private key.
     */
    public SymmetricKey unwrap_sym(byte encSymmKey[], SymmetricKey.Usage usage) {
        try {
            CryptoToken token = getToken();

            // (1) unwrap the session
            PrivateKey priKey = getPrivateKey();
            String priKeyAlgo = priKey.getAlgorithm();
            CMS.debug("EncryptionUnit::unwrap_sym() private key algo: " + priKeyAlgo);
            KeyWrapper keyWrapper = null;
            if (priKeyAlgo.equals("EC")) {
                keyWrapper = token.getKeyWrapper(KeyWrapAlgorithm.AES_ECB);
                keyWrapper.initUnwrap(priKey, null);
            } else {
                keyWrapper = token.getKeyWrapper(KeyWrapAlgorithm.RSA);
                keyWrapper.initUnwrap(priKey, null);
            }
            SymmetricKey sk = keyWrapper.unwrapSymmetric(encSymmKey,
                    SymmetricKey.DES3, usage,
                    0);
            CMS.debug("EncryptionUnit::unwrap_sym() unwrapped on slot: "
                    + token.getName());
            return sk;
        } catch (Exception e) {
            CMS.debug("EncryptionUnit::unwrap_sym() error:" +
                      e.toString());
            return null;
        }
    }

    public SymmetricKey unwrap_sym(byte encSymmKey[]) {
        return unwrap_sym(encSymmKey, SymmetricKey.Usage.WRAP);
    }

    public SymmetricKey unwrap_encrypt_sym(byte encSymmKey[]) {
        return unwrap_sym(encSymmKey, SymmetricKey.Usage.ENCRYPT);
    }

    /**
     * Decrypts the user private key.
     */
    public byte[] decryptExternalPrivate(byte encSymmKey[],
            String symmAlgOID, byte symmAlgParams[], byte encValue[])
            throws EBaseException {
        return decryptExternalPrivate(encSymmKey, symmAlgOID, symmAlgParams,
                                      encValue, null);
    }

    /**
     * Decrypts the user private key.
     */
    public byte[] decryptExternalPrivate(byte encSymmKey[],
            String symmAlgOID, byte symmAlgParams[], byte encValue[],
            org.mozilla.jss.crypto.X509Certificate transCert)
            throws EBaseException {
        try {

            CMS.debug("EncryptionUnit.decryptExternalPrivate");
            CryptoToken token = getToken(transCert);

            // (1) unwrap the session
            KeyWrapper rsaWrap = token.getKeyWrapper(
                    KeyWrapAlgorithm.RSA);

            rsaWrap.initUnwrap(getPrivateKey(transCert), null);
            SymmetricKey sk = rsaWrap.unwrapSymmetric(encSymmKey,
                    SymmetricKey.DES3, SymmetricKey.Usage.DECRYPT,
                    0);

            // (2) unwrap the pri
            Cipher cipher = token.getCipherContext(
                    EncryptionAlgorithm.DES3_CBC_PAD // XXX
                    );

            cipher.initDecrypt(sk, new IVParameterSpec(
                    symmAlgParams));
            return cipher.doFinal(encValue);
        } catch (IllegalBlockSizeException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_EXTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::decryptExternalPrivate " + e.toString());
            return null;
        } catch (BadPaddingException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_EXTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::decryptExternalPrivate " + e.toString());
            return null;
        } catch (TokenException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_EXTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::decryptExternalPrivate " + e.toString());
            return null;
        } catch (NoSuchAlgorithmException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_EXTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::decryptExternalPrivate " + e.toString());
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_EXTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::decryptExternalPrivate " + e.toString());
            return null;
        } catch (InvalidKeyException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_EXTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::decryptExternalPrivate " + e.toString());
            return null;
        } catch (Exception e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_EXTERNAL", e.toString()));
            Debug.trace("EncryptionUnit::decryptExternalPrivate " + e.toString());
            return null;
        }
    }

    /**
     * External unwrapping. Unwraps the symmetric key using
     * the transport private key.
     */
    public SymmetricKey unwrap_symmetric(byte encSymmKey[],
        String symmAlgOID, byte symmAlgParams[],
        byte encValue[])
        throws EBaseException {
        try {
            CryptoToken token = getToken();

            // (1) unwrap the session
            KeyWrapper rsaWrap = token.getKeyWrapper(
                    KeyWrapAlgorithm.RSA);

            rsaWrap.initUnwrap(getPrivateKey(), null);
            SymmetricKey sk = rsaWrap.unwrapSymmetric(encSymmKey,
                    SymmetricKey.DES3, SymmetricKey.Usage.UNWRAP,
                    0);

            // (2) unwrap the sym key
            KeyWrapper wrapper = token.getKeyWrapper(
                    KeyWrapAlgorithm.DES3_CBC_PAD // XXX
                    );

            wrapper.initUnwrap(sk, new IVParameterSpec(
                    symmAlgParams));

            SymmetricKey symKey = wrapper.unwrapSymmetric(encValue, SymmetricKey.DES3, SymmetricKey.Usage.DECRYPT, 0);

            return symKey;
        } catch (TokenException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            return null;
        } catch (NoSuchAlgorithmException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            return null;
        } catch (InvalidKeyException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            return null;
        } catch (Exception e) {
            CMS.debug("EncryptionUnit.unwrap : Exception:" + e.toString());
            return null;
        }
    }

    /**
     * External unwrapping. Unwraps the data using
     * the transport private key.
     */
    public PrivateKey unwrap(byte encSymmKey[],
        String symmAlgOID, byte symmAlgParams[],
        byte encValue[], PublicKey pubKey)
        throws EBaseException {
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
        throws EBaseException {
        try {
            CryptoToken token = getToken(transCert);

            // (1) unwrap the session
            KeyWrapper rsaWrap = token.getKeyWrapper(
                    KeyWrapAlgorithm.RSA);

            rsaWrap.initUnwrap(getPrivateKey(transCert), null);
            SymmetricKey sk = rsaWrap.unwrapSymmetric(encSymmKey,
                    SymmetricKey.DES3, SymmetricKey.Usage.UNWRAP,
                    0);

            // (2) unwrap the pri
            KeyWrapper wrapper = token.getKeyWrapper(
                    KeyWrapAlgorithm.DES3_CBC_PAD // XXX
                );

            wrapper.initUnwrap(sk, new IVParameterSpec(
                    symmAlgParams));

           PrivateKey.Type keytype = null;
            String alg = pubKey.getAlgorithm();
            CMS.debug("EncryptionUnit.unwrap alg ="+ alg);
            if (alg.equals("DSA")) {
                keytype = PrivateKey.DSA;
            } else if (alg.equals("EC")) {
                keytype = PrivateKey.EC;
            } else {
                keytype = PrivateKey.RSA;
            }
            PrivateKey pk = wrapper.unwrapTemporaryPrivate(encValue,
                    keytype , pubKey);

            return pk;
        } catch (TokenException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            CMS.debug("EncryptionUnit.unwrap "+ e.toString());
            return null;
        } catch (NoSuchAlgorithmException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            CMS.debug("EncryptionUnit.unwrap "+ e.toString());
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            CMS.debug("EncryptionUnit.unwrap "+ e.toString());
            return null;
        } catch (InvalidKeyException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            CMS.debug("EncryptionUnit.unwrap "+ e.toString());
            return null;
        } catch (Exception e) {
            CMS.debug("EncryptionUnit.unwrap : Exception:"+e.toString());
            return null;
        }
    }

    /**
     * External unwrapping. Unwraps the data using
     * the transport private key.
     */

    public byte[] decryptInternalPrivate(byte wrappedKeyData[])
            throws EBaseException {
        try {
            CMS.debug("EncryptionUnit.decryptInternalPrivate");
            DerValue val = new DerValue(wrappedKeyData);
            // val.tag == DerValue.tag_Sequence
            DerInputStream in = val.data;
            DerValue dSession = in.getDerValue();
            byte session[] = dSession.getOctetString();
            DerValue dPri = in.getDerValue();
            byte pri[] = dPri.getOctetString();

            CryptoToken token = getToken();

            // (1) unwrap the session
            CMS.debug("decryptInternalPrivate(): getting key wrapper on slot:" + token.getName());
            KeyWrapper rsaWrap = token.getKeyWrapper(
                    KeyWrapAlgorithm.RSA);

            rsaWrap.initUnwrap(getPrivateKey(), null);
            SymmetricKey sk = rsaWrap.unwrapSymmetric(session,
                    SymmetricKey.DES3, SymmetricKey.Usage.DECRYPT, 0);

            // (2) unwrap the pri
            Cipher cipher = token.getCipherContext(
                    EncryptionAlgorithm.DES3_CBC_PAD);

            cipher.initDecrypt(sk, IV);
            return cipher.doFinal(pri);
        } catch (IllegalBlockSizeException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_DECRYPT", e.toString()));
            Debug.trace("EncryptionUnit::decryptInternalPrivate " + e.toString());
            return null;
        } catch (BadPaddingException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_DECRYPT", e.toString()));
            Debug.trace("EncryptionUnit::decryptInternalPrivate " + e.toString());
            return null;
        } catch (TokenException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_DECRYPT", e.toString()));
            Debug.trace("EncryptionUnit::decryptInternalPrivate " + e.toString());
            return null;
        } catch (NoSuchAlgorithmException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_DECRYPT", e.toString()));
            Debug.trace("EncryptionUnit::decryptInternalPrivate " + e.toString());
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_DECRYPT", e.toString()));
            Debug.trace("EncryptionUnit::decryptInternalPrivate " + e.toString());
            return null;
        } catch (InvalidKeyException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_DECRYPT", e.toString()));
            Debug.trace("EncryptionUnit::decryptInternalPrivate " + e.toString());
            return null;
        } catch (IOException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_DECRYPT", e.toString()));
            Debug.trace("EncryptionUnit::decryptInternalPrivate " + e.toString());
            return null;
        } catch (Exception e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_DECRYPT", e.toString()));
            Debug.trace("EncryptionUnit::decryptInternalPrivate " + e.toString());
            return null;
        }
    }

    /**
     * External unwrapping of stored symmetric key.
     */
    public SymmetricKey unwrap(byte wrappedKeyData[])
            throws EBaseException {
        try {
            DerValue val = new DerValue(wrappedKeyData);
            // val.tag == DerValue.tag_Sequence
            DerInputStream in = val.data;
            DerValue dSession = in.getDerValue();
            byte session[] = dSession.getOctetString();
            DerValue dPri = in.getDerValue();
            byte pri[] = dPri.getOctetString();

            CryptoToken token = getToken();
            // (1) unwrap the session key
            KeyWrapper rsaWrap = token.getKeyWrapper(
                    KeyWrapAlgorithm.RSA);

            rsaWrap.initUnwrap(getPrivateKey(), null);
            SymmetricKey sk = rsaWrap.unwrapSymmetric(session,
                    SymmetricKey.DES3, SymmetricKey.Usage.UNWRAP, 0);

            // (2) unwrap the symmetric key
            KeyWrapper wrapper = token.getKeyWrapper(
                    KeyWrapAlgorithm.DES3_CBC_PAD);

            wrapper.initUnwrap(sk, IV);

            SymmetricKey sk_ret = wrapper.unwrapSymmetric(pri,
                    SymmetricKey.DES3, SymmetricKey.Usage.UNWRAP,
                    0);

            return sk_ret;
        } catch (TokenException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            CMS.debug(e);
            return null;
        } catch (NoSuchAlgorithmException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            return null;
        } catch (InvalidKeyException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.printStackTrace(e);
            return null;
        } catch (IOException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            return null;
        } catch (Exception e) {
            Debug.printStackTrace(e);
            return null;
        }
    }

    /**
     * Internal unwrapping.
     */
    public PrivateKey unwrap_temp(byte wrappedKeyData[], PublicKey pubKey)
            throws EBaseException {
        return _unwrap(wrappedKeyData, pubKey, true);
    }

    /**
     * Internal unwrapping.
     */
    public PrivateKey unwrap(byte wrappedKeyData[], PublicKey pubKey)
            throws EBaseException {
        return _unwrap(wrappedKeyData, pubKey, false);
    }

    /**
     * Internal unwrapping.
     */
    private PrivateKey _unwrap(byte wrappedKeyData[], PublicKey
                               pubKey, boolean temporary)
            throws EBaseException {
        try {
            DerValue val = new DerValue(wrappedKeyData);
            // val.tag == DerValue.tag_Sequence
            DerInputStream in = val.data;
            DerValue dSession = in.getDerValue();
            byte session[] = dSession.getOctetString();
            DerValue dPri = in.getDerValue();
            byte pri[] = dPri.getOctetString();

            CryptoToken token = getToken();
            // (1) unwrap the session
            KeyWrapper rsaWrap = token.getKeyWrapper(
                    KeyWrapAlgorithm.RSA);

            rsaWrap.initUnwrap(getPrivateKey(), null);
            SymmetricKey sk = rsaWrap.unwrapSymmetric(session,
                    SymmetricKey.DES3, SymmetricKey.Usage.UNWRAP, 0);

            // (2) unwrap the pri
            KeyWrapper wrapper = token.getKeyWrapper(
                    KeyWrapAlgorithm.DES3_CBC_PAD);

            wrapper.initUnwrap(sk, IV);

            PrivateKey pk = null;
            if (temporary) {
                pk = wrapper.unwrapTemporaryPrivate(pri,
                        PrivateKey.RSA, pubKey);
            } else {
                pk = wrapper.unwrapPrivate(pri,
                        PrivateKey.RSA, pubKey);
            }
            return pk;
        } catch (TokenException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            CMS.debug(e);
            return null;
        } catch (NoSuchAlgorithmException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            return null;
        } catch (InvalidKeyException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.printStackTrace(e);
            return null;
        } catch (IOException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_UNWRAP", e.toString()));
            Debug.trace("EncryptionUnit::unwrap " + e.toString());
            return null;
        } catch (Exception e) {
            Debug.printStackTrace(e);
            return null;
        }
    }

    /***
     * Internal wrap, accounts for either private or symmetric key
     */
    private byte[] _wrap(PrivateKey priKey, SymmetricKey symmKey) throws EBaseException {
        try (DerOutputStream out = new DerOutputStream()) {
            if ((priKey == null && symmKey == null) || (priKey != null && symmKey != null)) {
                return null;
            }
            CMS.debug("EncryptionUnit.wrap interal.");
            CryptoToken token = getToken();

            // (1) generate session key
            org.mozilla.jss.crypto.KeyGenerator kg =
                        token.getKeyGenerator(KeyGenAlgorithm.DES3);
            // internalToken.getKeyGenerator(KeyGenAlgorithm.DES3);
            SymmetricKey.Usage usages[] = new SymmetricKey.Usage[2];
            usages[0] = SymmetricKey.Usage.WRAP;
            usages[1] = SymmetricKey.Usage.UNWRAP;
            kg.setKeyUsages(usages);
            kg.temporaryKeys(true);
            SymmetricKey sk = kg.generate();
            CMS.debug("EncryptionUnit:wrap() session key generated on slot: " + token.getName());

            // (2) wrap private key with session key
            // KeyWrapper wrapper = internalToken.getKeyWrapper(
            KeyWrapper wrapper = token.getKeyWrapper(
                    KeyWrapAlgorithm.DES3_CBC_PAD);

            wrapper.initWrap(sk, IV);

            byte pri[] = null;

            if ( priKey != null) {
                pri = wrapper.wrap(priKey);
            } else if ( symmKey != null) {
                pri = wrapper.wrap(symmKey);
            }
            CMS.debug("EncryptionUnit:wrap() privKey wrapped");

            // (3) wrap session with transport public
            KeyWrapper rsaWrap = token.getKeyWrapper(
                    KeyWrapAlgorithm.RSA);

            rsaWrap.initWrap(getPublicKey(), null);
            byte session[] = rsaWrap.wrap(sk);
            CMS.debug("EncryptionUnit:wrap() sessin key wrapped");

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
        } catch (TokenException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_WRAP", e.toString()));
            Debug.trace("EncryptionUnit::wrap " + e.toString());
            return null;
        } catch (NoSuchAlgorithmException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_WRAP", e.toString()));
            Debug.trace("EncryptionUnit::wrap " + e.toString());
            return null;
        } catch (CharConversionException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_WRAP", e.toString()));
            Debug.trace("EncryptionUnit::wrap " + e.toString());
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_WRAP", e.toString()));
            Debug.trace("EncryptionUnit::wrap " + e.toString());
            return null;
        } catch (InvalidKeyException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_WRAP", e.toString()));
            Debug.trace("EncryptionUnit::wrap " + e.toString());
            return null;
        } catch (IOException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_WRAP", e.toString()));
            Debug.trace("EncryptionUnit::wrap " + e.toString());
            return null;
        } catch (Exception e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_ENCRYPTION_WRAP", e.toString()));
            Debug.trace("EncryptionUnit::wrap " + e.toString());
            return null;
        }
    }

    /**
     * Verify the given key pair.
     */
    public void verify(PublicKey publicKey, PrivateKey privateKey) throws
            EBaseException {
    }
}
