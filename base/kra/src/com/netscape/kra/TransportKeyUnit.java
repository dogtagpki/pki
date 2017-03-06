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

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.certsrv.security.WrappingParams;
import com.netscape.cmsutil.util.Cert;

/**
 * A class represents the transport key pair. This key pair
 * is used to protected EE's private key in transit.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class TransportKeyUnit extends EncryptionUnit implements
        ISubsystem, ITransportKeyUnit {

    public static final String PROP_NICKNAME = "nickName";
    public static final String PROP_NEW_NICKNAME = "newNickName";
    public static final String PROP_SIGNING_ALGORITHM = "signingAlgorithm";

    // private RSAPublicKey mPublicKey = null;
    // private RSAPrivateKey mPrivateKey = null;
    private IConfigStore mConfig = null;
    private org.mozilla.jss.crypto.X509Certificate mCert = null;
    private org.mozilla.jss.crypto.X509Certificate mNewCert = null;
    private CryptoManager mManager = null;

    /**
     * Constructs this token.
     */
    public TransportKeyUnit() {
        super();
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return "transportKeyUnit";
    }

    /**
     * Sets subsystem identifier.
     */
    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    /**
     * Initializes this subsystem.
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;
        try {
            mManager = CryptoManager.getInstance();
            mCert = mManager.findCertByNickname(getNickName());
            String algo = config.getString("signingAlgorithm", "SHA256withRSA");

            // #613795 - initialize this; otherwise JSS is not happy
            CryptoToken token = getToken();
            SignatureAlgorithm sigalg = Cert.mapAlgorithmToJss(algo);
            Signature signer = token.getSignatureContext(sigalg);
            signer.initSign(getPrivateKey());

            String newNickName = getNewNickName();
            if (newNickName != null && newNickName.length() > 0) {
                mNewCert = mManager.findCertByNickname(newNickName);
            }

        } catch (org.mozilla.jss.CryptoManager.NotInitializedException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));

        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (ObjectNotFoundException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        }
    }

    public WrappingParams getWrappingParams() {
        return getOldWrappingParams();
    }

    public CryptoToken getInternalToken() {
        try {
            return CryptoManager.getInstance().getInternalKeyStorageToken();
        } catch (Exception e) {
            return null;
        }
    }

    public CryptoToken getToken() {
        // 390148: returning the token that owns the private
        //         key.
        return getPrivateKey().getOwningToken();
    }

    public CryptoToken getToken(org.mozilla.jss.crypto.X509Certificate cert) {
        return getPrivateKey(cert).getOwningToken();
    }

    /**
     * Starts up this subsystem.
     */
    public void startup() throws EBaseException {
    }

    /**
     * Shutdowns this subsystem.
     */
    public void shutdown() {
    }

    /**
     * Returns the configuration store of this token.
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public String getNickName() throws EBaseException {
        return mConfig.getString(PROP_NICKNAME);
    }

    public void setNickName(String str) throws EBaseException {
        mConfig.putString(PROP_NICKNAME, str);
    }

    private String getNewNickName() {
        String newNickName = null;
        try {
            newNickName = mConfig.getString(PROP_NEW_NICKNAME);
        } catch (Exception e) {
        }
        return newNickName;
    }

    public String getSigningAlgorithm() throws EBaseException {
        return mConfig.getString(PROP_SIGNING_ALGORITHM);
    }

    public void setSigningAlgorithm(String str) throws EBaseException {
        mConfig.putString(PROP_SIGNING_ALGORITHM, str);
    }

    /**
     * Logins to this token.
     */
    public void login(String pin) throws EBaseException {
    }

    /**
     * Logout from this token.
     */
    public void logout() {
    }

    /**
     * Retrieves public key.
     */
    public org.mozilla.jss.crypto.X509Certificate getCertificate() {
        return mCert;
    }

    public org.mozilla.jss.crypto.X509Certificate getNewCertificate() {
        return mNewCert;
    }

    public org.mozilla.jss.crypto.X509Certificate verifyCertificate(String transportCert) {
        org.mozilla.jss.crypto.X509Certificate cert = null;
        if (transportCert != null && transportCert.length() > 0) {
            String certB64 = null;
            if (mCert != null) {
                try {
                    certB64 = ((CMS.BtoA(mCert.getEncoded())).replaceAll("\n", "")).replaceAll("\r", "");
                    if (transportCert.equals(certB64)) {
                        cert = mCert;
                        CMS.debug("TransportKeyUnit:  Transport certificate verified");
                    }
                } catch (Exception e) {
                }
            }
            if (cert == null && mNewCert != null) {
                try {
                    certB64 = ((CMS.BtoA(mNewCert.getEncoded())).replaceAll("\n", "")).replaceAll("\r", "");
                    if (transportCert.equals(certB64)) {
                        cert = mNewCert;
                        CMS.debug("TransportKeyUnit:  New transport certificate verified");
                    }
                } catch (Exception e) {
                }
            }
        } else {
            cert = mCert;
        }
        return cert;
    }

    public PublicKey getPublicKey() {
        return mCert.getPublicKey();
    }

    public PrivateKey getPrivateKey() {
        return getPrivateKey(mCert);
    }

    public PrivateKey getPrivateKey(org.mozilla.jss.crypto.X509Certificate cert) {
        if (cert == null) {
            cert = mCert;
        }
        try {
            return mManager.findPrivKeyByCert(cert);
        } catch (TokenException e) {
            return null;
        } catch (ObjectNotFoundException e) {
            return null;
        }
    }

    /**
     * Verifies the integrity of the given key pair.
     */
    public void verify(byte publicKey[], PrivateKey privateKey)
            throws EBaseException {
        // XXX
    }

    public SymmetricKey unwrap_sym(byte encSymmKey[], WrappingParams params) {
        return unwrap_session_key(getToken(), encSymmKey, SymmetricKey.Usage.WRAP, params);
    }

    /**
     * Decrypts the user private key.  This is called on the transport unit.
     */
    public byte[] decryptExternalPrivate(byte encSymmKey[],
            String symmAlgOID, byte symmAlgParams[], byte encValue[],
            org.mozilla.jss.crypto.X509Certificate transCert)
            throws Exception {

        CMS.debug("EncryptionUnit.decryptExternalPrivate");
        CryptoToken token = getToken(transCert);

        // TODO(alee) Strictly speaking, we should set the wrapping params from the
        // params coming in. (symmAlgOID etc).  Will fix this in a later patch.
        WrappingParams params = getWrappingParams();
        params.setPayloadEncryptionIV(new IVParameterSpec(symmAlgParams));

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

        return decrypt_private_key(token, sk, encValue, params);
    }

    /**
     * External unwrapping. Unwraps the symmetric key using
     * the transport private key.
     */
    public SymmetricKey unwrap_symmetric(byte encSymmKey[],
            String symmAlgOID, byte symmAlgParams[],
            byte encValue[], SymmetricKey.Type algorithm, int strength)
            throws Exception {

        // TODO(alee) Strictly speaking, we should set the wrapping params from the
        // params coming in. (symmAlgOID etc).  Will fix this in a later patch.
        WrappingParams params = getWrappingParams();
        params.setPayloadEncryptionIV(new IVParameterSpec(symmAlgParams));

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
            byte encValue[], PublicKey pubKey,
            org.mozilla.jss.crypto.X509Certificate transCert)
            throws Exception {
        CryptoToken token = getToken(transCert);

        WrappingParams params = new WrappingParams(
                SymmetricKey.DES3, KeyGenAlgorithm.DES3, 0,
                KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                KeyWrapAlgorithm.DES3_CBC_PAD,
                new IVParameterSpec(symmAlgParams),
                new IVParameterSpec(symmAlgParams));

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
                true /*temporary*/,
                sk,
                encValue,
                params);
    }
}
