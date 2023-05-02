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

import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.util.WrappingParams;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * A class represents the transport key pair. This key pair
 * is used to protected EE's private key in transit.
 *
 * @author thomask
 */
public class TransportKeyUnit extends EncryptionUnit {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TransportKeyUnit.class);

    public static final String PROP_NICKNAME = "nickName";
    public static final String PROP_NEW_NICKNAME = "newNickName";
    public static final String PROP_SIGNING_ALGORITHM = "signingAlgorithm";

    // private RSAPublicKey mPublicKey = null;
    // private RSAPrivateKey mPrivateKey = null;
    private ConfigStore mConfig;
    private org.mozilla.jss.crypto.X509Certificate mCert = null;
    private org.mozilla.jss.crypto.X509Certificate[] chain;
    private org.mozilla.jss.crypto.X509Certificate mNewCert = null;
    private CryptoManager mManager = null;
    private KeyWrapAlgorithm rsaKeyWrapAlg = KeyWrapAlgorithm.RSA;

    /**
     * Constructs this token.
     */
    public TransportKeyUnit() {
        super();
    }

    /**
     * Initializes this subsystem.
     */
    public void init(ConfigStore config) throws EBaseException {
        mConfig = config;
        try {
            String nickname = getNickName();
            logger.info("TransportKeyUnit: Loading " + nickname + " certificate");

            mManager = CryptoManager.getInstance();
            mCert = mManager.findCertByNickname(nickname);
            chain = mManager.buildCertificateChain(mCert);

            String algo = config.getString("signingAlgorithm", "SHA256withRSA");


            KRAEngine engine = KRAEngine.getInstance();
            KRAEngineConfig kraCfg = null;
            kraCfg  = engine.getConfig();

            boolean useOAEPKeyWrap = kraCfg.getUseOAEPKeyWrap();
            logger.debug("TransportKeyUnit: keyWrap.useOAEP:  " + useOAEPKeyWrap);
            if(useOAEPKeyWrap == true) {
                this.rsaKeyWrapAlg = KeyWrapAlgorithm.RSA_OAEP;
            }

            // #613795 - initialize this; otherwise JSS is not happy
            CryptoToken token = getToken();
            SignatureAlgorithm sigalg = Cert.mapAlgorithmToJss(algo);
            Signature signer = token.getSignatureContext(sigalg);
            signer.initSign(getPrivateKey());

            String newNickName = getNewNickName();
            if (newNickName != null && newNickName.length() > 0) {
                mNewCert = mManager.findCertByNickname(newNickName);
            }

        } catch (NotInitializedException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (ObjectNotFoundException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);
        }
    }

    @Override
    public CryptoToken getInternalToken() {
        try {
            return CryptoManager.getInstance().getInternalKeyStorageToken();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns this Unit's crypto token object.
     * @return CryptoToken object.
     */
    public CryptoToken getToken() {
        // 390148: returning the token that owns the private
        //         key.
        return getPrivateKey().getOwningToken();
    }

    @Override
    public CryptoToken getToken(org.mozilla.jss.crypto.X509Certificate cert) {
        return getPrivateKey(cert).getOwningToken();
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

    /**
     * Returns this Unit's signing algorithm in String format.
     * @return String of signing algorithm
     * @throws EBaseException
     */
    public String getSigningAlgorithm() throws EBaseException {
        return mConfig.getString(PROP_SIGNING_ALGORITHM);
    }

    /**
     * Sets this Unit's signing algorithm.
     * @param str String of signing algorithm to set.
     * @throws EBaseException
     */
    public void setSigningAlgorithm(String str) throws EBaseException {
        mConfig.putString(PROP_SIGNING_ALGORITHM, str);
    }

    /**
     * Logins to this token.
     */
    @Override
    public void login(String pin) throws EBaseException {
    }

    /**
     * Logout from this token.
     */
    @Override
    public void logout() {
    }

    /**
     * Retrieves public key.
     *
     * @return certificate
     */
    public org.mozilla.jss.crypto.X509Certificate getCertificate() {
        return mCert;
    }

    public org.mozilla.jss.crypto.X509Certificate[] getChain() {
        return chain;
    }

    /**
     * Retrieves new transport certificate.
     *
     * @return certificate
     */
    public org.mozilla.jss.crypto.X509Certificate getNewCertificate() {
        return mNewCert;
    }

    /**
     * Verifies transport certificate.
     *
     * @return certificate
     */
    public org.mozilla.jss.crypto.X509Certificate verifyCertificate(String transportCert) {
        org.mozilla.jss.crypto.X509Certificate cert = null;
        if (transportCert != null && transportCert.length() > 0) {
            String certB64 = null;
            if (mCert != null) {
                try {
                    certB64 = Utils.base64encode(mCert.getEncoded(), true).replaceAll("\n", "").replaceAll("\r", "");
                    if (transportCert.equals(certB64)) {
                        cert = mCert;
                        logger.debug("TransportKeyUnit:  Transport certificate verified");
                    }
                } catch (Exception e) {
                }
            }
            if (cert == null && mNewCert != null) {
                try {
                    certB64 = Utils.base64encode(mNewCert.getEncoded(), true).replaceAll("\n", "").replaceAll("\r", "");
                    if (transportCert.equals(certB64)) {
                        cert = mNewCert;
                        logger.debug("TransportKeyUnit:  New transport certificate verified");
                    }
                } catch (Exception e) {
                }
            }
        } else {
            cert = mCert;
        }
        return cert;
    }

    @Override
    public PublicKey getPublicKey() {
        return mCert.getPublicKey();
    }

    /**
     * Retrieves private key associated with certificate
     *
     * @return certificate
     */
    public PrivateKey getPrivateKey() {
        return getPrivateKey(mCert);
    }

    @Override
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

    /**
     * Unwraps symmetric key . This method
     * unwraps the symmetric key.
     *
     * @param encSymmKey wrapped symmetric key to be unwrapped
     * @return Symmetric key object
     * @throws Exception
     */
    public SymmetricKey unwrap_sym(byte encSymmKey[], WrappingParams params) throws Exception {
        return unwrap_session_key(getToken(), encSymmKey, SymmetricKey.Usage.WRAP, params);
    }

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
    public byte[] decryptExternalPrivate(byte encSymmKey[],
            String wrapOID, byte wrapIV[], byte encValue[],
            org.mozilla.jss.crypto.X509Certificate transCert)
            throws Exception {

        logger.debug("TransportKeyUnit.decryptExternalPrivate");

        if (transCert == null) {
            transCert = mCert;
        }
        CryptoToken token = getToken(transCert);
        PrivateKey wrappingKey = getPrivateKey(transCert);
        String priKeyAlgo = wrappingKey.getAlgorithm();
        WrappingParams params = WrappingParams.getWrappingParamsFromArchiveOptions(
                wrapOID,
                priKeyAlgo,
                new IVParameterSpec(wrapIV));

        KeyWrapAlgorithm skWrapAlgorithm = null;
        if(priKeyAlgo == "RSA") {
            skWrapAlgorithm = rsaKeyWrapAlg;
        } else {
            skWrapAlgorithm = params.getSkWrapAlgorithm();
        }

        SymmetricKey sk = CryptoUtil.unwrap(
                token,
                params.getSkType(),
                params.getSkType().equals(SymmetricKey.DES3)? 0: params.getSkLength(),
                SymmetricKey.Usage.DECRYPT,
                wrappingKey,
                encSymmKey,
                skWrapAlgorithm);

        return CryptoUtil.decryptUsingSymmetricKey(
                token,
                params.getPayloadEncryptionIV(),
                encValue,
                sk,
                params.getPayloadEncryptionAlgorithm());
    }


    /**
     * Unwraps the symmetric key using the transport private key.
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
    public SymmetricKey unwrap_symmetric(byte encSymmKey[],
            String symmAlgOID, byte symmAlgParams[],
            byte encValue[], SymmetricKey.Type algorithm, int strength)
            throws Exception {

        CryptoToken token = getToken();
        PrivateKey wrappingKey = getPrivateKey(mCert);
        String priKeyAlgo = wrappingKey.getAlgorithm();
        WrappingParams params = new WrappingParams(
                symmAlgOID,
                null,
                priKeyAlgo,
                new IVParameterSpec(symmAlgParams),
                null);

        // (1) unwrap the session key
        SymmetricKey sk = unwrap_session_key(token, encSymmKey, SymmetricKey.Usage.UNWRAP, params);

        // (2) unwrap the session-wrapped-symmetric-key
        return CryptoUtil.unwrap(
                token,
                algorithm,
                strength,
                SymmetricKey.Usage.DECRYPT,
                sk,
                encValue,
                params.getPayloadWrapAlgorithm(),
                params.getPayloadEncryptionIV());
    }

    /**
     * Unwraps the data using the transport private key.
     *
     * @param symmAlgOID symmetric algorithm
     * @param symmAlgParams symmetric algorithm parameters
     * @param pubKey public key
     * @param transportCert transport certificate
     * @return private key object
     * @throws Exception
     */
    public PrivateKey unwrap(byte encSymmKey[],
            String wrapOID, byte wrapIV[],
            byte encValue[], PublicKey pubKey,
            org.mozilla.jss.crypto.X509Certificate transCert)
            throws Exception {
        CryptoToken token = getToken(transCert);
        PrivateKey wrappingKey = getPrivateKey(transCert);
        String priKeyAlgo = wrappingKey.getAlgorithm();
        WrappingParams params = WrappingParams.getWrappingParamsFromArchiveOptions(
                wrapOID,
                priKeyAlgo,
                new IVParameterSpec(wrapIV));

        // (1) unwrap the session key


        KeyWrapAlgorithm skWrapAlgorithm = null;
        if(priKeyAlgo == "RSA") {
            skWrapAlgorithm = rsaKeyWrapAlg;
        } else {
            skWrapAlgorithm = params.getSkWrapAlgorithm();
        }

        SymmetricKey sk = CryptoUtil.unwrap(
                token,
                params.getSkType(),
                params.getSkType().equals(SymmetricKey.DES3)? 0: params.getSkLength(),
                SymmetricKey.Usage.UNWRAP,
                wrappingKey,
                encSymmKey,
                skWrapAlgorithm);

        // (2) unwrap the session-wrapped-private key
        return CryptoUtil.unwrap(
                token,
                pubKey,
                true,
                sk,
                encValue,
                params.getPayloadWrapAlgorithm(),
                params.getPayloadWrappingIV());
    }
}
