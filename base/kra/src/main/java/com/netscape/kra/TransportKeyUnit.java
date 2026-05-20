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
            logger.info("TransportKeyUnit: - subject: " + mCert.getSubjectX500Principal());

            chain = mManager.buildCertificateChain(mCert);

            String signingAlgorithm = config.getString("signingAlgorithm", "SHA256withRSA");
            logger.info("TransportKeyUnit: - signing algorithm: " + signingAlgorithm);

            KRAEngine engine = KRAEngine.getInstance();
            KRAEngineConfig kraCfg = engine.getConfig();

            boolean useOAEPKeyWrap = kraCfg.getUseOAEPKeyWrap();
            logger.info("TransportKeyUnit: - use OAEP key wrap:  " + useOAEPKeyWrap);

            if (useOAEPKeyWrap) {
                this.rsaKeyWrapAlg = KeyWrapAlgorithm.RSA_OAEP;
            }

            // #613795 - initialize this; otherwise JSS is not happy
            CryptoToken token = getToken();
            SignatureAlgorithm signatureAlgorightm = Cert.mapAlgorithmToJss(signingAlgorithm);
            logger.info("TransportKeyUnit: - signature algorithm: " + signatureAlgorightm);

            if (signatureAlgorightm != null) {
                Signature signer = token.getSignatureContext(signatureAlgorightm);
                signer.initSign(getPrivateKey());
            }

            String newNickName = getNewNickName();
            if (newNickName != null && newNickName.length() > 0) {
                mNewCert = mManager.findCertByNickname(newNickName);
                logger.info("TransportKeyUnit: - new subject: " + mNewCert.getSubjectX500Principal());
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
                    logger.info("TransportKeyUnitServlet: transport cert: " + certB64);
                    if (transportCert.equals(certB64)) {
                        cert = mCert;
                        logger.debug("TransportKeyUnit:  Transport certificate verified");
                    }
                } catch (Exception e) {
                    logger.warn("Unable to check transport cert: " + e.getMessage(), e);
                }
            }
            if (cert == null && mNewCert != null) {
                try {
                    certB64 = Utils.base64encode(mNewCert.getEncoded(), true).replaceAll("\n", "").replaceAll("\r", "");
                    logger.info("TransportKeyUnit: new transport cert: " + certB64);
                    if (transportCert.equals(certB64)) {
                        cert = mNewCert;
                        logger.debug("TransportKeyUnit:  New transport certificate verified");
                    }
                } catch (Exception e) {
                    logger.warn("Unable to check new transport cert: " + e.getMessage(), e);
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

        if ("RSA".equals(priKeyAlgo)) {
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

        WrappingParams params = null;
        SymmetricKey sk = null;

        if (CryptoUtil.isAlgorithmMLKEM(priKeyAlgo)) {
            logger.debug("TransportKeyUnit.unwrap: Using ML-KEM decapsulation");
            params = CryptoUtil.getWrappingParams(priKeyAlgo);
            sk = CryptoUtil.decapsulateMLKEM(wrappingKey,
                     encSymmKey,
                     params.getPayloadEncryptionAlgorithm());
            logger.debug("TransportKeyUnit.unwrap: Using ML-KEM decapsulation successful");

        } else {

            params = WrappingParams.getWrappingParamsFromArchiveOptions(
                wrapOID,
                priKeyAlgo,
                new IVParameterSpec(wrapIV));

            //Favor KWP over WRAP PAD if supported
            promoteIfWrapPadToKWP(token, params);

            // (1) unwrap the session key

            KeyWrapAlgorithm skWrapAlgorithm = null;
            if ("RSA".equals(priKeyAlgo)) {
                skWrapAlgorithm = rsaKeyWrapAlg;
            } else {
                skWrapAlgorithm = params.getSkWrapAlgorithm();
            }

            sk = CryptoUtil.unwrap(
                token,
                params.getSkType(),
                params.getSkType().equals(SymmetricKey.DES3)? 0: params.getSkLength(),
                SymmetricKey.Usage.UNWRAP,
                wrappingKey,
                encSymmKey,
                skWrapAlgorithm);
        }

        if (logger.isDebugEnabled()) {
            logger.debug("TransportKeyUnit.unwrap: Session key successfully unwrapped or decapsulated");
            logger.debug("TransportKeyUnit.unwrap: Session key type: " + sk.getType());
            String tokenName = (sk.getOwningToken() != null) ? sk.getOwningToken().getName() : "unknown";
            logger.debug("TransportKeyUnit.unwrap: Session key owning token: " + tokenName);
            logger.debug("TransportKeyUnit.unwrap: Payload wrap algorithm: " + params.getPayloadWrapAlgorithm());
            logger.debug("TransportKeyUnit.unwrap: Payload wrap IV: " + (params.getPayloadWrappingIV() != null ? "present" : "null"));
            logger.debug("TransportKeyUnit.unwrap: About to unwrap private key with session key");
        }

        // (2) unwrap the session-wrapped-private key

        try {
            return CryptoUtil.unwrap(
                    token,
                    pubKey,
                    true,
                    sk,
                    encValue,
                    params.getPayloadWrapAlgorithm(),
                    params.getPayloadWrappingIV());
        } catch (TokenException e) {

            // Fallback strategy: If KWP unwrap fails, the client may have used the older
            // NSS-specific mechanism (AES_KEY_WRAP_PAD) which some clients still use.
            // Since both mechanisms share the same OID, we cannot determine which was used
            // until we attempt the operation. Try the legacy mechanism as fallback.

            KeyWrapAlgorithm currentAlg = params.getPayloadWrapAlgorithm();
            if (currentAlg == KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP) { 
                logger.debug("TransportKeyUnit.unwrap: KWP unwrap failed, retrying with AES_KEY_WRAP_PAD: Original Failure: " + e.getMessage());
                params.setPayloadWrapAlgorithm(KeyWrapAlgorithm.AES_KEY_WRAP_PAD);

                try {
                    PrivateKey result =  CryptoUtil.unwrap(
                            token,
                            pubKey,
                            true,
                            sk,
                            encValue,
                            params.getPayloadWrapAlgorithm(),
                            params.getPayloadWrappingIV());
                    logger.debug("TransportKeyUnit.unwrap: AES_KEY_WRAP_PAD fallback succeeded");
                    return result;
                } catch (TokenException e2) {
                    e2.addSuppressed(e);
                    throw e2;
                }
            }
            throw e;
        }
    }

    /**
     * Promotes AES_KEY_WRAP_PAD to standard AES_KEY_WRAP_PAD_KWP if the token
     * supports it.
     * This addresses two issues:
     *   Both PKCS#11 mechanisms (CKM_NSS_AES_KEY_WRAP_PAD = 0x210A and
     *   CKM_AES_KEY_WRAP_KWP = 0x210B) implement RFC 5649 and share the same
     *   ASN.1 OID
     *   (2.16.840.1.101.3.4.1.8). When receiving wrapped keys, fromOID()
     *   cannot distinguish
     *   which mechanism was used, so it defaults to AES_KEY_WRAP_PAD.
     *   Not all HSMs support the newer PKCS#11 v3.0 standard mechanism
     *   (KWP).
     *   This method detects HSM capability and promotes to the standard mechanism when
     *   available, ensuring future compatibility while maintaining support for older HSM's.
     * Note: Both AES_KEY_WRAP_PAD and AES_KEY_WRAP_PAD_KWP implement
     * RFC 5649, which uses an internal Alternative Initial Value (AIV)
     * rather than an external IV. The IV is set to null accordingly.
     *   @param token The crypto token to check for KWP support
     *   @param params The wrapping params to adjust
     *
     * No-op if the algorithm is not WrapPad or the token lacks KWP support.
     *
     */
    private void promoteIfWrapPadToKWP(CryptoToken token, WrappingParams params) {
        if (token == null || params == null) {
            return;
        }

        if ((params.getPayloadWrapAlgorithm() == KeyWrapAlgorithm.AES_KEY_WRAP_PAD ||
             params.getPayloadWrapAlgorithm() == KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP) &&
            token.doesAlgorithm(KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP)) {
            //If already KWP do anyway to simplify the conditional, consider no op.
            params.setPayloadWrapAlgorithm(KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP);
            params.setPayloadWrappingIV(null);
        }
    }
}
