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
package com.netscape.ocsp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.security.ISigningUnit;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * OCSP signing unit based on JSS.
 *
 * $Revision$ $Date$
 */

public final class OCSPSigningUnit implements ISigningUnit {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OCSPSigningUnit.class);

    private CryptoManager mManager = null;
    private CryptoToken mToken = null;
    private PublicKey mPubk = null;
    private PrivateKey mPrivk = null;

    protected X509Certificate mCert = null;
    protected X509CertImpl mCertImpl = null;
    protected String mNickname = null;

    private boolean mInited = false;
    private IConfigStore mConfig;

    @SuppressWarnings("unused")
    private ISubsystem mOwner;

    private String mDefSigningAlgname = null;
    private SignatureAlgorithm mDefSigningAlgorithm = null;

    public OCSPSigningUnit() {
    }

    public X509Certificate getCert() {
        return mCert;
    }

    public X509CertImpl getCertImpl() {
        return mCertImpl;
    }

    public String getNickname() {
        return mNickname;
    }

    public String getNewNickName() throws EBaseException {
        return mConfig.getString(PROP_NEW_NICKNAME, "");
    }

    public void setNewNickName(String name) {
        mConfig.putString(PROP_NEW_NICKNAME, name);
    }

    public PublicKey getPublicKey() {
        return mPubk;
    }

    public PrivateKey getPrivateKey() {
        return mPrivk;
    }

    public void updateConfig(String nickname, String tokenname) {
        mConfig.putString(PROP_CERT_NICKNAME, nickname);
        mConfig.putString(PROP_TOKEN_NAME, tokenname);
    }

    public String getTokenName() throws EBaseException {
        return mConfig.getString(PROP_TOKEN_NAME);
    }

    public String getNickName() throws EBaseException {
        return mConfig.getString(PROP_CERT_NICKNAME);
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {

        logger.debug("OCSPSigningUnit.init(" + owner.getId() + ", " + config.getName() + ")");

        mOwner = owner;
        mConfig = config;

        String tokenname = null;

        try {
            mManager = CryptoManager.getInstance();

            mNickname = config.getString(PROP_CERT_NICKNAME);

            tokenname = config.getString(PROP_TOKEN_NAME);
            mToken = CryptoUtil.getKeyStorageToken(tokenname);
            if (!CryptoUtil.isInternalToken(tokenname)) {
                mNickname = tokenname + ":" + mNickname;
                setNewNickName(mNickname);
            }

            logger.debug("SigningUnit: Loading certificate " + mNickname);
            mCert = mManager.findCertByNickname(mNickname);
            logger.debug("SigningUnit: certificate serial number: " + mCert.getSerialNumber());

            mCertImpl = new X509CertImpl(mCert.getEncoded());

            logger.debug("SigningUnit: Loading private key");
            mPrivk = mManager.findPrivKeyByCert(mCert);

            String privateKeyID = CryptoUtil.encodeKeyID(mPrivk.getUniqueID());
            logger.debug("SigningUnit: private key ID: " + privateKeyID);

            mPubk = mCert.getPublicKey();

            // get def alg and check if def sign alg is valid for token.
            mDefSigningAlgname = config.getString(PROP_DEFAULT_SIGNALG);
            mDefSigningAlgorithm = checkSigningAlgorithmFromName(mDefSigningAlgname);
            logger.debug("SigningUnit: signing algorithm: " + mDefSigningAlgorithm);

            mInited = true;

        } catch (java.security.cert.CertificateException e) {
            logger.error(CMS.getLogMessage("CMSCORE_OCSP_CONVERT_X509", e.getMessage()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (NotInitializedException e) {
            logger.error(CMS.getLogMessage("CMSCORE_OCSP_SIGNING", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (NoSuchTokenException e) {
            logger.error(CMS.getLogMessage("CMSCORE_OCSP_TOKEN_NOT_FOUND", tokenname, e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (ObjectNotFoundException e) {
            logger.error(CMS.getLogMessage("CMSCORE_OCSP_OBJECT_NOT_FOUND", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (TokenException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);
        }
    }

    /**
     * Check if the signing algorithm name is supported and valid for this
     * signing unit's token and key.
     *
     * @param algname a signing algorithm name from JCA.
     * @return the mapped JSS signature algorithm object.
     *
     * @exception EBaseException if signing algorithm is not supported.
     */
    public SignatureAlgorithm checkSigningAlgorithmFromName(String algname)
            throws EBaseException {
        try {
            SignatureAlgorithm sigalg = null;

            sigalg = mapAlgorithmToJss(algname);
            if (sigalg == null) {
                logger.error(CMS.getLogMessage("CMSCORE_OCSP_SIGN_ALG_NOT_SUPPORTED", algname));
                throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", ""));
            }
            Signature signer = mToken.getSignatureContext(sigalg);

            signer.initSign(mPrivk);
            return sigalg;

        } catch (NoSuchAlgorithmException e) {
            logger.error(CMS.getLogMessage("CMSCORE_OCSP_SIGN_ALG_NOT_SUPPORTED", algname), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (TokenException e) {
            // from get signature context or from initSign
            logger.error(CMS.getLogMessage("CMSCORE_OCSP_SIGN_ALG_NOT_SUPPORTED", algname), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (InvalidKeyException e) {
            logger.error(CMS.getLogMessage("CMSCORE_OCSP_SIGN_ALG_NOT_SUPPORTED", algname), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);
        }
    }

    /**
     * @param algname is expected to be one of JCA's algorithm names.
     */
    public byte[] sign(byte[] data, String algname)
            throws EBaseException {
        OCSPEngine engine = OCSPEngine.getInstance();
        if (!mInited) {
            throw new EBaseException("OCSPSigningUnit not initialized!");
        }
        try {
            // XXX for now do this mapping until James changes the names
            // to match JCA names and provide a getAlgorithm method.
            SignatureAlgorithm signAlg = mDefSigningAlgorithm;

            if (algname != null) {
                signAlg = checkSigningAlgorithmFromName(algname);
            }

            // XXX use a pool of signers based on alg ?
            // XXX Map algor. name to id. hack: use hardcoded define for now.
            logger.debug("Getting algorithm context for " + algname + " " + signAlg);
            Signature signer = mToken.getSignatureContext(signAlg);

            signer.initSign(mPrivk);
            signer.update(data);
            logger.debug("Signing OCSP Response");
            return signer.sign();

        } catch (NoSuchAlgorithmException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (TokenException e) {
            // from get signature context or from initSign
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (InvalidKeyException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (SignatureException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            engine.checkForAndAutoShutdown();
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);
        }
    }

    public boolean verify(byte[] data, byte[] signature, String algname)
            throws EBaseException {
        OCSPEngine engine = OCSPEngine.getInstance();
        if (!mInited) {
            throw new EBaseException("OCSPSigningUnit not initialized!");
        }
        try {
            SignatureAlgorithm signAlg = mapAlgorithmToJss(algname);

            if (signAlg == null) {
                logger.error(CMS.getLogMessage("CMSCORE_OCSP_SIGN_ALG_NOT_SUPPORTED", algname));
                throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", ""));
            }

            // XXX make this configurable. hack: use hardcoded for now.
            Signature signer = mToken.getSignatureContext(signAlg);

            signer.initVerify(mPubk);
            signer.update(data);
            return signer.verify(signature);

        } catch (NoSuchAlgorithmException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (TokenException e) {
            // from get signature context or from initSign
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (InvalidKeyException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (SignatureException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            engine.checkForAndAutoShutdown();
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);
        }
    }

    /**
     * returns default signature algorithm
     */
    public SignatureAlgorithm getDefaultSignatureAlgorithm() {
        return mDefSigningAlgorithm;
    }

    /**
     * returns default signing algorithm name.
     */
    public String getDefaultAlgorithm() {
        return mDefSigningAlgname;
    }

    public void setDefaultAlgorithm(String algorithm) throws EBaseException {
        mConfig.putString(PROP_DEFAULT_SIGNALG, algorithm);
        mDefSigningAlgname = algorithm;
        logger.info("Default signing algorithm is set to " + algorithm);
    }

    /**
     * get all possible algorithms for the OCSP signing key type.
     */
    public String[] getAllAlgorithms() throws EBaseException {
        byte[] keybytes = mPubk.getEncoded();
        X509Key key = new X509Key();

        try {
            key.decode(keybytes);
        } catch (java.security.InvalidKeyException e) {
            String msg = "Invalid encoding in OCSP signing key.";
            logger.error(CMS.getLogMessage("CMSCORE_OCSP_INVALID_ENCODING"), e);
            throw new EOCSPException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", msg), e);
        }

        if (key.getAlgorithmId().getOID().equals(AlgorithmId.DSA_oid)) {
            return AlgorithmId.DSA_SIGNING_ALGORITHMS;
        } else {
            return AlgorithmId.ALL_SIGNING_ALGORITHMS;
        }
    }

    public static SignatureAlgorithm mapAlgorithmToJss(String algname) {
        return Cert.mapAlgorithmToJss(algname);
    }
}
