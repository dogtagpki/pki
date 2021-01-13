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
import java.security.SignatureException;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.security.SigningUnit;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * OCSP signing unit based on JSS.
 *
 * $Revision$ $Date$
 */

public final class OCSPSigningUnit extends SigningUnit {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OCSPSigningUnit.class);

    public OCSPSigningUnit() {
    }

    public void updateConfig(String nickname, String tokenname) {
        mConfig.putString(PROP_CERT_NICKNAME, nickname);
        mConfig.putString(PROP_TOKEN_NAME, tokenname);
    }

    public void init(IConfigStore config) throws EBaseException {

        logger.debug("OCSPSigningUnit.init(" + config.getName() + ")");

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
}
