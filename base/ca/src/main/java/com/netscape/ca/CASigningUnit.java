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
package com.netscape.ca;

import java.security.SignatureException;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ca.CAMissingCertException;
import com.netscape.certsrv.ca.CAMissingKeyException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.security.SigningUnit;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * CA signing unit based on JSS.
 *
 * $Revision$ $Date$
 */

public final class CASigningUnit extends SigningUnit {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CASigningUnit.class);

    public CASigningUnit() {
    }

    @Override
    public void updateConfig(String nickname, String tokenname) {
        mConfig.putString(PROP_CA_CERT_NICKNAME, nickname);
        mConfig.putString(PROP_TOKEN_NAME, tokenname);
    }

    public void init(IConfigStore config, String nickname) throws EBaseException {

        logger.debug("CASigningUnit.init(" + config.getName() + ", " + nickname + ")");

        mConfig = config;

        String tokenname = null;
        try {
            mManager = CryptoManager.getInstance();

            if (nickname == null) {
                try {
                    mNickname = mConfig.getString(PROP_CERT_NICKNAME);
                } catch (EPropertyNotFound e) {
                    mNickname = mConfig.getString(PROP_CA_CERT_NICKNAME);
                }
            } else {
                mNickname = nickname;
            }

            tokenname = config.getString(PROP_TOKEN_NAME);
            mToken = CryptoUtil.getKeyStorageToken(tokenname);
            if (!CryptoUtil.isInternalToken(tokenname)) {
                mNickname = tokenname + ":" + mNickname;
            }
            setNewNickName(mNickname);

            try {
                logger.debug("SigningUnit: Loading certificate " + mNickname);
                mCert = mManager.findCertByNickname(mNickname);
                logger.debug("SigningUnit: certificate serial number: " + mCert.getSerialNumber());

            } catch (ObjectNotFoundException e) {
                throw new CAMissingCertException("Certificate not found: " + mNickname + ": " + e.getMessage(), e);
            }

            buildCertChain();
            mCertImpl = new X509CertImpl(mCert.getEncoded());

            try {
                logger.debug("SigningUnit: Loading private key");
                mPrivk = mManager.findPrivKeyByCert(mCert);

            } catch (ObjectNotFoundException e) {
                throw new CAMissingKeyException("Private key not found: " + mNickname + ": " + e.getMessage(), e);
            }

            String privateKeyID = CryptoUtil.encodeKeyID(mPrivk.getUniqueID());
            logger.debug("SigningUnit: private key ID: " + privateKeyID);

            mPubk = mCert.getPublicKey();

            // get def alg and check if def sign alg is valid for token.
            mDefSigningAlgname = config.getString(PROP_DEFAULT_SIGNALG);
            mDefSigningAlgorithm = checkSigningAlgorithmFromName(mDefSigningAlgname);
            logger.debug("SigningUnit: signing algorithm: " + mDefSigningAlgorithm);

            mInited = true;

        } catch (java.security.cert.CertificateException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SIGNING_CA_CERT", e.getMessage()), e);
            throw new ECAException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()), e);

        } catch (NotInitializedException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SIGNING_TOKEN_INIT", e.toString()), e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_CRYPTO_NOT_INITIALIZED"), e);

        } catch (NoSuchTokenException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SIGNING_TOKEN_NOT_FOUND", tokenname, e.toString()), e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_TOKEN_NOT_FOUND", tokenname), e);

        } catch (CAMissingCertException | CAMissingKeyException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SIGNING_CERT_NOT_FOUND", e.toString()), e);
            throw e;  // re-throw

        } catch (TokenException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_TOKEN_ERROR"), e);
        }
    }

    /**
     * @param algname is expected to be one of JCA's algorithm names.
     */
    @Override
    public byte[] sign(byte[] data, String algname) throws Exception {

        if (!mInited) {
            throw new EBaseException("CASigningUnit not initialized");
        }

        // XXX for now do this mapping until James changes the names
        // to match JCA names and provide a getAlgorithm method.
        SignatureAlgorithm signAlg = mDefSigningAlgorithm;

        if (algname != null) {
            signAlg = checkSigningAlgorithmFromName(algname);
        }

        // XXX use a pool of signers based on alg ?
        // XXX Map algor. name to id. hack: use hardcoded define for now.
        logger.info("CASigningUnit: Getting algorithm context for " + algname + " " + signAlg);
        Signature signer = mToken.getSignatureContext(signAlg);

        signer.initSign(mPrivk);
        signer.update(data);

        /* debugging
        boolean testAutoShutdown = false;
        testAutoShutdown = mConfig.getBoolean("autoShutdown.test", false);
        if (testAutoShutdown) {
            logger.debug("SigningUnit.sign: test auto shutdown");
            CMS.checkForAndAutoShutdown();
        }
        */

        logger.info("CASigningUnit: Signing Certificate");

        boolean testSignatureFailure = mConfig.getBoolean("testSignatureFailure", false);
        if (testSignatureFailure) {
            throw new SignatureException("SignatureException forced for testing");
        }

        return signer.sign();
    }

    @Override
    public boolean verify(byte[] data, byte[] signature, String algname) throws Exception {

        if (!mInited) {
            throw new EBaseException("CASigningUnit not initialized!");
        }

        SignatureAlgorithm signAlg = Cert.mapAlgorithmToJss(algname);

        if (signAlg == null) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SIGNING_ALG_NOT_SUPPORTED", algname, ""));
            throw new ECAException(CMS.getUserMessage("CMS_CA_SIGNING_ALGOR_NOT_SUPPORTED", algname));
        }

        // XXX make this configurable. hack: use hardcoded for now.
        Signature signer = mToken.getSignatureContext(signAlg);

        signer.initVerify(mPubk);
        signer.update(data);

        return signer.verify(signature);
    }
}
