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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ECAException;

/**
 * A class represents the signing unit which is
 * capable of signing data.
 *
 * @version $Revision$, $Date$
 */
public abstract class SigningUnit {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SigningUnit.class);

    protected CryptoManager mManager;
    protected CryptoToken mToken;
    protected PublicKey mPubk;
    protected PrivateKey mPrivk;

    protected X509Certificate mCert;
    protected X509CertImpl mCertImpl;
    protected CertificateChain certChain;
    protected String mNickname;

    protected boolean mInited;
    protected SigningUnitConfig mConfig;

    protected String mDefSigningAlgname;
    protected SignatureAlgorithm mDefSigningAlgorithm;

    /**
     * Retrieves the nickname of the signing certificate.
     */
    public String getNickname() {
        return mNickname;
    }

    /**
     * Retrieves the new nickname in the renewal process.
     *
     * @return new nickname
     * @exception EBaseException failed to get new nickname
     */
    public String getNewNickName() throws EBaseException {
        return mConfig.getNewNickname();
    }

    /**
     * Sets new nickname of the signing certificate.
     *
     * @param name nickname
     */
    public void setNewNickName(String name) {
        mConfig.setNewNickname(name);
    }

    /**
     * Retrieves the signing certificate.
     *
     * @return signing certificate
     */
    public X509Certificate getCert() {
        return mCert;
    }

    /**
     * Retrieves the signing certificate.
     *
     * @return signing certificate
     */
    public X509CertImpl getCertImpl() {
        return mCertImpl;
    }

    public void buildCertChain() throws NotInitializedException, CertificateException, TokenException {

        logger.debug("SigningUnit: Building cert chain:");

        CryptoManager manager = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate[] chain = manager.buildCertificateChain(mCert);

        java.security.cert.X509Certificate[] certs = new java.security.cert.X509Certificate[chain.length];

        for (int i = 0; i < chain.length; i++) {
            certs[i] = new X509CertImpl(chain[i].getEncoded());
            logger.debug("SigningUnit: - " + certs[i].getSubjectDN());
        }

        certChain = new CertificateChain(certs);
    }

    public CertificateChain getCertChain() {
        return certChain;
    }

    /**
     * Signs the given data in specific algorithm.
     *
     * @param data data to be signed
     * @param algname signing algorithm to be used
     * @return signed data
     * @exception Exception failed to sign
     */
    public abstract byte[] sign(byte[] data, String algname) throws Exception;

    /**
     * Verifies the signed data.
     *
     * @param data signed data
     * @param signature signature
     * @param algname signing algorithm
     * @return true if verification is good
     * @exception Exception failed to verify
     */
    public abstract boolean verify(byte[] data, byte[] signature, String algname) throws Exception;

    /**
     * Retrieves the default algorithm.
     *
     * @return default signing algorithm
     */
    public SignatureAlgorithm getDefaultSignatureAlgorithm() {
        return mDefSigningAlgorithm;
    }

    /**
     * Retrieves the default algorithm name.
     *
     * @return default signing algorithm name
     */
    public String getDefaultAlgorithm() {
        return mDefSigningAlgname;
    }

    /**
     * Set default signing algorithm.
     *
     * @param algorithm signing algorithm
     * @exception EBaseException failed to set default signing algorithm
     */
    public void setDefaultAlgorithm(String algorithm) throws EBaseException {
        mConfig.setDefaultSigningAlgorithm(algorithm);
        mDefSigningAlgname = algorithm;
        logger.info("Default signing algorithm is set to " + algorithm);
    }

    /**
     * Retrieves all supported signing algorithm of this unit.
     *
     * @return a list of signing algorithms
     * @exception EBaseException failed to list
     */
    public String[] getAllAlgorithms() throws EBaseException {
        byte[] bytes = mPubk.getEncoded();
        X509Key key = new X509Key();

        try {
            key.decode(bytes);
        } catch (java.security.InvalidKeyException e) {
            String message = "Invalid signing key encoding: " + e.getMessage();
            throw new EBaseException(message, e);
        }
        boolean isDSA = key.getAlgorithmId().getOID().equals(AlgorithmId.DSA_oid);
        return isDSA ? AlgorithmId.DSA_SIGNING_ALGORITHMS : AlgorithmId.ALL_SIGNING_ALGORITHMS;
    }

    /**
     * Retrieves the token name of this unit.
     *
     * @return token name
     * @exception EBaseException failed to retrieve name
     */
    public String getTokenName() throws EBaseException {
        return mConfig.getTokenName();
    }

    /**
     * Updates new nickname and tokename in the configuration file.
     *
     * @param nickname new nickname
     * @param tokenname new tokenname
     */
    public abstract void updateConfig(String nickname, String tokenname);

    /**
     * Checks if the given algorithm name is supported.
     *
     * @param algname algorithm name from JCA
     * @return JSS signing algorithm
     * @exception EBaseException failed to check signing algorithm
     */
    public SignatureAlgorithm checkSigningAlgorithmFromName(String algname)
            throws EBaseException {
        try {
            SignatureAlgorithm sigalg = Cert.mapAlgorithmToJss(algname);
            if (sigalg == null) {
                throw new ECAException("Signing algorithm not supported: " + algname);
            }
            Signature signer = mToken.getSignatureContext(sigalg);

            signer.initSign(mPrivk);
            return sigalg;

        } catch (NoSuchAlgorithmException e) {
            throw new ECAException("Signing algorithm not supported: " + algname + ": " + e.getMessage(), e);

        } catch (TokenException e) {
            throw new ECAException("Signing algorithm not supported: " + algname + ": " + e.getMessage(), e);

        } catch (InvalidKeyException e) {
            throw new ECAException("Signing algorithm not supported: " + algname + ": " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves the public key associated in this unit.
     *
     * @return public key
     */
    public PublicKey getPublicKey() {
        return mPubk;
    }

    /**
     * Retrieves the private key associated in this unit.
     *
     * @return public key
     */
    public PrivateKey getPrivateKey() {
        return mPrivk;
    }
}
