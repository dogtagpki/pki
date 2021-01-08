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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.ca;

import java.security.PublicKey;
import java.util.Collection;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CAMissingCertException;
import com.netscape.certsrv.ca.CAMissingKeyException;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class KeyRetrieverRunner implements Runnable {

    public final static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeyRetrieverRunner.class);

    private KeyRetriever keyRetriever;
    private CertificateAuthority certificateAuthority;
    private AuthorityID aid;
    private String nickname;
    private Collection<String> hosts;
    private boolean useOAEPKeyWrap = false;

    public KeyRetrieverRunner(KeyRetriever keyRetriever, CertificateAuthority certificateAuthority) {
        this.keyRetriever = keyRetriever;
        this.certificateAuthority = certificateAuthority;
        this.aid = certificateAuthority.getAuthorityID();
        this.nickname = certificateAuthority.getNickname();
        this.hosts = certificateAuthority.getAuthorityKeyHosts();

        CAEngine engine = CAEngine.getInstance();
        EngineConfig cs = engine.getConfig();
        try {
            this.useOAEPKeyWrap = cs.getBoolean("keyWrap.useOAEP",false);
        } catch (EBaseException e1) {
            throw new RuntimeException("Invalid value for keyWrap.useOAEP: " + e1);
        }

    }

    public void run() {
        try {
            long d = 10000;  // initial delay of 10 seconds

            while (!_run()) {
                logger.debug("Retrying in " + d / 1000 + " seconds");
                try {
                    Thread.sleep(d);
                } catch (InterruptedException e) {
                    break;
                }
                d += d / 2;  // back off
            }

        } finally {
            // remove self from tracker
            CAEngine engine = CAEngine.getInstance();
            engine.removeKeyRetriever(aid);
        }
    }

    /**
     * Main routine of key retrieval and key import.
     *
     * @return false if retrieval should be retried, or true if
     *         the process is "done".  Note that a result of true
     *         does not necessarily imply that the process fully
     *         completed.  See comments at sites of 'return true;'
     *         below.
     */
    private boolean _run() {

        CAEngine engine = CAEngine.getInstance();
        EngineConfig cs = engine.getConfig();

        KeyRetriever.Result krr = null;
        try {
            krr = keyRetriever.retrieveKey(nickname, hosts);
        } catch (Throwable e) {
            logger.warn("Caught exception during execution of KeyRetriever.retrieveKey", e);
            return false;
        }

        if (krr == null) {
            logger.warn("KeyRetriever did not return a result.");
            return false;
        }

        logger.debug("Importing key and cert");
        byte[] certBytes = krr.getCertificate();
        byte[] paoData = krr.getPKIArchiveOptions();

        try {
            CryptoManager manager = CryptoManager.getInstance();
            CryptoToken token = manager.getInternalKeyStorageToken();

            X509Certificate cert = manager.importCACertPackage(certBytes);
            PublicKey pubkey = cert.getPublicKey();
            token.getCryptoStore().deleteCert(cert);

            PrivateKey unwrappingKey = engine.getCA().mSigningUnit.getPrivateKey();

            CryptoUtil.importPKIArchiveOptions(
                token, unwrappingKey, pubkey, paoData, useOAEPKeyWrap);

            cert = manager.importUserCACertPackage(certBytes, nickname);
        } catch (Throwable e) {
            logger.warn("Caught exception during cert/key import", e);
            return false;
        }

        logger.debug("Reinitialising SigningUnit");

        /* While we were retrieving the key and cert, the
         * CA instance in the CAEngine might
         * have been replaced, so look it up afresh.
         */
        CertificateAuthority ca = engine.getCA(aid);
        if (ca == null) {
            /* We got the key, but the authority has been
             * deleted.  Do not retry.
             */
            logger.debug("Authority was deleted; returning.");
            return true;
        }

        boolean initSigUnitSucceeded = false;
        try {
            // re-init signing unit, but avoid triggering
            // key replication if initialisation fails again
            // for some reason
            //
            logger.info("CertificateAuthority: reinitializing signing units in KeyRetrieverRunner");
            ca.initCertSigningUnit();
            ca.initCRLSigningUnit();
            ca.initOCSPSigningUnit();
            initSigUnitSucceeded = true;

        } catch (CAMissingCertException e) {
            logger.warn("CertificateAuthority: CA signing cert not (yet) present in NSS database");
            this.certificateAuthority.signingUnitException = e;

        } catch (CAMissingKeyException e) {
            logger.warn("CertificateAuthority: CA signing key not (yet) present in NSS database");
            this.certificateAuthority.signingUnitException = e;

        } catch (Throwable e) {
            logger.warn("Caught exception during SigningUnit re-init", e);
            return false;
        }

        if (!initSigUnitSucceeded) {
            logger.warn("Failed to re-init SigningUnit");
            return false;
        }

        logger.debug("Adding self to authorityKeyHosts attribute");
        try {
            String host = cs.getHostname() + ":" + engine.getEESSLPort();
            engine.addAuthorityKeyHost(ca, host);
        } catch (Throwable e) {
            /* We retrieved key, imported it, and successfully
             * re-inited the signing unit.  The only thing that
             * failed was adding this host to the list of hosts
             * that possess the key.  This is unlikely, and the
             * key is available elsewhere, so no need to retry.
             */
            logger.warn("Failed to add self to authorityKeyHosts", e);
            return true;
        }

        /* All good! */
        return true;
    }
}
