//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.client;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * JSSTrustManager for PKI HTTP clients.
 *
 * <p>Loads trust anchors from the NSS certificate database (internal token),
 * from PKCS #11 tokens configured for this client ({@code --token} or
 * entries in {@code -f} password.conf), and from any external PKCS #11 token
 * that is already logged in. The default {@link JSSTrustManager} uses
 * {@link CryptoManager#getCACerts()}, which enumerates CA certificates on all
 * PKCS #11 modules and can trigger password prompts on unrelated HSM tokens.
 */
public class ClientJSSTrustManager extends JSSTrustManager {

    private static final Logger logger = LoggerFactory.getLogger(ClientJSSTrustManager.class);

    private ClientConfig clientConfig;

    public void setClientConfig(ClientConfig clientConfig) {
        this.clientConfig = clientConfig;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {

        logger.debug("ClientJSSTrustManager: getAcceptedIssuers():");

        Collection<X509Certificate> caCerts = new ArrayList<>();

        try {
            for (String tokenName : getTrustAnchorTokenNames()) {
                try {
                    CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
                    logger.debug("ClientJSSTrustManager: listing trust anchors on " + tokenName);
                    addTrustAnchors(caCerts, token);

                } catch (NoSuchTokenException e) {
                    logger.debug("ClientJSSTrustManager: token not found: " + tokenName);
                } catch (TokenException e) {
                    logger.debug("ClientJSSTrustManager: unable to access token " + tokenName
                            + ": " + e.getMessage());
                }
            }

        } catch (NotInitializedException e) {
            logger.error("ClientJSSTrustManager: Unable to get CryptoManager: " + e, e);
            throw new RuntimeException(e);

        } catch (Exception e) {
            logger.error("ClientJSSTrustManager: Unable to list trust anchors: " + e, e);
            throw new RuntimeException(e);
        }

        return caCerts.toArray(new X509Certificate[caCerts.size()]);
    }

    private Set<String> getTrustAnchorTokenNames() throws NotInitializedException {

        Set<String> tokenNames = new LinkedHashSet<>();
        tokenNames.add(CryptoUtil.INTERNAL_TOKEN_NAME);

        if (clientConfig != null) {
            String tokenName = clientConfig.getTokenName();
            if (!CryptoUtil.isInternalToken(tokenName)) {
                tokenNames.add(tokenName);
            }

            Map<String, String> nssPasswords = clientConfig.getNSSPasswords();
            if (nssPasswords != null) {
                for (String name : nssPasswords.keySet()) {
                    if (!CryptoUtil.isInternalToken(name)) {
                        tokenNames.add(name);
                    }
                }
            }
        }

        addLoggedInExternalTokenNames(tokenNames);
        return tokenNames;
    }

    private void addLoggedInExternalTokenNames(Set<String> tokenNames)
            throws NotInitializedException {

        CryptoManager manager = CryptoManager.getInstance();
        Enumeration<CryptoToken> externalTokens = manager.getExternalTokens();

        while (externalTokens != null && externalTokens.hasMoreElements()) {
            CryptoToken token = externalTokens.nextElement();

            try {
                if (!token.isLoggedIn()) {
                    continue;
                }

                String name = token.getName();
                if (!CryptoUtil.isInternalToken(name)) {
                    logger.debug("ClientJSSTrustManager: including logged-in token " + name);
                    tokenNames.add(name);
                }

            } catch (TokenException e) {
                logger.debug("ClientJSSTrustManager: unable to check login state: " + e.getMessage());
            }
        }
    }

    private void addTrustAnchors(Collection<X509Certificate> caCerts, CryptoToken token)
            throws Exception {

        CryptoStore store = token.getCryptoStore();

        for (org.mozilla.jss.crypto.X509Certificate cert : store.getCertificates()) {

            if (!isTrustAnchor(cert)) {
                continue;
            }

            logger.debug("ClientJSSTrustManager:  - " + cert.getSubjectDN());

            try {
                PK11Cert caCert = (PK11Cert) cert;
                caCert.checkValidity();

                if (!containsCert(caCerts, caCert)) {
                    caCerts.add(caCert);
                }

            } catch (Exception e) {
                logger.debug("ClientJSSTrustManager: " + e.getClass().getName() + ": " + e.getMessage());
            }
        }
    }

    private static boolean containsCert(Collection<X509Certificate> caCerts, PK11Cert candidate) {

        for (X509Certificate cert : caCerts) {
            if (cert.equals(candidate)) {
                return true;
            }
        }

        return false;
    }

    private static boolean isTrustAnchor(org.mozilla.jss.crypto.X509Certificate cert) {

        if (!(cert instanceof PK11Cert)) {
            return false;
        }

        return isCATrust(cert.getSSLTrust())
                || isCATrust(cert.getEmailTrust())
                || isCATrust(cert.getObjectSigningTrust());
    }

    private static boolean isCATrust(int trust) {

        return org.mozilla.jss.crypto.X509Certificate.isTrustFlagEnabled(
                org.mozilla.jss.crypto.X509Certificate.TRUSTED_CA, trust)
            || org.mozilla.jss.crypto.X509Certificate.isTrustFlagEnabled(
                org.mozilla.jss.crypto.X509Certificate.TRUSTED_CLIENT_CA, trust)
            || org.mozilla.jss.crypto.X509Certificate.isTrustFlagEnabled(
                org.mozilla.jss.crypto.X509Certificate.VALID_CA, trust)
            || org.mozilla.jss.crypto.X509Certificate.isTrustFlagEnabled(
                org.mozilla.jss.crypto.X509Certificate.NS_TRUSTED_CA, trust);
    }
}
