package org.dogtagpki.tomcat;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmsutil.crypto.CryptoUtil;

import org.mozilla.jss.netscape.security.x509.X509CertImpl;

public class PKITrustManager implements X509TrustManager {

    final static Logger logger = LoggerFactory.getLogger(PKITrustManager.class);

    final static String SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1";
    final static String CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";

    public void checkCertChain(X509Certificate[] certChain, String keyUsage) throws Exception {

        logger.debug("PKITrustManager: checkCertChain(" + keyUsage + ")");

        // sort cert chain from root to leaf
        certChain = CryptoUtil.sortCertificateChain(certChain);

        for (X509Certificate cert : certChain) {
            logger.debug("PKITrustManager:  - " + cert.getSubjectDN());
        }

        // get CA certs
        X509Certificate[] caCerts = getAcceptedIssuers();

        // validating cert chain from root to leaf
        for (int i = 0; i < certChain.length; i++) {

            X509Certificate cert = certChain[i];

            // validating key usage on leaf cert only
            String usage;
            if (i == certChain.length - 1) {
                usage = keyUsage;
            } else {
                usage = null;
            }

            checkCert(cert, caCerts, usage);

            // use the current cert as the CA cert for the next cert in the chain
            caCerts = new X509Certificate[] { cert };
        }
    }

    public void checkCert(X509Certificate cert, X509Certificate[] caCerts, String keyUsage) throws Exception {

        logger.debug("PKITrustManager: checkCert(" + cert.getSubjectDN() + "):");

        boolean[] aki = cert.getIssuerUniqueID();
        logger.debug("PKITrustManager: cert AKI: " + Arrays.toString(aki));

        X509Certificate issuer = null;
        for (X509Certificate caCert : caCerts) {

            boolean[] ski = caCert.getSubjectUniqueID();
            logger.debug("PKITrustManager: SKI of " + caCert.getSubjectDN() + ": " + Arrays.toString(ski));

            try {
                cert.verify(caCert.getPublicKey(), "Mozilla-JSS");
                issuer = caCert;
                break;
            } catch (Exception e) {
                logger.debug("PKITrustManager: invalid certificate: " + e);
            }
        }

        if (issuer == null) {
            throw new CertificateException("Unable to validate signature: " + cert.getSubjectDN());
        }

        logger.debug("PKITrustManager: cert signed by " + issuer.getSubjectDN());

        logger.debug("PKITrustManager: checking validity range:");
        logger.debug("PKITrustManager:  - not before: " + cert.getNotBefore());
        logger.debug("PKITrustManager:  - not after: " + cert.getNotAfter());
        cert.checkValidity();

        if (keyUsage != null) {

            List<String> extendedKeyUsages = cert.getExtendedKeyUsage();
            logger.debug("PKITrustManager: checking extended key usages:");

            for (String extKeyUsage : extendedKeyUsages) {
                logger.debug("PKITrustManager:  - " + extKeyUsage);
            }

            if (extendedKeyUsages.contains(keyUsage)) {
                logger.debug("PKITrustManager: extended key usage found: " + keyUsage);
            } else {
                throw new CertificateException("Missing extended key usage: " + keyUsage);
            }
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certChain, String authType) throws CertificateException {

        logger.debug("PKITrustManager: checkClientTrusted(" + authType + "):");

        try {
            checkCertChain(certChain, CLIENT_AUTH_OID);
            logger.debug("PKITrustManager: SSL client certificate is valid");

        } catch (CertificateException e) {
            logger.warn("Invalid SSL client certificate: " + e);
            throw e;

        } catch (Exception e) {
            logger.warn("Unable to validate certificate: " + e);
            throw new CertificateException(e);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certChain, String authType) throws CertificateException {

        logger.debug("PKITrustManager: checkServerTrusted(" + certChain.length + ", " + authType + "):");

        try {
            checkCertChain(certChain, SERVER_AUTH_OID);
            logger.debug("PKITrustManager: SSL server certificate is valid");

        } catch (CertificateException e) {
            logger.warn("Invalid SSL server certificate: " + e);
            throw e;

        } catch (Exception e) {
            logger.warn("Unable to validate SSL server certificate: " + e);
            throw new CertificateException(e);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {

        logger.debug("PKITrustManager: getAcceptedIssuers():");

        Collection<X509Certificate> caCerts = new ArrayList<>();

        try {
            CryptoManager manager = CryptoManager.getInstance();
            for (org.mozilla.jss.crypto.X509Certificate cert : manager.getCACerts()) {
                logger.debug("PKITrustManager:  - " + cert.getSubjectDN());

                try {
                    X509CertImpl caCert = new X509CertImpl(cert.getEncoded());
                    caCert.checkValidity();
                    caCerts.add(caCert);

                } catch (Exception e) {
                    logger.debug("PKITrustManager: invalid CA certificate: " + e);
                }
            }

        } catch (NotInitializedException e) {
            logger.error("Unable to get CryptoManager: " + e, e);
            throw new RuntimeException(e);
        }

        return caCerts.toArray(new X509Certificate[caCerts.size()]);
    }
}
