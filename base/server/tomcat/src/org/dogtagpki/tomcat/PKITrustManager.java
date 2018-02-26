package org.dogtagpki.tomcat;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.logging.Logger;

import javax.net.ssl.X509TrustManager;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;

import netscape.security.x509.X509CertImpl;

public class PKITrustManager implements X509TrustManager {

    final static Logger logger = Logger.getLogger(PKITrustManager.class.getName());

    @Override
    public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {

        logger.fine("PKITrustManager: checkClientTrusted(" + authType + "):");

        for (X509Certificate cert : certs) {
            logger.fine("PKITrustManager:  - " + cert.getSubjectDN());
        }

        try {
            CryptoManager manager = CryptoManager.getInstance();
            X509Certificate cert = certs[0];

            if (!manager.isCertValid(cert.getEncoded(), true, CryptoManager.CertUsage.SSLClient)) {
                throw new CertificateException("Missing SSLClient certificate usage: " + cert.getSubjectDN());
            }

            logger.fine("PKITrustManager: certificate is valid");

        } catch (CertificateException e) {
            throw e;

        } catch (Exception e) {
            throw new CertificateException(e);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {

        logger.fine("PKITrustManager: checkServerTrusted(" + authType + "):");

        for (X509Certificate cert : certs) {
            logger.fine("PKITrustManager:  - " + cert.getSubjectDN());
        }

        try {
            CryptoManager manager = CryptoManager.getInstance();
            X509Certificate cert = certs[0];

            if (!manager.isCertValid(cert.getEncoded(), true, CryptoManager.CertUsage.SSLServer)) {
                throw new CertificateException("Missing SSLServer certificate usage: " + cert.getSubjectDN());
            }

            logger.fine("PKITrustManager: certificate is valid");

        } catch (CertificateException e) {
            throw e;

        } catch (Exception e) {
            throw new CertificateException(e);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {

        logger.fine("PKITrustManager: getAcceptedIssuers():");

        Collection<X509Certificate> certs = new ArrayList<>();

        try {
            CryptoManager manager = CryptoManager.getInstance();
            for (org.mozilla.jss.crypto.X509Certificate cert : manager.getCACerts()) {
                logger.fine("PKITrustManager:  - " + cert.getSubjectDN());

                certs.add(new X509CertImpl(cert.getEncoded()));
            }

        } catch (NotInitializedException | CertificateException e) {
            throw new RuntimeException(e);
        }

        return certs.toArray(new X509Certificate[certs.size()]);
    }
}
