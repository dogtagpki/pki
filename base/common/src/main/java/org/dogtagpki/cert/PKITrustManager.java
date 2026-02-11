package org.dogtagpki.cert;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.PrettyPrintFormat;
import org.mozilla.jss.netscape.security.x509.AuthorityKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PKITrustManager implements X509TrustManager {

    final static Logger logger = LoggerFactory.getLogger(PKITrustManager.class);

    public final static String SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1";
    public final static String CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";

    public void checkCertChain(X509Certificate[] certChain, String keyUsage) throws Exception {

        logger.debug("PKITrustManager: checkCertChain(" + keyUsage + ")");

        // sort cert chain from root to leaf
        certChain = Cert.sortCertificateChain(certChain);

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

    public void checkCert(X509Certificate cert) throws Exception {
        checkCert(cert, getAcceptedIssuers(), null);
    }

    public void checkCert(X509Certificate cert, X509Certificate[] caCerts, String keyUsage) throws Exception {

        logger.debug("PKITrustManager: checkCert(" + cert.getSubjectX500Principal().getName() + "):");

        DerInputStream in;
        byte[] aki = cert.getExtensionValue("2.5.29.35");
        KeyIdentifier akiId = null;
        PrettyPrintFormat pp = new PrettyPrintFormat(":", 30);
        if (aki != null) {
            in = new DerInputStream(aki);
            AuthorityKeyIdentifierExtension akiEx = new AuthorityKeyIdentifierExtension(Boolean.TRUE, in.getOctetString());
            akiId = (KeyIdentifier) akiEx.get(AuthorityKeyIdentifierExtension.KEY_ID);
            logger.debug("PKITrustManager: cert AKI: " + pp.toHexString(akiId.getIdentifier()).trim());
        }

        X509Certificate issuer = null;
        for (X509Certificate caCert : caCerts) {
            byte[] ski = caCert.getExtensionValue("2.5.29.14");
            KeyIdentifier skiId = null;
            if (ski != null){
                in = new DerInputStream(ski);
                SubjectKeyIdentifierExtension skiEx = new SubjectKeyIdentifierExtension(Boolean.TRUE, in.getOctetString());
                skiId = (KeyIdentifier) skiEx.get(SubjectKeyIdentifierExtension.KEY_ID);
                logger.debug("PKITrustManager: SKI of " + caCert.getSubjectX500Principal() + ": " + pp.toHexString(skiId.getIdentifier()).trim());
            }

            if (akiId != null && skiId != null &&
                    ! Arrays.equals(akiId.getIdentifier(), skiId.getIdentifier())) {
                // If AKI in the certificate and SKI in the root certificate are present
                // they have to match
                logger.debug("PKITrustManager: cert AKI not compatible with CA SKI of " + caCert.getSubjectX500Principal());
                continue;
            }
            try {
                cert.verify(caCert.getPublicKey(), "Mozilla-JSS");
                issuer = caCert;
                break;
            } catch (InvalidKeyException e) {
                // The CA key could not be used to sign the certificate, it is possible to move to the next CA
                logger.debug("PKITrustManager: cert not compatible with " + caCert.getSubjectX500Principal() + ": " + e.getMessage());
            } catch (SignatureException e) {
                // The CA has not signed the certificate, it is possible to move to the next CA
                logger.debug("PKITrustManager: cert not issued by " + caCert.getSubjectX500Principal() + ": " + e.getMessage());
            }
        }

        if (issuer == null) {
            throw new SignatureException("Unable to validate certificate signature: " + cert.getSubjectX500Principal());
        }

        logger.debug("PKITrustManager: cert signed by " + issuer.getSubjectX500Principal());

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
                logger.debug("PKITrustManager:  - " + cert.getSubjectX500Principal());

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
