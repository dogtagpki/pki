package org.dogtagpki.est;

import java.security.cert.X509Certificate;
import java.util.Optional;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.PKIException;

/**
 * The EST API backend interface.
 *
 * @author Fraser Tweedale
 */
public abstract class ESTBackend {

    void start() throws Throwable { }

    void stop() throws Throwable { }

    ESTBackendConfig config;

    public void setConfig(ESTBackendConfig config) {
        this.config = config;
    }

    /**
     * Return CA certificates chain for the (optionally) labeled CA.
     * Described in RFC 7030 section 4.1.
     */
    public abstract CertificateChain cacerts(Optional<String> label)
        throws PKIException;

    /**
     * Simple Enrollment (labeled CA).  RFC 7030 section 4.2.1 and 4.2.3.
     */
    public abstract X509CertImpl simpleenroll(Optional<String> label, PKCS10 csr)
        throws PKIException;

    /**
     * Simple Re-enrollment (labeled CA).  RFC 7030 section 4.2.2 and 4.2.3.
     */
    public abstract X509CertImpl simplereenroll(Optional<String> label, PKCS10 csr)
        throws PKIException;

}
