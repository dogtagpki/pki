package org.dogtagpki.est;

import java.security.cert.X509Certificate;
import java.util.Optional;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;

/**
 * The EST API backend interface.
 *
 * @author Fraser Tweedale
 */
public interface ESTBackend {

    default void start() { }

    default void stop() { }

    /**
     * Return CA certificates chain for the (optionally) labeled CA.
     * Described in RFC 7030 section 4.1.
     */
    public CertificateChain cacerts(Optional<String> label);

    /**
     * Simple Enrollment (labeled CA).  RFC 7030 section 4.2.1 and 4.2.3.
     */
    public ESTEnrollResult simpleenroll(Optional<String> label, PKCS10 csr);

    /**
     * Simple Re-enrollment (labeled CA).  RFC 7030 section 4.2.2 and 4.2.3.
     */
    public ESTEnrollResult simplereenroll(Optional<String> label, PKCS10 csr);

}
