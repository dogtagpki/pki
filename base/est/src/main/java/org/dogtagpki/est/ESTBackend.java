//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import java.util.Optional;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.PKIException;

/**
 * The EST API backend interface.
 *
 * @author Fraser Tweedale
 * @author cfu (added /fullcmc support)
 */
public abstract class ESTBackend {

    void start() throws Throwable { }

    void stop() throws Throwable { }

    protected ESTBackendConfig config;

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
     *
     * @param authzData data returned by the ESTRequestAuthorizer.  May be null.
     */
    public abstract X509CertImpl simpleenroll(Optional<String> label, PKCS10 csr, ESTRequestAuthorizationData authzData, Object authzResult)
        throws PKIException;

    /**
     * Simple Re-enrollment (labeled CA).  RFC 7030 section 4.2.2 and 4.2.3.
     *
     * @param authzData data returned by the ESTRequestAuthorizer.  May be null.
     */
    public abstract X509CertImpl simplereenroll(Optional<String> label, PKCS10 csr, ESTRequestAuthorizationData authzData, Object authzResult)
        throws PKIException;

    /**
     * Full CMC (labeled CA).  RFC 7030 section 4.3.
     *
     * @param label Optional CA label (preliminary implementation ignores this; future consideration)
     * @param cmcRequest The CMC request data (base64-encoded)
     * @param authzData Authorization data from the request
     * @param authzResult Result from the ESTRequestAuthorizer. May be null.
     * @return CMC response data (binary). Will be base64-encoded by ESTServlet before sending to client.
     */
    public abstract byte[] fullcmc(Optional<String> label, byte[] cmcRequest, ESTRequestAuthorizationData authzData, Object authzResult)
        throws PKIException;

    /**
     * Get the CMC status from the last fullcmc() call in this thread.
     * This is used by ESTServlet to map CMC status to HTTP status codes per RFC 7030/8951.
     *
     * @return CMC status value (SUCCESS=0, FAILED=2, PENDING=3, etc.) or null if not available
     */
    public Integer getLastCMCStatus() {
        return null;  // Default implementation returns null
    }

}
