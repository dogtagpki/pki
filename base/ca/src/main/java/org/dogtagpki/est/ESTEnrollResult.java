package org.dogtagpki.est;

import java.security.cert.X509Certificate;

public final class ESTEnrollResult {

    private X509Certificate cert = null;
    private Throwable error = null;

    private ESTEnrollResult(X509Certificate cert) {
        this.cert = cert;
    }

    private ESTEnrollResult(Throwable e) {
        this.error = e;
    }

    public static ESTEnrollResult success(X509Certificate cert) {
        return new ESTEnrollResult(cert);
    }

    public static ESTEnrollResult failure(Throwable e) {
        return new ESTEnrollResult(e);
    }

    /**
     * If true, getCertificate() will return a certificate.
     * If false, getError() will return a Throwable.
     */
    public boolean isSuccess() {
        return this.cert != null;
    }

    /** Return the certificate from the result (if the result is successful) */
    public X509Certificate getCertificate() {
        return this.cert;
    }

    /** Return the failure result */
    public Throwable getError() {
        return this.error;
    }

}
