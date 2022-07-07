package org.dogtagpki.est;

import javax.ws.rs.ServiceUnavailableException;

import java.security.cert.X509Certificate;
import java.util.Optional;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;

/**
 * EST backend that acts as RA for a Dogtag CA subsystem
 *
 * @author Fraser Tweedale
 */
public class DogtagRABackend extends ESTBackend {

    @Override
    public CertificateChain cacerts(Optional<String> label) {
        // TODO use label to select LWCA;
        return null;
    }

    @Override
    public ESTEnrollResult simpleenroll(Optional<String> label, PKCS10 csr) {
        return ESTEnrollResult.failure(new ServiceUnavailableException("not implemented"));
    }

    @Override
    public ESTEnrollResult simplereenroll(Optional<String> label, PKCS10 csr) {
        return ESTEnrollResult.failure(new ServiceUnavailableException("not implemented)"));
    }

}
