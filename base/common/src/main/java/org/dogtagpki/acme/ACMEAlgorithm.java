package org.dogtagpki.acme;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

/**
 * @author Minsu Park
 */

public enum ACMEAlgorithm {
    // RFC 7518 Appendix A.1
    // Digital Signature/MAC Algorithm Identifier Cross-Reference
    HS256("HS256", "HmacSHA256"),
    HS384("HS384", "HmacSHA384"),
    HS512("HS512", "HmacSHA512"),
    RS256("RS256", "SHA256withRSA"),
    RS384("RS384", "SHA384withRSA"),
    RS512("RS512", "SHA512withRSA"),
    ES256("ES256", "SHA256withECDSA"),
    ES384("ES384", "SHA384withECDSA"),
    ES512("ES512", "SHA512withECDSA"),
    PS256("PS256", "SHA256withRSAandMGF1"),
    PS384("PS384", "SHA384withRSAandMGF1"),
    PS512("PS512", "SHA512withRSAandMGF1");

    private String alg;
    private String jca;

    private ACMEAlgorithm(String alg, String jca) {
        this.alg = alg;
        this.jca = jca;
    }

    public String getJCA() {
        return jca;
    }

    public static ACMEAlgorithm fromString(String alg) throws Exception {
        for (ACMEAlgorithm a : ACMEAlgorithm.values()) {
            if (a.alg == alg) {
                return a;
            }
        }

        throw new Exception("unsupported algorithm " + alg);
    }
}