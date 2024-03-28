package org.dogtagpki.acme;

/**
 * @author Minsu Park
 */

public enum ACMEAlgorithm {
    // RFC 7518 Appendix A.1
    // Digital Signature/MAC Algorithm Identifier Cross-Reference

    // Dogtag's JSS has slightly different algorithm names
    // than what is in RFC 7518

    // TODO: Implement HS256, HS384, HS512 once JSS provider
    // implements those algorithms
    RS256("RS256", "SHA256withRSA"),
    RS384("RS384", "SHA384withRSA"),
    RS512("RS512", "SHA512withRSA"),
    ES256("ES256", "SHA256withEC"),
    ES384("ES384", "SHA384withEC"),
    ES512("ES512", "SHA512withEC"),
    PS256("PS256", "SHA256withRSA/PSS"),
    PS384("PS384", "SHA384withRSA/PSS"),
    PS512("PS512", "SHA512withRSA/PSS");

    private String alg;
    private String jca;

    private ACMEAlgorithm(String alg, String jca) {
        this.alg = alg;
        this.jca = jca;
    }

    public String getJCA() {
        return jca;
    }

    public static ACMEAlgorithm fromString(String alg) throws IllegalArgumentException {
        return ACMEAlgorithm.valueOf(alg.toUpperCase());
    }
}
