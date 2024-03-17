package org.dogtagpki.acme;

public class ACMEAlgorithm {
    public enum Algorithm {
        HS256("HS256","HmacSHA256"),
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

        // RFC 7518 Appendix A.1
        // Digital Signature/MAC Algorithm Identifier Cross-Reference
        public String getJCA() {
            return jca;
        }

        private Algorithm (String alg, String jca) {
            this.alg = alg;
            this.jca = jca;
        }
    }

    public boolean isSupported(String alg) {
        for (Algorithm a : Algorithm.values()) {
            if (a.alg == alg) {
                return true;
            }
        }

        return false;
    }
}