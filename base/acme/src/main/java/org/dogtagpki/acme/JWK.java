//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class JWK {

    private String e;
    private String kty;
    private String n;

    public String getE() {
        return e;
    }

    public void setE(String e) {
        this.e = e;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getN() {
        return n;
    }

    public void setN(String n) {
        this.n = n;
    }

    /*
     * JSON Web Key (JWK) Thumbprint
     * https://tools.ietf.org/html/rfc7638
     *
     * Construct a JSON object [RFC7159] containing only the required
     * members of a JWK representing the key and with no whitespace or
     * line breaks before or after any syntactic elements and with the
     * required members ordered lexicographically by the Unicode
     * [UNICODE] code points of the member names. (This JSON object is
     * itself a legal JWK representation of the key.)
     */
    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static JWK fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, JWK.class);
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
