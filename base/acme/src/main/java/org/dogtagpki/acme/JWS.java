//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme;

import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class JWS {

    @JsonProperty("protected")
    private String protectedHeader;

    private String payload;
    private String signature;

    public String getProtectedHeader() {
        return protectedHeader;
    }

    public byte[] getProtectedHeaderAsBytes() {
        return Base64.decodeBase64(protectedHeader);
    }

    public void setProtectedHeader(String protectedHeader) {
        this.protectedHeader = protectedHeader;
    }

    public String getPayload() {
        return payload;
    }

    public byte[] getPayloadAsBytes() {
        return Base64.decodeBase64(payload);
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getSignature() {
        return signature;
    }

    public byte[] getSignatureAsBytes() {
        return Base64.decodeBase64(signature);
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static JWS fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, JWS.class);
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
