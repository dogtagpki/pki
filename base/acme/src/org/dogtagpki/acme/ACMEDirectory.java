//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme;

import java.net.URI;

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
public class ACMEDirectory {

    @JsonProperty("meta")
    private ACMEMetadata metadata;

    private URI newNonce;
    private URI newAccount;
    private URI newOrder;
    private URI newAuthz;
    private URI revokeCert;
    private URI keyChange;

    public ACMEMetadata getMetadata() {
        return metadata;
    }

    public void setMetadata(ACMEMetadata metadata) {
        this.metadata = metadata;
    }

    public URI getNewNonce() {
        return newNonce;
    }

    public void setNewNonce(URI newNonce) {
        this.newNonce = newNonce;
    }

    public URI getNewAccount() {
        return newAccount;
    }

    public void setNewAccount(URI newAccount) {
        this.newAccount = newAccount;
    }

    public URI getNewOrder() {
        return newOrder;
    }

    public void setNewOrder(URI newOrder) {
        this.newOrder = newOrder;
    }

    public URI getNewAuthz() {
        return newAuthz;
    }

    public void setNewAuthz(URI newAuthz) {
        this.newAuthz = newAuthz;
    }

    public URI getRevokeCert() {
        return revokeCert;
    }

    public void setRevokeCert(URI revokeCert) {
        this.revokeCert = revokeCert;
    }

    public URI getKeyChange() {
        return keyChange;
    }

    public void setKeyChange(URI keyChange) {
        this.keyChange = keyChange;
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static ACMEDirectory fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ACMEDirectory.class);
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
