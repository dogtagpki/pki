//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme;

import java.math.BigInteger;
import java.net.URI;
import java.util.Date;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ACMEOrder {

    @JsonIgnore
    private String id;

    @JsonIgnore
    private String accountID;

    @JsonIgnore
    private Date expirationTime;

    @JsonIgnore
    private Date notBeforeTime;

    @JsonIgnore
    private Date notAfterTime;

    @JsonIgnore
    private String[] authzIDs;

    @JsonIgnore
    private BigInteger serialNumber;

    private String status;
    private String expires;
    private ACMEIdentifier[] identifiers;
    private String notBefore;
    private String notAfter;
    private String error;
    private URI[] authorizations;
    private URI finalize;
    private String csr;
    private URI certificate;
    private URI resource;

    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    public String getAccountID() {
        return accountID;
    }

    public void setAccountID(String accountID) {
        this.accountID = accountID;
    }

    public Date getExpirationTime() {
        return expirationTime;
    }

    public void setExpirationTime(Date expirationTime) {
        this.expirationTime = expirationTime;
        expires = expirationTime == null ? null : ACME.DATE_FORMAT.format(expirationTime);
    }

    public Date getNotBeforeTime() {
        return notBeforeTime;
    }

    public void setNotBeforeTime(Date notBeforeTime) {
        this.notBeforeTime = notBeforeTime;
        notBefore = notBeforeTime == null ? null : ACME.DATE_FORMAT.format(notBeforeTime);
    }

    public Date getNotAfterTime() {
        return notAfterTime;
    }

    public void setNotAfterTime(Date notAfterTime) {
        this.notAfterTime = notAfterTime;
        notAfter = notAfterTime == null ? null : ACME.DATE_FORMAT.format(notAfterTime);
    }

    public String[] getAuthzIDs() {
        return authzIDs;
    }

    public void setAuthzIDs(String[] authzIDs) {
        this.authzIDs = authzIDs;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getExpires() {
        return expires;
    }

    public void setExpires(String expires) {
        this.expires = expires;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    public ACMEIdentifier[] getIdentifiers() {
        return identifiers;
    }

    public void setIdentifiers(ACMEIdentifier[] identifiers) {
        this.identifiers = identifiers;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public URI[] getAuthorizations() {
        return authorizations;
    }

    public void setAuthorizations(URI[] authorizations) {
        this.authorizations = authorizations;
    }

    public URI getFinalize() {
        return finalize;
    }

    public void setFinalize(URI finalize) {
        this.finalize = finalize;
    }

    public String getCSR() {
        return csr;
    }

    public void setCSR(String csr) {
        this.csr = csr;
    }

    public URI getCertificate() {
        return certificate;
    }

    public void setCertificate(URI certificate) {
        this.certificate = certificate;
    }

    public URI getResource() {
        return resource;
    }

    public void setResource(URI resource) {
        this.resource = resource;
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static ACMEOrder fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ACMEOrder.class);
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
