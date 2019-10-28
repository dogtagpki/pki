//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme;

import java.net.URI;
import java.util.Collection;
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
public class ACMEAuthorization {

    @JsonIgnore
    private String id;

    @JsonIgnore
    private String accountID;

    @JsonIgnore
    private Date expirationTime;

    private String status;
    private String expires;
    private ACMEIdentifier identifier;
    private Collection<ACMEChallenge> challenges;
    private Boolean wildcard;

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
        expires = ACME.DATE_FORMAT.format(expirationTime);
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

    public ACMEIdentifier getIdentifier() {
        return identifier;
    }

    public void setIdentifier(ACMEIdentifier identifier) {
        this.identifier = identifier;
    }

    public Collection<ACMEChallenge> getChallenges() {
        return challenges;
    }

    public ACMEChallenge getChallenge(URI challengeURL) {
        for (ACMEChallenge challenge : challenges) {
            if (challenge.getURL().equals(challengeURL)) return challenge;
        }
        return null;
    }

    public void setChallenges(Collection<ACMEChallenge> challenges) {
        this.challenges = challenges;
    }

    public Boolean getWildcard() {
        return wildcard;
    }

    public void setWildcard(Boolean wildcard) {
        this.wildcard = wildcard;
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static ACMEAuthorization fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ACMEAuthorization.class);
    }

    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
