//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import java.net.URI;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEOrder;

/**
 * @author Endi S. Dewata
 */
public class ACMEDatabase {

    protected ACMEDatabaseConfig config;

    public ACMEDatabaseConfig getConfig() {
        return config;
    }

    public void setConfig(ACMEDatabaseConfig config) {
        this.config = config;
    }

    public void init() throws Exception {
    }

    public void close() throws Exception {
    }

    public ACMEAccount getAccount(String accountID) throws Exception {
        return null;
    }

    public void addAccount(ACMEAccount account) throws Exception {
    }

    public ACMEOrder getOrder(String orderID) throws Exception {
        return null;
    }

    public ACMEOrder getOrderByAuthorization(URI authzURI) throws Exception {
        return null;
    }

    public void addOrder(ACMEOrder order) throws Exception {
    }

    public void updateOrder(ACMEOrder order) throws Exception {
    }

    public ACMEAuthorization getAuthorization(String authzID) throws Exception {
        return null;
    }

    public ACMEAuthorization getAuthorizationByChallenge(URI challengeURI) throws Exception {
        return null;
    }

    public void addAuthorization(ACMEAuthorization authorization) throws Exception {
    }

    public void updateAuthorization(ACMEAuthorization authorization) throws Exception {
    }

    public ACMEChallenge getChallenge(String challengeID) throws Exception {
        return null;
    }

    public void addChallenge(ACMEChallenge challenge) throws Exception {
    }
}
