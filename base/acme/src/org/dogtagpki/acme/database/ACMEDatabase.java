//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import java.util.Date;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;

/**
 * @author Endi S. Dewata
 */
public abstract class ACMEDatabase {

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

    public abstract void addNonce(ACMENonce nonce) throws Exception;
    public abstract ACMENonce removeNonce(String value) throws Exception;
    public abstract void removeExpiredNonces(Date currentTime) throws Exception;

    public abstract ACMEAccount getAccount(String accountID) throws Exception;
    public abstract void addAccount(ACMEAccount account) throws Exception;

    public abstract ACMEOrder getOrder(String orderID) throws Exception;
    public abstract ACMEOrder getOrderByAuthorization(String authzID) throws Exception;
    public abstract void addOrder(ACMEOrder order) throws Exception;
    public abstract void updateOrder(ACMEOrder order) throws Exception;

    public abstract ACMEAuthorization getAuthorization(String authzID) throws Exception;
    public abstract ACMEAuthorization getAuthorizationByChallenge(String challengeID) throws Exception;
    public abstract void addAuthorization(ACMEAuthorization authorization) throws Exception;
    public abstract void updateAuthorization(ACMEAuthorization authorization) throws Exception;
}
