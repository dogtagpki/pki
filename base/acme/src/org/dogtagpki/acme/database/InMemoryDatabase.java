//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import java.net.URI;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;

/**
 * @author Endi S. Dewata
 */
public class InMemoryDatabase extends ACMEDatabase {

    private Map<String, ACMENonce> nonces = new ConcurrentHashMap<>();
    private Map<String, ACMEAccount> accounts = new ConcurrentHashMap<>();
    private Map<String, ACMEOrder> orders = new ConcurrentHashMap<>();
    private Map<String, ACMEAuthorization> authorizations = new ConcurrentHashMap<>();

    public void addNonce(ACMENonce nonce) throws Exception {
        nonces.put(nonce.getValue(), nonce);
    }

    public ACMENonce removeNonce(String value) throws Exception {
        return nonces.remove(value);
    }

    public void removeExpiredNonces(Date currentTime) throws Exception {
        nonces.values().removeIf(n -> !currentTime.before(n.getExpirationTime()));
    }

    public ACMEAccount getAccount(String accountID) throws Exception {
        return accounts.get(accountID);
    }

    public void addAccount(ACMEAccount account) throws Exception {
        accounts.put(account.getID(), account);
    }

    public ACMEOrder getOrder(String orderID) throws Exception {
        return orders.get(orderID);
    }

    public ACMEOrder getOrderByAuthorization(String authzID) throws Exception {
        for (ACMEOrder order : orders.values()) {

            if (order.getAuthzIDs() == null) {
                continue;
            }

            for (String orderAuthzID : order.getAuthzIDs()) {
                if (!orderAuthzID.equals(authzID)) continue;

                return order;
            }
        }

        return null;
    }

    public void addOrder(ACMEOrder order) throws Exception {
        orders.put(order.getID(), order);
    }

    public void updateOrder(ACMEOrder order) throws Exception {
        orders.put(order.getID(), order);
    }

    public ACMEAuthorization getAuthorization(String authzID) throws Exception {
        return authorizations.get(authzID);
    }

    public ACMEAuthorization getAuthorizationByChallenge(URI challengeURI) throws Exception {
        for (ACMEAuthorization authorization : authorizations.values()) {

            if (authorization.getChallenges() == null) {
                continue;
            }

            for (ACMEChallenge challenge : authorization.getChallenges()) {
                URI url = challenge.getURL();
                if (!url.equals(challengeURI)) continue;

                return authorization;
            }
        }

        return null;
    }

    public void addAuthorization(ACMEAuthorization authorization) throws Exception {
        authorizations.put(authorization.getID(), authorization);
    }

    public void updateAuthorization(ACMEAuthorization authorization) throws Exception {
        authorizations.put(authorization.getID(), authorization);
    }
}
