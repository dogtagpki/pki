//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;

/**
 * @author Endi S. Dewata
 */
public class InMemoryDatabase extends ACMEDatabase {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(InMemoryDatabase.class);

    private Map<String, ACMENonce> nonces = new ConcurrentHashMap<>();
    private Map<String, ACMEAccount> accounts = new ConcurrentHashMap<>();
    private Map<String, ACMEOrder> orders = new ConcurrentHashMap<>();
    private Map<String, ACMEAuthorization> authorizations = new ConcurrentHashMap<>();

    public void init() throws Exception {
        logger.info("Initializing in-memory database");
    }

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

    public void updateAccount(ACMEAccount account) throws Exception {
    }

    public ACMEOrder getOrder(String orderID) throws Exception {
        return orders.get(orderID);
    }

    public Collection<ACMEOrder> getOrdersByAuthorizationAndStatus(
            String authzID, String status) throws Exception {
        Vector<ACMEOrder> l = new Vector<>();

        for (ACMEOrder order : orders.values()) {

            if (order.getAuthzIDs() == null) {
                continue;
            }

            for (String orderAuthzID : order.getAuthzIDs()) {
                if (orderAuthzID.equals(authzID) && order.getStatus() == "pending") {
                    l.add(order);
                }
            }
        }

        return l;
    }

    public ACMEOrder getOrderByCertificate(String certID) throws Exception {
        for (ACMEOrder order : orders.values()) {
            if (certID.equals(order.getCertID())) {
                // order found
                return order;
            }
        }

        // no order found
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

    public ACMEAuthorization getAuthorizationByChallenge(String challengeID) throws Exception {
        for (ACMEAuthorization authorization : authorizations.values()) {

            if (authorization.getChallenge(challengeID) != null) {
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
