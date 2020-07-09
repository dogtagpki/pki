//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEIdentifier;
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
    private Map<String, X509Certificate> certificates = new ConcurrentHashMap<>();

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

    public Collection<ACMEAuthorization> getRevocationAuthorizations(String accountID, Date time) throws Exception {

        Collection<ACMEAuthorization> results = new ArrayList<>();

        for (ACMEAuthorization authorization : authorizations.values()) {

            if (!authorization.getAccountID().equals(accountID)) {
                continue;
            }

            String status = authorization.getStatus();
            if (!"valid".equals(status)) {
                logger.info("Authorization " + authorization.getID() + " is " + status);
                continue;
            }

            Date expirationTime = authorization.getExpirationTime();
            if (expirationTime != null && !expirationTime.after(time)) {
                logger.info("Authorization " + authorization.getID() + " has expired");
                continue;
            }

            results.add(authorization);
        }

        return results;
    }

    public boolean hasRevocationAuthorization(String accountID, Date time, ACMEIdentifier identifier) throws Exception {

        for (ACMEAuthorization authorization : authorizations.values()) {

            if (!authorization.getAccountID().equals(accountID)) {
                continue;
            }

            String status = authorization.getStatus();
            if (!"valid".equals(status)) {
                logger.info("Authorization " + authorization.getID() + " is " + status);
                continue;
            }

            Date expirationTime = authorization.getExpirationTime();
            if (expirationTime != null && !expirationTime.after(time)) {
                logger.info("Authorization " + authorization.getID() + " has expired");
                continue;
            }

            // Compare authorization's identifier against provided identifier

            ACMEIdentifier authzIdentifier = authorization.getIdentifier();
            String type = authzIdentifier.getType();

            if ("dns".equals(type) && authorization.getWildcard()) {

                // append *. prefix so the identifiers can be compared
                String value = "*." + authzIdentifier.getValue();

                authzIdentifier = new ACMEIdentifier();
                authzIdentifier.setType(type);
                authzIdentifier.setValue(value);
            }

            if (!authzIdentifier.equals(identifier)) {
                logger.info("Authorization " + authorization.getID() + " does not match " + identifier);
                continue;
            }

            return true;
        }

        return false;
    }

    public void addAuthorization(ACMEAuthorization authorization) throws Exception {
        authorizations.put(authorization.getID(), authorization);
    }

    public void updateAuthorization(ACMEAuthorization authorization) throws Exception {
        authorizations.put(authorization.getID(), authorization);
    }

    public void removeExpiredAuthorizations(Date currentTime) throws Exception {
        authorizations.values().removeIf(
                n -> n.getExpirationTime() != null && !currentTime.before(n.getExpirationTime()));
    }

    public X509Certificate getCertificate(String certID) throws Exception {
        return certificates.get(certID);
    }

    public void addCertificate(String certID, X509Certificate cert) throws Exception {
        certificates.put(certID, cert);
    }

    public void removeCertificate(String certID) throws Exception {
        certificates.remove(certID);
    }
}
