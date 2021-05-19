//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMECertificate;
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
    private Map<String, ACMECertificate> certificates = new ConcurrentHashMap<>();

    @Override
    public void init() throws Exception {
        logger.info("Initializing in-memory database");
    }

    @Override
    public void addNonce(ACMENonce nonce) throws Exception {
        nonces.put(nonce.getID(), nonce);
    }

    @Override
    public ACMENonce removeNonce(String nonceID) throws Exception {
        return nonces.remove(nonceID);
    }

    @Override
    public void removeExpiredNonces(Date currentTime) throws Exception {
        nonces.values().removeIf(n -> !currentTime.before(n.getExpirationTime()));
    }

    @Override
    public ACMEAccount getAccount(String accountID) throws Exception {
        return accounts.get(accountID);
    }

    @Override
    public void addAccount(ACMEAccount account) throws Exception {
        accounts.put(account.getID(), account);
    }

    @Override
    public void updateAccount(ACMEAccount account) throws Exception {
    }

    @Override
    public ACMEOrder getOrder(String orderID) throws Exception {
        return orders.get(orderID);
    }

    @Override
    public Collection<ACMEOrder> getOrdersByAccount(String accountID) throws Exception {

        Collection<ACMEOrder> results = new ArrayList<>();

        for (ACMEOrder order : orders.values()) {
            if (order.getAccountID().equals(accountID)) {
                results.add(order);
            }
        }

        return results;
    }

    @Override
    public Collection<ACMEOrder> getOrdersByAuthorizationAndStatus(
            String authzID, String status) throws Exception {

        Collection<ACMEOrder> results = new ArrayList<>();

        for (ACMEOrder order : orders.values()) {
            if (!order.getStatus().equals(status)) continue;
            if (order.getAuthzIDs() == null) continue;

            for (String orderAuthzID : order.getAuthzIDs()) {
                if (!orderAuthzID.equals(authzID)) continue;
                results.add(order);
                break;
            }
        }

        return results;
    }

    @Override
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

    @Override
    public void addOrder(ACMEOrder order) throws Exception {
        orders.put(order.getID(), order);
    }

    @Override
    public void updateOrder(ACMEOrder order) throws Exception {
        orders.put(order.getID(), order);
    }

    @Override
    public void removeExpiredOrders(Date currentTime) throws Exception {
        orders.values().removeIf(
                n -> n.getExpirationTime() != null && !currentTime.before(n.getExpirationTime()));
    }

    @Override
    public ACMEAuthorization getAuthorization(String authzID) throws Exception {
        return authorizations.get(authzID);
    }

    @Override
    public ACMEAuthorization getAuthorizationByChallenge(String challengeID) throws Exception {
        for (ACMEAuthorization authorization : authorizations.values()) {

            if (authorization.getChallenge(challengeID) != null) {
                return authorization;
            }
        }

        return null;
    }

    @Override
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

    @Override
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

    @Override
    public void addAuthorization(ACMEAuthorization authorization) throws Exception {
        authorizations.put(authorization.getID(), authorization);
    }

    @Override
    public void updateAuthorization(ACMEAuthorization authorization) throws Exception {
        authorizations.put(authorization.getID(), authorization);
    }

    @Override
    public void removeExpiredAuthorizations(Date currentTime) throws Exception {
        authorizations.values().removeIf(
                n -> n.getExpirationTime() != null && !currentTime.before(n.getExpirationTime()));
    }

    @Override
    public ACMECertificate getCertificate(String certID) throws Exception {
        return certificates.get(certID);
    }

    @Override
    public void addCertificate(String certID, ACMECertificate certificate) throws Exception {
        certificates.put(certID, certificate);
    }

    @Override
    public void removeExpiredCertificates(Date currentTime) throws Exception {
        certificates.values().removeIf(
                n -> n.getExpirationTime() != null && !currentTime.before(n.getExpirationTime()));
    }
}
