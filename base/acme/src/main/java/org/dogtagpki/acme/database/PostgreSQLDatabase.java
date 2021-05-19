//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.TimeZone;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMECertificate;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWK;

/**
 * @author Endi S. Dewata
 */
public class PostgreSQLDatabase extends ACMEDatabase {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PostgreSQLDatabase.class);
    public static Calendar UTC = Calendar.getInstance(TimeZone.getTimeZone("UTC"));

    protected Properties info;
    protected String url;

    protected Properties statements;
    protected Connection connection;

    Boolean enabled;
    PostgreSQLConfigMonitor monitor;

    @Override
    public void init() throws Exception {

        logger.info("Initializing PostgreSQL database");

        info = new Properties();
        for (String name : config.getParameterNames()) {
            String value = config.getParameter(name);

            if (!"password".equals(name)) {
                logger.info("- " + name + ": " + value);
            }

            info.put(name, value);
        }

        url = (String) info.remove("url");

        String statementsFilename = info.getProperty(
                "statements",
                "/usr/share/pki/acme/database/postgresql/statements.conf");

        logger.info("Loading statements from " + statementsFilename);

        statements = new Properties();
        try (FileReader reader = new FileReader(statementsFilename)) {
            statements.load(reader);
        }

        for (String name : statements.stringPropertyNames()) {
            String value = statements.getProperty(name);
            logger.info("- " + name + ": " + value);
        }

        String monitorEnabled = config.getParameter("monitor.enabled");
        logger.info("- monitor enabled: " + monitorEnabled);

        if ("true".equals(monitorEnabled)) {

            monitor = new PostgreSQLConfigMonitor();
            monitor.setDatabase(this);

            String monitorInterval = config.getParameter("monitor.interval");
            if (monitorInterval == null) {
                monitorInterval = PostgreSQLConfigMonitor.DEFAULT_INTERVAL + "";
            }
            logger.info("- monitor interval (minutes): " + monitorInterval);

            if (monitorInterval != null) {
                monitor.setInterval(Integer.parseInt(monitorInterval));
            }

            new Thread(monitor, "PostgreSQLConfigMonitor").start();
        }
    }

    /**
     * This method will create the initial connection, validate
     * the current connection, or reestablish the connection if
     * it's closed.
     *
     * This method should only be called by methods implementing
     * ACMEDatabase.
     *
     * TODO: Use connection pool.
     */
    public void connect() throws Exception {

        if (connection == null) { // create the initial connection
            logger.info("Connecting to " + url);
            connection = DriverManager.getConnection(url, info);
            setup();
            return;
        }

        // validate the current connection
        try (Statement st = connection.createStatement();
            ResultSet rs = st.executeQuery("SELECT 1")) {

        } catch (SQLException e) {

            if (connection.isClosed()) { // reestablish the connection
                logger.info("Reconnecting to " + url);
                connection = DriverManager.getConnection(url, info);
                return;
            }

            logger.error("Unable to access database: " + e.getMessage());

            // https://www.postgresql.org/docs/current/errcodes-appendix.html
            logger.error("SQL state: " + e.getSQLState());

            throw e;
        }
    }

    /**
     * This method will create the tables if they do not exist.
     */
    public void setup() throws Exception {

        logger.info("Setting up database");

        String filename = "/usr/share/pki/acme/database/postgresql/create.sql";
        String content = new String(Files.readAllBytes(Paths.get(filename)));

        String[] statements = content.split(";");
        for (String sql : statements) {
            sql = sql.trim();
            if (StringUtils.isEmpty(sql)) continue;
            logger.info("SQL: " + sql);

            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.executeUpdate();

            } catch (SQLException e) {

                // https://www.postgresql.org/docs/current/errcodes-appendix.html
                String sqlState = e.getSQLState();

                // If table already exists, ignore
                if ("42P07".equals(sqlState)) continue;

                logger.error("Unable to set up database: " + e.getMessage());
                logger.error("SQL state: " + sqlState);

                throw e;
            }
        }
    }

    String getConfig(String id) throws Exception {

        logger.info("Getting config " + id);

        String sql = statements.getProperty("getConfig");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, id);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                return rs.getString("value");
            }
        }
    }

    void addConfig(String id, String value) throws Exception {

        logger.info("Setting config " + id + ": " + value);

        String sql = statements.getProperty("addConfig");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setString(2, value);
            ps.executeUpdate();
        }
    }

    int updateConfig(String id, String value) throws Exception {

        logger.info("Updating config " + id + ": " + value);

        String sql = statements.getProperty("updateConfig");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, value);
            ps.setString(2, id);
            return ps.executeUpdate();
        }
    }

    void removeConfig(String id) throws Exception {

        logger.info("Removing config " + id);

        String sql = statements.getProperty("removeConfig");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.executeUpdate();
        }
    }

    void setConfig(String id, String value) throws Exception {

        if (value == null) {
            removeConfig(id);
            return;
        }

        int updatedRows = updateConfig(id, value);
        if (updatedRows > 0) return;

        addConfig(id, value);
    }

    @Override
    public Boolean getEnabled() throws Exception {

        // If monitor is not enabled, get config from database on each request.
        // Otherwise, return the config stored in memory which is updated by
        // PostgreSQLConfigMonitor.

        if (monitor == null) {

            connect();

            String value = getConfig("enabled");
            enabled = value == null ? null : Boolean.valueOf(value);
        }

        return enabled;
    }

    @Override
    public void setEnabled(Boolean enabled) throws Exception {

        connect();

        String value = enabled == null ? null : enabled.toString();
        setConfig("enabled", value);

        this.enabled = enabled;
    }

    private ACMENonce getNonce(String nonceID) throws Exception {

        logger.info("Getting nonce " + nonceID);

        String sql = statements.getProperty("getNonce");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, nonceID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                ACMENonce nonce = new ACMENonce();
                nonce.setID(nonceID);

                Timestamp created = rs.getTimestamp("created");
                nonce.setCreationTime(new Date(created.getTime()));

                Timestamp expires = rs.getTimestamp("expires");
                nonce.setExpirationTime(new Date(expires.getTime()));

                return nonce;
            }
        }
    }

    @Override
    public void addNonce(ACMENonce nonce) throws Exception {

        connect();

        String nonceID = nonce.getID();
        logger.info("Adding nonce " + nonceID);

        String sql = statements.getProperty("addNonce");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, nonceID);

            Date creationTime = nonce.getCreationTime();
            ps.setTimestamp(2, new Timestamp(creationTime.getTime()), UTC);

            Date expirationTime = nonce.getExpirationTime();
            ps.setTimestamp(3, new Timestamp(expirationTime.getTime()), UTC);

            ps.executeUpdate();
        }
    }

    @Override
    public ACMENonce removeNonce(String nonceID) throws Exception {

        connect();

        ACMENonce nonce = getNonce(nonceID);
        if (nonce == null) return null;

        deleteNonce(nonceID);
        return nonce;
    }

    private void deleteNonce(String nonceID) throws Exception {

        logger.info("Removing nonce " + nonceID);

        String sql = statements.getProperty("removeNonce");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, nonceID);
            ps.executeUpdate();
        }
    }

    @Override
    public void removeExpiredNonces(Date currentTime) throws Exception {

        connect();

        logger.info("Getting expired nonces");

        Collection<String> nonceIDs = getExpiredNonceIDs(currentTime);

        logger.info("Removing expired nonces");

        for (String nonceID : nonceIDs) {
            deleteNonce(nonceID);
        }
    }

    private Collection<String> getExpiredNonceIDs(Date currentTime) throws Exception {

        String sql = statements.getProperty("getExpiredNonceIDs");
        logger.info("SQL: " + sql);

        Collection<String> nonces = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setTimestamp(1, new Timestamp(currentTime.getTime()), UTC);

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    String nonceID = rs.getString("id");
                    nonces.add(nonceID);
                }
            }
        }

        return nonces;
    }

    @Override
    public ACMEAccount getAccount(String accountID) throws Exception {

        connect();

        logger.info("Getting account " + accountID);

        String sql = statements.getProperty("getAccount");
        logger.info("SQL: " + sql);

        ACMEAccount account = new ACMEAccount();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, accountID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                account.setID(accountID);

                Timestamp created = rs.getTimestamp("created");
                account.setCreationTime(new Date(created.getTime()));

                account.setStatus(rs.getString("status"));

                String jwk = rs.getString("jwk");
                account.setJWK(JWK.fromJSON(jwk));
            }
        }

        getAccountContacts(account);

        return account;
    }

    private void getAccountContacts(ACMEAccount account) throws Exception {

        String accountID = account.getID();
        logger.info("Getting contacts for " + accountID);

        String sql = statements.getProperty("getAccountContacts");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, accountID);

            try (ResultSet rs = ps.executeQuery()) {

                List<String> contacts = new ArrayList<>();

                while (rs.next()) {
                    String contact = rs.getString("contact");
                    contacts.add(contact);
                }

                if (!contacts.isEmpty()) {
                    account.setContact(contacts.toArray(new String[contacts.size()]));
                }
            }
        }
    }

    @Override
    public void addAccount(ACMEAccount account) throws Exception {

        connect();

        String accountID = account.getID();
        logger.info("Adding account " + accountID);

        String sql = statements.getProperty("addAccount");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, accountID);

            Date creationTime = account.getCreationTime();
            ps.setTimestamp(2, creationTime == null ? null : new Timestamp(creationTime.getTime()), UTC);

            ps.setString(3, account.getStatus());
            ps.setString(4, account.getJWK().toJSON());

            ps.executeUpdate();
        }

        addAccountContacts(account);
    }

    @Override
    public void updateAccount(ACMEAccount account) throws Exception {

        connect();

        String accountID = account.getID();
        logger.info("Updating account " + accountID);

        String sql = statements.getProperty("updateAccount");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, account.getStatus());
            ps.setString(2, accountID);

            ps.executeUpdate();
        }

        removeAccountContacts(accountID);
        addAccountContacts(account);
    }

    private void addAccountContacts(ACMEAccount account) throws Exception {

        String[] contacts = account.getContact();
        if (contacts == null) return;

        String accountID = account.getID();
        logger.info("Adding contacts for account " + accountID);

        String sql = statements.getProperty("addAccountContacts");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            for (String contact : contacts) {

                ps.setString(1, accountID);
                ps.setString(2, contact);

                ps.executeUpdate();
            }
        }
    }

    private void removeAccountContacts(String accountID) throws Exception {

        logger.info("Removing contacts for account " + accountID);

        String sql = statements.getProperty("removeAccountContacts");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, accountID);

            ps.executeUpdate();
        }
    }

    @Override
    public ACMEOrder getOrder(String orderID) throws Exception {

        connect();

        logger.info("Getting order " + orderID);

        String sql = statements.getProperty("getOrder");
        logger.info("SQL: " + sql);

        ACMEOrder order = new ACMEOrder();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                order.setID(orderID);
                order.setAccountID(rs.getString("account_id"));

                Timestamp created = rs.getTimestamp("created");
                order.setCreationTime(created == null ? null : new Date(created.getTime()));

                order.setStatus(rs.getString("status"));

                Timestamp expires = rs.getTimestamp("expires");
                order.setExpirationTime(expires == null ? null : new Date(expires.getTime()));

                Timestamp notBefore = rs.getTimestamp("not_before");
                order.setNotBeforeTime(notBefore == null ? null : new Date(notBefore.getTime()));

                Timestamp notAfter = rs.getTimestamp("not_after");
                order.setNotAfterTime(notAfter == null ? null : new Date(notAfter.getTime()));

                order.setCertID(rs.getString("cert_id"));
            }
        }

        getOrderIdentifiers(order);
        getOrderAuthorizations(order);

        return order;
    }

    @Override
    public Collection<ACMEOrder> getOrdersByAccount(String accountID) throws Exception {

        connect();

        logger.info("Getting orders for account " + accountID);

        String sql = statements.getProperty("getOrdersByAccount");
        logger.info("SQL: " + sql);

        Collection<ACMEOrder> orders = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, accountID);

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    ACMEOrder order = new ACMEOrder();
                    order.setID(rs.getString("id"));
                    order.setAccountID(accountID);

                    Timestamp created = rs.getTimestamp("created");
                    order.setCreationTime(created == null ? null : new Date(created.getTime()));

                    order.setStatus(rs.getString("status"));

                    Timestamp expires = rs.getTimestamp("expires");
                    order.setExpirationTime(expires == null ? null : new Date(expires.getTime()));

                    Timestamp notBefore = rs.getTimestamp("not_before");
                    order.setNotBeforeTime(notBefore == null ? null : new Date(notBefore.getTime()));

                    Timestamp notAfter = rs.getTimestamp("not_after");
                    order.setNotAfterTime(notAfter == null ? null : new Date(notAfter.getTime()));

                    order.setCertID(rs.getString("cert_id"));

                    getOrderIdentifiers(order);
                    getOrderAuthorizations(order);

                    orders.add(order);
                }
            }
        }

        return orders;
    }

    @Override
    public Collection<ACMEOrder> getOrdersByAuthorizationAndStatus(String authzID, String status)
            throws Exception {

        connect();

        logger.info("Getting " + status + " orders for authorization " + authzID);

        String sql = statements.getProperty("getOrdersByAuthorizationAndStatus");
        logger.info("SQL: " + sql);

        Collection<ACMEOrder> orders = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, authzID);
            ps.setString(2, status);

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    ACMEOrder order = new ACMEOrder();
                    order.setID(rs.getString("id"));
                    order.setAccountID(rs.getString("account_id"));

                    Timestamp created = rs.getTimestamp("created");
                    order.setCreationTime(created == null ? null : new Date(created.getTime()));

                    order.setStatus(rs.getString("status"));

                    Timestamp expires = rs.getTimestamp("expires");
                    order.setExpirationTime(expires == null ? null : new Date(expires.getTime()));

                    Timestamp notBefore = rs.getTimestamp("not_before");
                    order.setNotBeforeTime(notBefore == null ? null : new Date(notBefore.getTime()));

                    Timestamp notAfter = rs.getTimestamp("not_after");
                    order.setNotAfterTime(notAfter == null ? null : new Date(notAfter.getTime()));

                    order.setCertID(rs.getString("cert_id"));

                    getOrderIdentifiers(order);
                    getOrderAuthorizations(order);

                    orders.add(order);
                }
            }
        }

        return orders;
    }

    @Override
    public ACMEOrder getOrderByCertificate(String certID) throws Exception {

        connect();

        logger.info("Getting order for certificate " + certID);

        String sql = statements.getProperty("getOrderByCertificate");
        logger.info("SQL: " + sql);

        ACMEOrder order = new ACMEOrder();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, certID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    // no order found
                    return null;
                }

                // order found

                order.setID(rs.getString("id"));
                order.setAccountID(rs.getString("account_id"));

                Timestamp created = rs.getTimestamp("created");
                order.setCreationTime(created == null ? null : new Date(created.getTime()));

                order.setStatus(rs.getString("status"));

                Timestamp expires = rs.getTimestamp("expires");
                order.setExpirationTime(expires == null ? null : new Date(expires.getTime()));

                Timestamp notBefore = rs.getTimestamp("not_before");
                order.setNotBeforeTime(notBefore == null ? null : new Date(notBefore.getTime()));

                Timestamp notAfter = rs.getTimestamp("not_after");
                order.setNotAfterTime(notAfter == null ? null : new Date(notAfter.getTime()));

                order.setCertID(certID);
            }
        }

        getOrderIdentifiers(order);
        getOrderAuthorizations(order);

        return order;
    }

    private Collection<String> getExpiredOrderIDs(Date currentTime) throws Exception {

        String sql = statements.getProperty("getExpiredOrderIDs");
        logger.info("SQL: " + sql);

        Collection<String> orderIDs = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setTimestamp(1, new Timestamp(currentTime.getTime()), UTC);

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    String orderID = rs.getString("id");
                    orderIDs.add(orderID);
                }
            }
        }

        return orderIDs;
    }

    private void getOrderIdentifiers(ACMEOrder order) throws Exception {

        String orderID = order.getID();
        logger.info("Getting identifiers for order " + orderID);

        String sql = statements.getProperty("getOrderIdentifiers");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);

            try (ResultSet rs = ps.executeQuery()) {

                List<ACMEIdentifier> identifiers = new ArrayList<>();

                while (rs.next()) {
                    ACMEIdentifier identifier = new ACMEIdentifier();
                    identifier.setType(rs.getString("type"));
                    identifier.setValue(rs.getString("value"));
                    identifiers.add(identifier);
                }

                if (!identifiers.isEmpty()) {
                    order.setIdentifiers(identifiers.toArray(new ACMEIdentifier[identifiers.size()]));
                }
            }
        }
    }

    private void getOrderAuthorizations(ACMEOrder order) throws Exception {

        String orderID = order.getID();
        logger.info("Getting authorizations for order " + orderID);

        String sql = statements.getProperty("getOrderAuthorizations");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);

            try (ResultSet rs = ps.executeQuery()) {

                List<String> authzIDs = new ArrayList<>();

                while (rs.next()) {
                    String authzID = rs.getString("authz_id");
                    authzIDs.add(authzID);
                }

                if (!authzIDs.isEmpty()) {
                    order.setAuthzIDs(authzIDs.toArray(new String[authzIDs.size()]));
                }
            }
        }
    }

    @Override
    public void addOrder(ACMEOrder order) throws Exception {

        connect();

        String orderID = order.getID();
        logger.info("Adding order " + orderID);

        String sql = statements.getProperty("addOrder");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, orderID);
            ps.setString(2, order.getAccountID());

            Date creationTime = order.getCreationTime();
            ps.setTimestamp(3, creationTime == null ? null : new Timestamp(creationTime.getTime()), UTC);

            ps.setString(4, order.getStatus());

            Date expirationTime = order.getExpirationTime();
            ps.setTimestamp(5, expirationTime == null ? null : new Timestamp(expirationTime.getTime()), UTC);

            Date notBefore = order.getNotBeforeTime();
            ps.setTimestamp(6, notBefore == null ? null : new Timestamp(notBefore.getTime()), UTC);

            Date notAfter = order.getNotAfterTime();
            ps.setTimestamp(7, notAfter == null ? null : new Timestamp(notAfter.getTime()), UTC);

            ps.setString(8, order.getCertID());

            ps.executeUpdate();
        }

        addOrderIdentifiers(order);
        addOrderAuthorizations(order);
    }

    private void addOrderIdentifiers(ACMEOrder order) throws Exception {

        ACMEIdentifier[] identifiers = order.getIdentifiers();
        if (identifiers == null) return;

        String orderID = order.getID();
        logger.info("Adding identifiers for order " + orderID);

        String sql = statements.getProperty("addOrderIdentifiers");
        logger.info("SQL: " + sql);

        for (ACMEIdentifier identifier : identifiers) {

            try (PreparedStatement ps = connection.prepareStatement(sql)) {

                ps.setString(1, orderID);
                ps.setString(2, identifier.getType());
                ps.setString(3, identifier.getValue());

                ps.executeUpdate();
            }
        }
    }

    private void removeOrderIdentifiers(String orderID) throws Exception {

        logger.info("Removing identifiers for order " + orderID);

        String sql = statements.getProperty("removeOrderIdentifiers");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);
            ps.executeUpdate();
        }
    }

    private void addOrderAuthorizations(ACMEOrder order) throws Exception {

        String[] authzIDs = order.getAuthzIDs();
        if (authzIDs == null) return;

        String orderID = order.getID();
        logger.info("Adding authorizations for order " + orderID);

        String sql = statements.getProperty("addOrderAuthorizations");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            for (String authzID : authzIDs) {

                ps.setString(1, orderID);
                ps.setString(2, authzID);

                ps.executeUpdate();
            }
        }
    }

    private void removeOrderAuthorizations(String orderID) throws Exception {

        logger.info("Removing authorizations for order " + orderID);

        String sql = statements.getProperty("removeOrderAuthorizations");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);
            ps.executeUpdate();
        }
    }

    @Override
    public void updateOrder(ACMEOrder order) throws Exception {

        connect();

        String orderID = order.getID();
        logger.info("Updating order " + orderID);

        String sql = statements.getProperty("updateOrder");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, order.getStatus());
            ps.setString(2, order.getCertID());

            Date expirationTime = order.getExpirationTime();
            ps.setTimestamp(3, expirationTime == null ? null : new Timestamp(expirationTime.getTime()), UTC);

            ps.setString(4, orderID);

            ps.executeUpdate();
        }
    }

    private void removeOrder(String orderID) throws Exception {

        removeOrderIdentifiers(orderID);
        removeOrderAuthorizations(orderID);

        logger.info("Removing order " + orderID);

        String sql = statements.getProperty("removeOrder");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);
            ps.executeUpdate();
        }
    }

    @Override
    public void removeExpiredOrders(Date currentTime) throws Exception {

        connect();

        logger.info("Getting expired order IDs");

        Collection<String> orderIDs = getExpiredOrderIDs(currentTime);

        logger.info("Removing expired orders");

        for (String orderID : orderIDs) {
            removeOrder(orderID);
        }
    }

    @Override
    public ACMEAuthorization getAuthorization(String authzID) throws Exception {

        connect();

        logger.info("Getting authorization " + authzID);

        String sql = statements.getProperty("getAuthorization");
        logger.info("SQL: " + sql);

        ACMEAuthorization authorization = new ACMEAuthorization();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, authzID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                authorization.setID(authzID);
                authorization.setAccountID(rs.getString("account_id"));

                Timestamp created = rs.getTimestamp("created");
                authorization.setCreationTime(created == null ? null : new Date(created.getTime()));

                authorization.setStatus(rs.getString("status"));

                Timestamp expires = rs.getTimestamp("expires");
                authorization.setExpirationTime(expires == null ? null : new Date(expires.getTime()));

                ACMEIdentifier identifier = new ACMEIdentifier();
                identifier.setType(rs.getString("identifier_type"));
                identifier.setValue(rs.getString("identifier_value"));
                authorization.setIdentifier(identifier);

                boolean wildcard = rs.getBoolean("wildcard");
                authorization.setWildcard(wildcard ? true : null);
            }
        }

        getAuthorizationChallenges(authorization);

        return authorization;
    }

    @Override
    public ACMEAuthorization getAuthorizationByChallenge(String challengeID) throws Exception {

        connect();

        logger.info("Getting authorization for challenge " + challengeID);

        String sql = statements.getProperty("getAuthorizationByChallenge");
        logger.info("SQL: " + sql);

        ACMEAuthorization authorization = new ACMEAuthorization();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, challengeID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                authorization.setID(rs.getString("id"));
                authorization.setAccountID(rs.getString("account_id"));

                Timestamp created = rs.getTimestamp("created");
                authorization.setCreationTime(created == null ? null : new Date(created.getTime()));

                authorization.setStatus(rs.getString("status"));

                Timestamp expires = rs.getTimestamp("expires");
                authorization.setExpirationTime(expires == null ? null : new Date(expires.getTime()));

                ACMEIdentifier identifier = new ACMEIdentifier();
                identifier.setType(rs.getString("identifier_type"));
                identifier.setValue(rs.getString("identifier_value"));
                authorization.setIdentifier(identifier);

                boolean wildcard = rs.getBoolean("wildcard");
                authorization.setWildcard(wildcard ? true : null);
            }
        }

        getAuthorizationChallenges(authorization);

        return authorization;
    }

    private Collection<String> getExpiredAuthorizationIDs(Date currentTime) throws Exception {

        String sql = statements.getProperty("getExpiredAuthorizationIDs");
        logger.info("SQL: " + sql);

        Collection<String> authzIDs = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setTimestamp(1, new Timestamp(currentTime.getTime()), UTC);

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    String authzID = rs.getString("id");
                    authzIDs.add(authzID);
                }
            }
        }

        return authzIDs;
    }

    @Override
    public Collection<ACMEAuthorization> getRevocationAuthorizations(String accountID, Date time) throws Exception {

        connect();

        logger.info("Getting authorizations for account " + accountID);

        String sql = statements.getProperty("getRevocationAuthorizations");
        logger.info("SQL: " + sql);

        Collection<ACMEAuthorization> authorizations = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, accountID);
            ps.setTimestamp(2, new Timestamp(time.getTime()), UTC);

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {

                    ACMEAuthorization authorization = new ACMEAuthorization();

                    authorization.setID(rs.getString("id"));
                    authorization.setAccountID(accountID);

                    Timestamp created = rs.getTimestamp("created");
                    authorization.setCreationTime(created == null ? null : new Date(created.getTime()));

                    authorization.setStatus(rs.getString("status"));

                    Timestamp expires = rs.getTimestamp("expires");
                    authorization.setExpirationTime(expires == null ? null : new Date(expires.getTime()));

                    ACMEIdentifier identifier = new ACMEIdentifier();
                    identifier.setType(rs.getString("identifier_type"));
                    identifier.setValue(rs.getString("identifier_value"));
                    authorization.setIdentifier(identifier);

                    boolean wildcard = rs.getBoolean("wildcard");
                    authorization.setWildcard(wildcard ? true : null);

                    getAuthorizationChallenges(authorization);

                    authorizations.add(authorization);
                }
            }
        }

        return authorizations;
    }

    private void getAuthorizationChallenges(ACMEAuthorization authorization) throws Exception {

        String authzID = authorization.getID();
        logger.info("Getting challenges for authorization " + authzID);

        String sql = statements.getProperty("getAuthorizationChallenges");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, authzID);

            try (ResultSet rs = ps.executeQuery()) {

                List<ACMEChallenge> challenges = new ArrayList<>();

                while (rs.next()) {
                    ACMEChallenge challenge = new ACMEChallenge();

                    challenge.setID(rs.getString("id"));
                    challenge.setAuthzID(authzID);
                    challenge.setType(rs.getString("type"));
                    challenge.setToken(rs.getString("token"));
                    challenge.setStatus(rs.getString("status"));

                    Timestamp validated = rs.getTimestamp("validated");
                    challenge.setValidationTime(validated == null ? null : new Date(validated.getTime()));

                    challenges.add(challenge);
                }

                if (!challenges.isEmpty()) {
                    authorization.setChallenges(challenges);
                }
            }
        }
    }

    @Override
    public void addAuthorization(ACMEAuthorization authorization) throws Exception {

        connect();

        String authzID = authorization.getID();
        logger.info("Adding authorization " + authzID);

        String sql = statements.getProperty("addAuthorization");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, authzID);
            ps.setString(2, authorization.getAccountID());

            Date creationTime = authorization.getCreationTime();
            ps.setTimestamp(3, creationTime == null ? null : new Timestamp(creationTime.getTime()), UTC);

            ps.setString(4, authorization.getStatus());

            Date expirationTime = authorization.getExpirationTime();
            ps.setTimestamp(5, expirationTime == null ? null : new Timestamp(expirationTime.getTime()), UTC);

            ACMEIdentifier identifier = authorization.getIdentifier();
            ps.setString(6, identifier.getType());
            ps.setString(7, identifier.getValue());

            Boolean wildcard = authorization.getWildcard();
            ps.setBoolean(8, wildcard == null ? false : wildcard);

            ps.executeUpdate();
        }

        addAuthorizationChallenges(authorization);
    }

    @Override
    public void updateAuthorization(ACMEAuthorization authorization) throws Exception {

        connect();

        String authzID = authorization.getID();
        logger.info("Updating authorization " + authzID);

        String sql = statements.getProperty("updateAuthorization");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, authorization.getStatus());

            Date expirationTime = authorization.getExpirationTime();
            ps.setTimestamp(2, expirationTime == null ? null : new Timestamp(expirationTime.getTime()), UTC);

            ps.setString(3, authzID);

            ps.executeUpdate();
        }

        removeAuthorizationChallenges(authzID);
        addAuthorizationChallenges(authorization);
    }

    private void removeAuthorizationChallenges(String authzID) throws Exception {

        logger.info("Removing challenges for authorization " + authzID);

        String sql = statements.getProperty("removeAuthorizationChallenges");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, authzID);
            ps.executeUpdate();
        }
    }

    private void addAuthorizationChallenges(ACMEAuthorization authorization) throws Exception {

        Collection<ACMEChallenge> challenges = authorization.getChallenges();
        if (challenges == null) return;

        String authzID = authorization.getID();
        logger.info("Adding challenges for authorization " + authzID);

        String sql = statements.getProperty("addAuthorizationChallenges");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            for (ACMEChallenge challenge : challenges) {

                ps.setString(1, challenge.getID());
                ps.setString(2, authzID);
                ps.setString(3, challenge.getType());
                ps.setString(4, challenge.getToken());
                ps.setString(5, challenge.getStatus());

                Date validationTime = challenge.getValidationTime();
                ps.setTimestamp(6, validationTime == null ? null : new Timestamp(validationTime.getTime()), UTC);

                ps.executeUpdate();
            }
        }
    }

    private void removeAuthorization(String authzID) throws Exception {

        removeAuthorizationChallenges(authzID);

        logger.info("Removing authorization " + authzID);

        String sql = statements.getProperty("removeAuthorization");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, authzID);
            ps.executeUpdate();
        }
    }

    @Override
    public void removeExpiredAuthorizations(Date currentTime) throws Exception {

        connect();

        logger.info("Getting expired authorization IDs");

        Collection<String> authzIDs = getExpiredAuthorizationIDs(currentTime);

        logger.info("Removing expired authorization");

        for (String authzID : authzIDs) {
            removeAuthorization(authzID);
        }
    }

    @Override
    public ACMECertificate getCertificate(String certID) throws Exception {

        connect();

        logger.info("Getting certificate " + certID);

        String sql = statements.getProperty("getCertificate");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, certID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                ACMECertificate certificate = new ACMECertificate();
                certificate.setID(certID);

                Timestamp created = rs.getTimestamp("created");
                certificate.setCreationTime(created == null ? null : new Date(created.getTime()));

                certificate.setData(rs.getBytes("data"));

                Timestamp expires = rs.getTimestamp("expires");
                certificate.setExpirationTime(expires == null ? null : new Date(expires.getTime()));

                return certificate;
            }
        }
    }

    private Collection<String> getExpiredCertificateIDs(Date currentTime) throws Exception {

        String sql = statements.getProperty("getExpiredCertificateIDs");
        logger.info("SQL: " + sql);

        Collection<String> certIDs = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setTimestamp(1, new Timestamp(currentTime.getTime()), UTC);

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    String certID = rs.getString("id");
                    certIDs.add(certID);
                }
            }
        }

        return certIDs;
    }

    @Override
    public void addCertificate(String certID, ACMECertificate certificate) throws Exception {

        connect();

        logger.info("Adding certificate " + certID);

        String sql = statements.getProperty("addCertificate");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, certID);

            Date creationTime = certificate.getCreationTime();
            ps.setTimestamp(2, creationTime == null ? null : new Timestamp(creationTime.getTime()), UTC);

            ps.setBytes(3, certificate.getData());

            Date expirationTime = certificate.getExpirationTime();
            ps.setTimestamp(4, expirationTime == null ? null : new Timestamp(expirationTime.getTime()), UTC);

            ps.executeUpdate();
        }
    }

    private void removeCertificate(String certID) throws Exception {

        logger.info("Removing certificate " + certID);

        String sql = statements.getProperty("removeCertificate");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, certID);
            ps.executeUpdate();
        }
    }

    @Override
    public void removeExpiredCertificates(Date currentTime) throws Exception {

        connect();

        logger.info("Getting expired certificaate IDs");

        Collection<String> certIDs = getExpiredCertificateIDs(currentTime);

        logger.info("Removing expired certificates");

        for (String certID : certIDs) {
            removeCertificate(certID);
        }
    }

    @Override
    public void close() throws Exception {

        if (monitor != null) {
            monitor.stop();
        }

        if (connection != null) {
            connection.close();
        }
    }
}
