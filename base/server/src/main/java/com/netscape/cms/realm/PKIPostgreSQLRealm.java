//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.realm;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.realm.MessageDigestCredentialHandler;
import org.apache.commons.lang3.StringUtils;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */
public class PKIPostgreSQLRealm extends RealmCommon {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIPostgreSQLRealm.class);

    Properties info;
    String url;

    Properties statements;
    Connection connection;

    MessageDigestCredentialHandler handler;

    @Override
    public void initInternal () throws LifecycleException {

        logger.info("Initializing PostgreSQL realm");

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
                "statements");

        logger.info("Loading statements from " + statementsFilename);

        statements = new Properties();
        try (FileReader reader = new FileReader(statementsFilename)) {
            statements.load(reader);
        }
        catch (Exception e) {
            throw new LifecycleException("Cannot read statements file: "  + statementsFilename,  e);
        }

        for (String name : statements.stringPropertyNames()) {
            String value = statements.getProperty(name);
            logger.info("- " + name + ": " + value);
        }

        logger.info("Initializing credential handler:");
        // https://tomcat.apache.org/tomcat-9.0-doc/config/credentialhandler.html

        String algorithm = info.getProperty("credentialHandler.algorithm");
        if (algorithm == null) {
            // tomcat-digest uses SHA-512 by default
            // https://tomcat.apache.org/tomcat-9.0-doc/realm-howto.html
            algorithm = "SHA-512";
        }
        logger.info("- algorithm: " + algorithm);

        String encoding = info.getProperty("credentialHandler.encoding");
        logger.info("- encoding: " + encoding);

        String iterations = info.getProperty("credentialHandler.iterations");
        logger.info("- iterations: " + iterations);

        String saltLength = info.getProperty("credentialHandler.saltLength");
        logger.info("- salt length: " + saltLength);

        handler = new MessageDigestCredentialHandler();
        try {
            handler.setAlgorithm(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new LifecycleException("No such algorithm: " + algorithm,  e);
        }

        if (encoding != null) {
            handler.setEncoding(encoding);
        }

        if (iterations != null) {
            handler.setIterations(Integer.parseInt(iterations));
        }

        if (saltLength != null) {
            handler.setSaltLength(Integer.parseInt(saltLength));
        }

        String createFile = info.getProperty("dbcreate.file");
        if (createFile != null) {
            try{
                connect();
                setup(createFile);
            } catch (Exception e) {
                throw new LifecycleException("DB creation failed. Creation file: " + createFile, e);
            }
        }
        
    }

    /**
     * This method will create the tables if they do not exist.
     */
    public void setup(String createFile) throws Exception {

        logger.info("Setting up PostgreSQL realm");

        String content = new String(Files.readAllBytes(Paths.get(createFile)));

        String[] stats = content.split(";");
        for (String sql : stats) {
            sql = sql.trim();
            if (StringUtils.isEmpty(sql)) continue;
            logger.info("SQL: " + sql);

            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.executeUpdate();

            } catch (SQLException e) {

                // https://www.postgresql.org/docs/current/errcodes-appendix.html
                String sqlState = e.getSQLState();

                // If table already exists, ignore
                if (!"42P07".equals(sqlState)) {

                    logger.error("Unable to set up PostgreSQL realm: " + e.getMessage());
                    logger.error("SQL state: " + sqlState);

                    throw e;
                }
            }
        }
    }

    /**
     * This method will create the initial connection, validate
     * the current connection, or reestablish the connection if
     * it's closed.
     *
     * TODO: Use connection pool.
     */
    public void connect() throws Exception {

        if (connection == null) { // create the initial connection
            logger.info("Connecting to " + url);
            connection = DriverManager.getConnection(url, info);
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

    public User createUser(ResultSet rs) throws Exception {
        User user = new User();

        String userID = rs.getString("id");
        user.setUserID(userID);

        String fullName = rs.getString("full_name");
        user.setFullName(fullName);

        String password = rs.getString("password");
        user.setPassword(password);

        return user;
    }

    public User getUserByID(String userID) throws Exception {

        logger.info("Getting user " + userID);

        String sql = statements.getProperty("getUserByID");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, userID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                return createUser(rs);
            }
        }
    }

    public String getCertID(X509Certificate cert) {
        return cert.getVersion() + ";"
                + cert.getSerialNumber() + ";"
                + cert.getIssuerDN() + ";"
                + cert.getSubjectDN();
    }

    public User getUserByCertID(String certID) throws Exception {

        logger.info("Getting user for cert " + certID);

        String sql = statements.getProperty("getUserByCertID");
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, certID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                return createUser(rs);
            }
        }
    }

    public List<X509Certificate> getUserCerts(String userID) throws Exception {

        logger.info("Getting certs for user " + userID);

        String sql = statements.getProperty("getUserCerts");
        logger.info("SQL: " + sql);

        List<X509Certificate> results = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, userID);

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    byte[] data = rs.getBytes("data");
                    results.add(new X509CertImpl(data));
                }
            }
        }

        return results;
    }

    public List<String> getUserRoles(String userID) throws Exception {

        logger.info("Getting roles for user " + userID);

        String sql = statements.getProperty("getUserRoles");
        logger.info("SQL: " + sql);

        List<String> roles = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, userID);

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    String rolename = rs.getString("group_id");
                    roles.add(rolename);
                }
            }
        }

        return roles;
    }

    @Override
    public Principal authenticate(String username, String credentials) {

        logger.info("Authenticating user " + username + " with password");

        try {
            connect();

            logger.info("Searching for user " + username);
            User user = getUserByID(username);

            if (user == null) {
                logger.warn("Unable to authenticate user " + username + ": User not found");
                return null;
            }

            logger.info("Validating password for user " + username);
            String storedCredentials = user.getPassword();

            if (!handler.matches(credentials, storedCredentials)) {
                logger.warn("Unable to authenticate user " + username + ": Invalid password");
                return null;
            }

            logger.info("User " + username + " authenticated");

            List<String> roles = getUserRoles(username);
            return new PKIPrincipal(user, null, roles);
        } catch (Exception e) {
            logger.error("Problem to verify user credentials: "+ e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public Principal authenticate(X509Certificate[] certChain) {
        try {
            // sort cert chain from leaf to root
            certChain = Cert.sortCertificateChain(certChain, true);

            // get leaf cert
            X509Certificate cert = certChain[0];
            String certID = getCertID(cert);

            logger.info("Authenticating user with certificate " + certID);

            connect();

            // cert already validated during SSL handshake

            logger.info("Searching for user with certificate " + certID);
            User user = getUserByCertID(certID);

            if (user == null) {
                logger.warn("Unable to authenticate user with certificate " + certID + ": User not found");
                return null;
            }

            logger.info("Searching for matching certificates in user " + user.getUserID());
            List<X509Certificate> certs = getUserCerts(user.getUserID());

            if (certs == null || certs.isEmpty()) {
                logger.warn("Unable to authenticate user " + user.getUserID() + ": User has no certificates");
                return null;
            }

            boolean found = false;
            byte[] data = cert.getEncoded();

            for (X509Certificate c : certs) {
                if (Arrays.equals(data, c.getEncoded())) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                logger.warn("Unable to authenticate user " + user.getUserID() + ": No matching certificate");
                return null;
            }

            logger.info("User " + user.getUserID() + " authenticated");

            List<String> roles = getUserRoles(user.getUserID());
            return new PKIPrincipal(user, null, roles);
        } catch(Exception e) {
            logger.error("Problem to verify the certificate", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void stopInternal() throws LifecycleException{

        logger.info("Shutting down PostgreSQL realm");

        if (connection != null) {
            try {
                connection.close();
            } catch(Exception e) {
                throw new LifecycleException("Cannot close the DB connection: " + e.getMessage(), e);
            }
        }
    }
}
