//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.realm;

import java.net.URI;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PlainPasswordFile;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;

/**
 * @author Endi S. Dewata
 */
public class LDAPRealm extends ACMERealm {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LDAPRealm.class);

    String usersDN;
    String groupsDN;

    PKISocketConfig socketConfig;
    LDAPConnectionConfig connConfig;
    LDAPAuthenticationConfig authConfig;
    LdapBoundConnFactory connFactory;

    @Override
    public void init() throws Exception {

        logger.info("Initializing LDAP realm");

        EngineConfig cs;
        IPasswordStore ps;
        LDAPConfig ldapConfig;

        String configFile = config.getParameter("configFile");

        if (configFile == null) {

            logger.info("Loading LDAP realm config from realm.conf");

            cs = new EngineConfig();
            ps = new PlainPasswordFile();
            ldapConfig = new LDAPConfig(null);

            for (String name : config.getParameterNames()) {
                String value = config.getParameter(name);

                if (name.equals("usersDN")) {
                    continue;

                } else if (name.equals("groupsDN")) {
                    continue;

                } else if (name.equals("url")) {
                    logger.info("- URL: " + value);

                    URI url = new URI(value);
                    String host = url.getHost();
                    String port = "" + url.getPort();

                    String protocol = url.getScheme();
                    String secureConn;
                    if ("ldap".equals(protocol)) {
                        secureConn = "false";
                    } else if ("ldaps".equals(protocol)) {
                        secureConn = "true";
                    } else {
                        throw new Exception("Unsupported LDAP protocol: " + protocol);
                    }

                    ldapConfig.put("ldapconn.host", host);
                    ldapConfig.put("ldapconn.port", port);
                    ldapConfig.put("ldapconn.secureConn", secureConn);

                } else if (name.equals("authType")) {
                    logger.info("- authentication type: " + value);
                    ldapConfig.put("ldapauth.authtype", value);

                } else if (name.equals("bindDN")) {
                    logger.info("- bind DN: " + value);
                    ldapConfig.put("ldapauth.bindDN", value);

                } else if (name.equals("bindPassword")) {
                    ldapConfig.put("ldapauth.bindPassword", value);

                } else if (name.equals("nickname")) {
                    logger.info("- nickname: " + value);
                    ldapConfig.put("ldapauth.clientCertNickname", value);

                } else if (name.equals("minConns")) {
                    logger.info("- " + name + ": " + value);
                    ldapConfig.put(name, value);

                } else if (name.equals("maxConns")) {
                    logger.info("- " + name + ": " + value);
                    ldapConfig.put(name, value);

                } else if (name.equals("maxResults")) {
                    logger.info("- " + name + ": " + value);
                    ldapConfig.put(name, value);

                } else if (name.equals("errorIfDown")) {
                    logger.info("- " + name + ": " + value);
                    ldapConfig.put(name, value);

                } else if (name.startsWith("ldapauth.")) {
                    ldapConfig.put(name, value);
                    logger.info("- " + name + ": " + value);

                } else if (name.startsWith("ldapconn.")) {
                    logger.info("- " + name + ": " + value);
                    ldapConfig.put(name, value);

                } else {
                    cs.put(name, value);
                }
            }

        } else {

            logger.info("Loading LDAP realm config from " + configFile);

            cs = new EngineConfig(new FileConfigStore(configFile));
            cs.load();

            ps = IPasswordStore.create(cs.getPasswordStoreConfig());
            ldapConfig = cs.getInternalDBConfig();
        }

        socketConfig = cs.getSocketConfig();
        connConfig = ldapConfig.getConnectionConfig();
        authConfig = ldapConfig.getAuthenticationConfig();

        usersDN = config.getParameter("usersDN");
        logger.info("- users DN: " + usersDN);

        groupsDN = config.getParameter("groupsDN");
        logger.info("- groups DN: " + groupsDN);

        connFactory = new LdapBoundConnFactory("LDAPRealm");
        connFactory.init(socketConfig, ldapConfig, ps);
    }

    public User createUser(LDAPEntry entry) throws Exception {
        User user = new User();

        user.setUserDN(entry.getDN());

        LDAPAttribute uidAttr = entry.getAttribute("uid");
        String uid = uidAttr.getStringValueArray()[0];
        user.setUserID(uid);

        LDAPAttribute cnAttr = entry.getAttribute("cn");
        if (cnAttr != null) {
            user.setFullName(cnAttr.getStringValues().nextElement());
        }

        LDAPAttribute mailAttr = entry.getAttribute("mail");
        if (mailAttr != null) {
            user.setEmail(mailAttr.getStringValues().nextElement());
        }

        LDAPAttribute phoneAttr = entry.getAttribute("telephoneNumber");
        if (phoneAttr != null) {
            user.setPhone(phoneAttr.getStringValues().nextElement());
        }

        LDAPAttribute userCertificate = entry.getAttribute("userCertificate");
        if (userCertificate != null) {
            byte[][] binCerts = userCertificate.getByteValueArray();
            X509Certificate[] certs = new X509Certificate[binCerts.length];
            for (int i = 0; i < binCerts.length; i++) {
                certs[i] = new X509CertImpl(binCerts[i]);
            }
            user.setX509Certificates(certs);
        }

        return user;
    }

    public List<String> getUserRoles(LDAPConnection conn, String userDN) throws Exception {

        List<String> roles = new ArrayList<>();
        String filter = "(uniqueMember=" + userDN + ")";

        logger.info("LDAP search:");
        logger.info("- base DN: " + groupsDN);
        logger.info("- filter: " + filter);

        LDAPSearchResults results = conn.search(
                groupsDN,
                LDAPConnection.SCOPE_ONE,
                filter,
                null, /* get all attributes*/
                false /* return attribute values */
        );

        logger.info("User roles:");
        while (results.hasMoreElements()) {
            LDAPEntry groupEntry = results.next();
            logger.info("- " + groupEntry.getDN());

            LDAPAttribute cnAttr = groupEntry.getAttribute("cn");
            String role = cnAttr.getStringValues().nextElement();
            roles.add(role);
        }

        return roles;
    }

    public User findUserByUsername(LDAPConnection conn, String username) throws Exception {

        String filter = "(uid=" + username + ")";

        logger.info("LDAP search:");
        logger.info("- base DN: " + usersDN);
        logger.info("- filter: " + filter);

        LDAPSearchResults results = conn.search(
                usersDN,
                LDAPConnection.SCOPE_ONE,
                filter,
                null, /* get all attributes*/
                false /* return attribute values */
        );

        if (!results.hasMoreElements()) {
            return null;
        }

        LDAPEntry entry = results.next();
        logger.info("User: " + entry.getDN());

        return createUser(entry);
    }

    public String getCertID(X509Certificate cert) {
        return cert.getVersion() + ";"
                + cert.getSerialNumber() + ";"
                + cert.getIssuerX500Principal() + ";"
                + cert.getSubjectX500Principal();
    }

    public User findUserByCertID(LDAPConnection conn, String certID) throws Exception {

        String filter = "(description=" + certID + ")";

        logger.info("LDAP search:");
        logger.info("- base DN: " + usersDN);
        logger.info("- filter: " + filter);

        LDAPSearchResults results = conn.search(
                usersDN,
                LDAPConnection.SCOPE_ONE,
                filter,
                null, /* get all attributes*/
                false /* return attribute values */
        );

        if (!results.hasMoreElements()) {
            return null;
        }

        LDAPEntry entry = results.next();
        logger.info("User: " + entry.getDN());

        return createUser(entry);
    }

    @Override
    public Principal authenticate(String username, String password) throws Exception {

        logger.info("Authenticating user " + username + " with password");

        LDAPConnection conn = connFactory.getConn();
        try {
            logger.info("Searching for user " + username);
            User user = findUserByUsername(conn, username);

            if (user == null) {
                logger.warn("Unable to authenticate user " + username + ": User not found");
                return null;
            }

            logger.info("Authenticating user " + user.getUserDN() + " with password");

            PKISocketFactory socketFactory = new PKISocketFactory(connConfig.isSecure());
            socketFactory.init(socketConfig);

            LDAPConnection authConn = new LDAPConnection(socketFactory);
            try {
                authConn.connect(connConfig.getHostname(), connConfig.getPort());
                authConn.authenticate(user.getUserDN(), password);

            } catch (LDAPException e) {
                logger.warn("Unable to authenticate user " + user.getUserDN() + ": " + e.getMessage());
                if (e.getLDAPResultCode() == LDAPException.INVALID_CREDENTIALS) {
                    return null;
                } else {
                    throw e;
                }
            } finally {
                authConn.close();
            }

            logger.info("User " + username + " authenticated");

            List<String> roles = getUserRoles(conn, user.getUserDN());
            return new PKIPrincipal(user, null, roles);

        } finally {
            connFactory.returnConn(conn);
        }
    }

    @Override
    public Principal authenticate(X509Certificate[] certChain) throws Exception {

        // sort cert chain from leaf to root
        certChain = Cert.sortCertificateChain(certChain, true);

        // get leaf cert
        X509Certificate cert = certChain[0];
        String certID = getCertID(cert);

        logger.info("Authenticating user with certificate " + certID);

        // cert already validated during SSL handshake

        LDAPConnection conn = connFactory.getConn();
        try {
            logger.info("Searching for user with certificate " + certID);
            User user = findUserByCertID(conn, certID);

            if (user == null) {
                logger.warn("Unable to authenticate user with certificate " + certID + ": User not found");
                return null;
            }

            logger.info("Searching for matching certificates in user " + user.getUserDN());
            X509Certificate[] certs = user.getX509Certificates();

            if (certs == null || certs.length == 0) {
                logger.warn("Unable to authenticate user " + user.getUserDN() + ": User has no certificates");
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
                logger.warn("Unable to authenticate user " + user.getUserDN() + ": No matching certificate");
                return null;
            }

            logger.info("User " + user.getUserDN() + " authenticated");

            List<String> roles = getUserRoles(conn, user.getUserDN());
            return new PKIPrincipal(user, null, roles);

        } finally {
            connFactory.returnConn(conn);
        }
    }

    @Override
    public void close() throws Exception {

        logger.info("Shutting down LDAP realm");

        connFactory.shutdown();
    }
}
