//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.realm;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.catalina.LifecycleException;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PlainPasswordFile;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;

/**
 * @author Endi S. Dewata
 */
public class PKILDAPRealm extends RealmCommon {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKILDAPRealm.class);

    String usersDN;
    String groupsDN;

    PKISocketConfig socketConfig;
    LDAPConnectionConfig connConfig;
    LDAPAuthenticationConfig authConfig;
    LdapBoundConnFactory connFactory;

    @Override
    public void initInternal () throws LifecycleException {

        logger.info("Initializing LDAP realm");

        EngineConfig cs;
        PasswordStore ps;
        LDAPConfig ldapConfig;

        String configFile = config.getParameter("configFile");

        if (configFile == null) {

            logger.info("Loading LDAP realm config from realm.conf");

            cs = new EngineConfig();
            ps = new PlainPasswordFile();
            ldapConfig = new LDAPConfig(null);

            for (String name : config.getParameterNames()) {
                String value = config.getParameter(name);
                switch(name) {
                case "usersDN", "groupsDN":
                    break;
                case "url":
                    logger.info("- URL: " + value);

                    URI url;
                    try {
                        url = new URI(value);
                    } catch (URISyntaxException e) {
                        throw new LifecycleException("No valid ldap url : " + value, e);
                    }
                    String host = url.getHost();
                    String port = Integer.toString(url.getPort());

                    String protocol = url.getScheme();
                    String secureConn;
                    if ("ldap".equals(protocol)) {
                        secureConn = "false";
                    } else if ("ldaps".equals(protocol)) {
                        secureConn = "true";
                    } else {
                        throw new LifecycleException("Unsupported LDAP protocol: " + protocol);
                    }

                    ldapConfig.put("ldapconn.host", host);
                    ldapConfig.put("ldapconn.port", port);
                    ldapConfig.put("ldapconn.secureConn", secureConn);
                    break;
                case "authType":
                    logger.info("- authentication type: " + value);
                    ldapConfig.put("ldapauth.authtype", value);
                    break;
                case "bindDN":
                    logger.info("- bind DN: " + value);
                    ldapConfig.put("ldapauth.bindDN", value);
                    break;
                case "bindPassword":
                    ldapConfig.put("ldapauth.bindPassword", value);
                    break;
                case "nickname":
                    logger.info("- nickname: " + value);
                    ldapConfig.put("ldapauth.clientCertNickname", value);
                    break;
                case "minConns","maxConns","maxResults", "errorIfDown":
                    logger.info("- " + name + ": " + value);
                    ldapConfig.put(name, value);
                    break;
                default:
                    if(name.startsWith("ldapauth.") || name.startsWith("ldapconn.")) {
                        logger.info("- " + name + ": " + value);
                        ldapConfig.put(name, value);
                    }
                    else {
                        cs.put(name, value);
                    }
                }
            }

        } else {

            logger.info("Loading LDAP realm config from " + configFile);
            try {
                cs = new EngineConfig(new FileConfigStorage(configFile));
                cs.load();

                ps = PasswordStore.create(cs.getPasswordStoreConfig());
            } catch (Exception e) {
                throw new LifecycleException("Cannot load config file " + configFile, e);
            }
            ldapConfig = cs.getInternalDBConfig();
        }

        socketConfig = cs.getSocketConfig();
        connConfig = ldapConfig.getConnectionConfig();
        authConfig = ldapConfig.getAuthenticationConfig();

        usersDN = config.getParameter("usersDN");
        logger.info("- users DN: " + usersDN);

        groupsDN = config.getParameter("groupsDN");
        logger.info("- groups DN: " + groupsDN);

        try {
            PKISocketFactory socketFactory = new PKISocketFactory();
            socketFactory.setSecure(connConfig.isSecure());
            if (LdapAuthInfo.LDAP_SSLCLIENTAUTH_STR.equals(authConfig.getAuthType())) {
                socketFactory.setClientCertNickname(authConfig.getClientCertNickname());
            }
            socketFactory.init(socketConfig);

            connFactory = new LdapBoundConnFactory("LDAPRealm");
            connFactory.setSocketFactory(socketFactory);
            connFactory.init(ldapConfig, ps);

        } catch (Exception e) {
            throw new LifecycleException("Unable to create LDAP connection:" + e.getMessage(), e);
        }
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
                + cert.getIssuerDN() + ";"
                + cert.getSubjectDN();
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
    public Principal authenticate(String username, String password) {
        logger.info("Authenticating user " + username + " with password");

        LDAPConnection conn = null;
        LDAPConnection authConn = null;
        PKIPrincipal principal = null;
        User user = null;
        try {
            conn = connFactory.getConn();
            logger.info("Searching for user " + username);
            user = findUserByUsername(conn, username);

            if (user == null) {
                logger.warn("Unable to authenticate user " + username + ": User not found");
                return null;
            }

            logger.info("Authenticating user " + user.getUserDN() + " with password");

            PKISocketFactory socketFactory = new PKISocketFactory();
            socketFactory.setSecure(connConfig.isSecure());
            socketFactory.init(socketConfig);

            authConn = new LDAPConnection(socketFactory);
            authConn.connect(connConfig.getHostname(), connConfig.getPort());
            authConn.authenticate(user.getUserDN(), password);
            logger.info("User " + username + " authenticated");

            List<String> roles = getUserRoles(conn, user.getUserDN());
            principal = new PKIPrincipal(user, null, roles);

        } catch (LDAPException e) {
            StringBuilder msg = new StringBuilder("Unable to authenticate user");
            if (user != null) {
                msg.append(" ").append(user.getUserDN());
            }
            msg.append(": ").append(e.getMessage());
            logger.warn(msg.toString());
            if (e.getLDAPResultCode() == LDAPException.INVALID_CREDENTIALS) {
                return null;
            }
            throw new RuntimeException(e);
        } catch (Exception e) {
            logger.error("Problem to verify user credentials", e);
            throw new RuntimeException(e);
        } finally {
            if(authConn != null)
                authConn.close();
            connFactory.returnConn(conn);
        }
        return principal;
    }

    @Override
    public Principal authenticate(X509Certificate[] certChain) {
        LDAPConnection conn = null;
        PKIPrincipal principal = null;
        try {
            // sort cert chain from leaf to root
            certChain = Cert.sortCertificateChain(certChain, true);

            // get leaf cert
            X509Certificate cert = certChain[0];
            String certID = getCertID(cert);

            logger.info("Authenticating user with certificate " + certID);

            // cert already validated during SSL handshake

            conn = connFactory.getConn();
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
            principal = new PKIPrincipal(user, null, roles);

        } catch (Exception e) {
            logger.error("Problem to verify the certificate", e);
            throw new RuntimeException(e);
        } finally {
            connFactory.returnConn(conn);
        }
        return principal;
    }

    @Override
    public void stopInternal() throws LifecycleException{

        logger.info("Shutting down LDAP realm");
        if(connFactory != null) {
            try {
                connFactory.shutdown();
            } catch (Exception e) {
                throw new LifecycleException("Cannot close the LDAP connection factory: " + e.getMessage(), e);
            }
        }
    }
}
