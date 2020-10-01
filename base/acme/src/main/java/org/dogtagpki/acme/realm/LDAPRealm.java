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
import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;

import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.crypto.CryptoUtil;
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

    public void init() throws Exception {

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

    public List<String> getUserRoles(LDAPConnection conn, LDAPEntry userEntry) throws Exception {

        List<String> roles = new ArrayList<>();
        String filter = "uniqueMember=" + userEntry.getDN();

        logger.info("LDAPRealm: Getting user roles:");
        logger.info("LDAPRealm: - base DN: " + groupsDN);
        logger.info("LDAPRealm: - filter: " + filter);

        LDAPSearchResults results = conn.search(
                groupsDN,
                LDAPConnection.SCOPE_ONE,
                filter,
                null, /* get all attributes*/
                false /* return attribute values */
        );

        logger.info("LDAPRealm: Roles:");
        while (results.hasMoreElements()) {
            LDAPEntry groupEntry = results.next();
            logger.info("LDAPRealm: - " + groupEntry.getDN());

            LDAPAttribute cnAttr = groupEntry.getAttribute("cn");
            String role = cnAttr.getStringValues().nextElement();
            roles.add(role);
        }

        return roles;
    }

    public LDAPEntry findUserByUsername(LDAPConnection conn, String username) throws Exception {

        String filter = "uid=" + username;

        logger.info("LDAPRealm: Finding user by username:");
        logger.info("LDAPRealm: - base DN: " + usersDN);
        logger.info("LDAPRealm: - filter: " + filter);

        LDAPSearchResults results = conn.search(
                usersDN,
                LDAPConnection.SCOPE_ONE,
                filter,
                null, /* get all attributes*/
                false /* return attribute values */
        );

        if (!results.hasMoreElements()) {
            logger.info("LDAPRealm: User not found");
            return null;
        }

        LDAPEntry entry = results.next();
        logger.info("LDAPRealm: User: " + entry.getDN());

        return entry;
    }

    public String getCertID(X509Certificate cert) {
        return cert.getVersion() + ";"
                + cert.getSerialNumber() + ";"
                + cert.getIssuerDN() + ";"
                + cert.getSubjectDN();
    }

    public LDAPEntry findUserByCert(LDAPConnection conn, X509Certificate[] certs) throws Exception {

        // sort certs from leaf to root
        certs = CryptoUtil.sortCertificateChain(certs, true);

        // get user cert
        X509Certificate cert = certs[0];

        String filter = "description=" + getCertID(cert);

        logger.info("LDAPRealm: Finding user by cert:");
        logger.info("LDAPRealm: - base DN: " + usersDN);
        logger.info("LDAPRealm: - filter: " + filter);

        LDAPSearchResults results = conn.search(
                usersDN,
                LDAPConnection.SCOPE_ONE,
                filter,
                null, /* get all attributes*/
                false /* return attribute values */
        );

        if (!results.hasMoreElements()) {
            logger.info("LDAPRealm: User not found");
            return null;
        }

        LDAPEntry entry = results.next();
        logger.info("LDAPRealm: User: " + entry.getDN());

        return entry;
    }

    public Principal authenticate(String username, String password) throws Exception {
        LDAPConnection conn = connFactory.getConn();
        try {
            LDAPEntry entry = findUserByUsername(conn, username);

            if (entry == null) {
                return null;
            }

            logger.info("LDAPRealm: Validating password");

            PKISocketFactory socketFactory = new PKISocketFactory(connConfig.isSecure());
            socketFactory.init(socketConfig);

            LDAPConnection authConn = new LDAPConnection(socketFactory);
            try {
                authConn.connect(connConfig.getHostname(), connConfig.getPort());
                authConn.authenticate(entry.getDN(), password);

            } catch (LDAPException e) {
                if (e.getLDAPResultCode() == LDAPException.INVALID_CREDENTIALS) {
                    return null;
                } else {
                    throw e;
                }
            } finally {
                authConn.close();
            }

            List<String> roles = getUserRoles(conn, entry);
            return new GenericPrincipal(username, null, roles);

        } finally {
            connFactory.returnConn(conn);
        }
    }

    public Principal authenticate(X509Certificate[] certs) throws Exception {

        LDAPConnection conn = connFactory.getConn();
        try {
            LDAPEntry entry = findUserByCert(conn, certs);

            if (entry == null) {
                return null;
            }

            // cert already validated during SSL handshake

            LDAPAttribute uid = entry.getAttribute("uid");
            String username = uid.getStringValues().nextElement();

            List<String> roles = getUserRoles(conn, entry);
            return new GenericPrincipal(username, null, roles);

        } finally {
            connFactory.returnConn(conn);
        }
    }

    public void close() throws Exception {
        connFactory.shutdown();
    }
}
