//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import java.net.URI;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.stream.Collectors;

import org.apache.commons.lang.StringUtils;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMECertificate;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWK;

import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PlainPasswordFile;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;

/**
 * LDAP database plugin for ACME service.
 *
 * Configuration fields:
 *
 * "configFile" : path to a CS.cfg containing "internaldb" and password
 *                configuration for connecting to LDAP.
 *
 * "basedn" : base DN of ACME subtree in LDAP directory
 *
 * A note about why we have different object classes for different
 * challenge types.  The dns-01 and http-01 challenge types both
 * only store a 'token'.  But challenge types could involve storing
 * other data.  So we define a different object class for each
 * challenge type, and each class specifies the challenge-specific
 * attribute types.
 *
 * @author Fraser Tweedale
 */
public class LDAPDatabase extends ACMEDatabase {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LDAPDatabase.class);

    static final String RDN_NONCE = "ou=nonces";
    static final String RDN_ACCOUNT = "ou=accounts";
    static final String RDN_ORDER = "ou=orders";
    static final String RDN_AUTHORIZATION = "ou=authorizations";
    static final String RDN_CHALLENGE = "ou=challenges";
    static final String RDN_CERTIFICATE = "ou=certificates";

    static final String ATTR_OBJECTCLASS = "objectClass";
    static final String ATTR_ACCOUNT_CONTACT = "acmeAccountContact";
    static final String ATTR_ACCOUNT_ID = "acmeAccountId";
    static final String ATTR_ACCOUNT_KEY = "acmeAccountKey";
    static final String ATTR_AUTHORIZATION_ID = "acmeAuthorizationId";
    static final String ATTR_AUTHORIZATION_WILDCARD = "acmeAuthorizationWildcard";
    static final String ATTR_CERTIFICATE_ID = "acmeCertificateId";
    static final String ATTR_CHALLENGE_ID = "acmeChallengeId";
    static final String ATTR_CREATED = "acmeCreated";
    static final String ATTR_ERROR = "acmeError";
    static final String ATTR_EXPIRES = "acmeExpires";
    static final String ATTR_IDENTIFIER = "acmeIdentifier";
    static final String ATTR_NONCE_ID = "acmeNonceId";
    static final String ATTR_ORDER_ID = "acmeOrderId";
    static final String ATTR_STATUS = "acmeStatus";
    static final String ATTR_TOKEN = "acmeToken";
    static final String ATTR_USER_CERTIFICATE = "userCertificate";
    static final String ATTR_VALIDATED_AT = "acmeValidatedAt";

    static final String OBJ_ACCOUNT = "acmeAccount";
    static final String OBJ_AUTHORIZATION = "acmeAuthorization";
    static final String OBJ_CERTIFICATE = "acmeCertificate";
    static final String OBJ_CHALLENGE = "acmeChallenge";
    static final String OBJ_CHALLENGE_DNS01 = "acmeChallengeDns01";
    static final String OBJ_CHALLENGE_HTTP01 = "acmeChallengeHttp01";
    static final String OBJ_NONCE = "acmeNonce";
    static final String OBJ_ORDER = "acmeOrder";

    static final String IDENTIFIER_TYPE_DNS = "dns";

    // The LDAP Generalized Time syntax
    static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmssZ");

    static {
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    enum LoadChallenges { DoLoad , DontLoad };
    enum OnNoSuchObject { Ignore , Throw };

    String basedn;

    LdapBoundConnFactory connFactory = null;

    public void init() throws Exception {

        PropConfigStore cs;
        IPasswordStore ps;
        LDAPConfig ldapConfig;

        String configFile = config.getParameter("configFile");

        if (configFile == null) {

            logger.info("Loading LDAP database configuration from database.conf");

            cs = new PropConfigStore();
            ps = new PlainPasswordFile();
            ldapConfig = new LDAPConfig(null);

            for (String name : config.getParameterNames()) {
                String value = config.getParameter(name);

                if (name.equals("baseDN") || name.equals("basedn")) {
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

            logger.info("Loading LDAP database configuration from " + configFile);

            cs = new PropConfigStore(new FileConfigStore(configFile));
            cs.load();

            ps = IPasswordStore.getPasswordStore("acme", cs.getProperties());
            ldapConfig = cs.getSubStore("internaldb", LDAPConfig.class);
        }

        basedn = config.getParameter("basedn");
        if (basedn == null) {
            basedn = config.getParameter("baseDN");
        } else {
            logger.warn("The basedn parameter has been deprecated. Use baseDN instead.");
        }
        logger.info("- base DN: " + basedn);

        connFactory = new LdapBoundConnFactory("acme");
        connFactory.init(cs, ldapConfig, ps);
    }

    public ACMENonce getNonce(String nonceID) throws Exception {
        String dn = ATTR_NONCE_ID +  "=" + nonceID + "," + RDN_NONCE + "," + basedn;
        LDAPEntry entry = ldapGet(dn);
        if (entry == null) return null;

        ACMENonce nonce = new ACMENonce();
        nonce.setID(nonceID);

        LDAPAttribute attrCreated = entry.getAttribute(ATTR_CREATED);
        nonce.setCreationTime(dateFormat.parse(attrCreated.getStringValues().nextElement()));

        LDAPAttribute attrExpires = entry.getAttribute(ATTR_EXPIRES);
        nonce.setExpirationTime(dateFormat.parse(attrExpires.getStringValues().nextElement()));

        return nonce;
    }

    public void addNonce(ACMENonce nonce) throws Exception {
        LDAPAttribute[] attrs = {
            new LDAPAttribute(ATTR_OBJECTCLASS, OBJ_NONCE),
            new LDAPAttribute(ATTR_NONCE_ID, nonce.getID()),
            new LDAPAttribute(ATTR_CREATED, dateFormat.format(nonce.getCreationTime())),
            new LDAPAttribute(ATTR_EXPIRES, dateFormat.format(nonce.getExpirationTime()))
        };
        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);
        String dn = ATTR_NONCE_ID + "=" + nonce.getID() + "," + RDN_NONCE + "," + basedn;
        LDAPEntry entry = new LDAPEntry(dn, attrSet);
        ldapAdd(entry);
    }

    public ACMENonce removeNonce(String nonceID) throws Exception {
        ACMENonce nonce = getNonce(nonceID);
        if (nonce == null) return null;

        String dn = ATTR_NONCE_ID + "=" + nonceID + "," + RDN_NONCE + "," + basedn;
        ldapDelete(dn, OnNoSuchObject.Ignore);

        return nonce;
    }

    public void removeExpiredNonces(Date currentTime) throws Exception {
        String[] attrs = {"1.1"};  // suppress attrs for performance; we only need DN
        List<LDAPEntry> entries = ldapSearch(
            RDN_NONCE + "," + basedn,
            "(" + ATTR_EXPIRES + "<=" + dateFormat.format(currentTime) + ")",
            attrs
        );
        for (LDAPEntry entry : entries) {
            ldapDelete(entry.getDN(), OnNoSuchObject.Ignore);
        }
    }

    public ACMEAccount getAccount(String accountID) throws Exception {
        String dn = ATTR_ACCOUNT_ID + "=" + accountID + "," + RDN_ACCOUNT + "," + basedn;
        LDAPEntry entry = ldapGet(dn);
        if (entry == null) return null;

        ACMEAccount account = new ACMEAccount();
        account.setID(accountID);

        LDAPAttribute attr = entry.getAttribute(ATTR_CREATED);
        account.setCreationTime(dateFormat.parse(attr.getStringValues().nextElement()));

        attr = entry.getAttribute(ATTR_STATUS);
        account.setStatus(attr.getStringValues().nextElement());

        attr = entry.getAttribute(ATTR_ACCOUNT_KEY);
        account.setJWK(JWK.fromJSON(attr.getStringValues().nextElement()));

        attr = entry.getAttribute(ATTR_ACCOUNT_CONTACT);
        if (attr != null) {
            account.setContact(attr.getStringValueArray());
        }

        // account was not created unless ToS were agreed
        account.setTermsOfServiceAgreed(true);

        return account;
    }

    public void addAccount(ACMEAccount account) throws Exception {
        LDAPAttribute[] attrs = {
            new LDAPAttribute(ATTR_OBJECTCLASS, OBJ_ACCOUNT),
            new LDAPAttribute(ATTR_ACCOUNT_ID, account.getID()),
            new LDAPAttribute(ATTR_CREATED, dateFormat.format(account.getCreationTime())),
            new LDAPAttribute(ATTR_ACCOUNT_KEY, account.getJWK().toJSON()),
            new LDAPAttribute(ATTR_STATUS, account.getStatus())
        };
        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);
        String[] contacts = account.getContact();
        if (contacts != null && contacts.length > 0) {
            attrSet.add(new LDAPAttribute(ATTR_ACCOUNT_CONTACT, contacts));
        }

        String dn = ATTR_ACCOUNT_ID + "=" + account.getID() + "," + RDN_ACCOUNT + "," + basedn;
        LDAPEntry entry = new LDAPEntry(dn, attrSet);
        ldapAdd(entry);
    }

    /**
     * Update account status.  Assume that AccountService has validated all data
     * and just perform the update.
     */
    public void updateAccount(ACMEAccount account) throws Exception {
        String dn = ATTR_ACCOUNT_ID + "=" + account.getID() + "," + RDN_ACCOUNT + "," + basedn;
        LDAPModificationSet mods = new LDAPModificationSet();
        mods.add(
            LDAPModification.REPLACE,
            new LDAPAttribute(ATTR_STATUS, account.getStatus())
        );

        String[] contact = account.getContact();
        if (contact == null) contact = new String[0];
        mods.add(
            LDAPModification.REPLACE,
            new LDAPAttribute(ATTR_ACCOUNT_CONTACT, contact)
        );
        ldapModify(dn, mods);
    }

    public ACMEOrder getOrder(String orderID) throws Exception {
        String dn = ATTR_ORDER_ID + "=" + orderID + "," + RDN_ORDER + "," + basedn;
        LDAPEntry entry = ldapGet(dn);
        if (entry == null) return null;
        return loadOrder(entry);
    }

    public Collection<ACMEOrder> getOrdersByAccount(String accountID) throws Exception {
        Collection<ACMEOrder> orders = new ArrayList<>();

        List<LDAPEntry> entries = ldapSearch(
            RDN_ORDER + "," + basedn,
            "(&(" + ATTR_OBJECTCLASS + "=" + OBJ_ORDER +
                ")(" + ATTR_ACCOUNT_ID + "=" + accountID + "))"
        );
        for (LDAPEntry entry : entries) {
            orders.add(loadOrder(entry));
        }
        return orders;
    }

    public Collection<ACMEOrder> getOrdersByAuthorizationAndStatus(String authzID, String status)
            throws Exception {
        Collection<ACMEOrder> orders = new ArrayList<>();

        List<LDAPEntry> entries = ldapSearch(
            RDN_ORDER + "," + basedn,
            "(&(" + ATTR_OBJECTCLASS + "=" + OBJ_ORDER +
                ")(" + ATTR_AUTHORIZATION_ID + "=" + authzID +
                ")(" + ATTR_STATUS + "=" + status + "))"
        );
        for (LDAPEntry entry : entries) {
            orders.add(loadOrder(entry));
        }
        return orders;
    }

    public ACMEOrder getOrderByCertificate(String certID)
            throws Exception {
        List<LDAPEntry> entries = ldapSearch(
            RDN_ORDER + "," + basedn,
            "(&(" + ATTR_OBJECTCLASS + "=" + OBJ_ORDER +
                ")(" + ATTR_CERTIFICATE_ID + "=" + certID + "))"
        );
        // there should be at most one order for the given cert id
        try {
            return loadOrder(entries.get(0));
        } catch (IndexOutOfBoundsException e) {
            return null;  // empty result set
        }
    }

    private static ACMEOrder loadOrder(LDAPEntry entry) throws Exception {
        ACMEOrder order = new ACMEOrder();

        LDAPAttribute attr = entry.getAttribute(ATTR_ORDER_ID);
        order.setID(attr.getStringValues().nextElement());

        attr = entry.getAttribute(ATTR_ACCOUNT_ID);
        order.setAccountID(attr.getStringValues().nextElement());

        attr = entry.getAttribute(ATTR_CREATED);
        order.setCreationTime(dateFormat.parse(attr.getStringValues().nextElement()));

        attr = entry.getAttribute(ATTR_STATUS);
        order.setStatus(attr.getStringValues().nextElement());

        attr = entry.getAttribute(ATTR_ERROR);
        if (attr != null) {
            order.setError(attr.getStringValues().nextElement());
        }

        attr = entry.getAttribute(ATTR_EXPIRES);
        if (attr != null) {
            order.setExpirationTime(dateFormat.parse(attr.getStringValues().nextElement()));
        }

        attr = entry.getAttribute(ATTR_CERTIFICATE_ID);
        if (attr != null) {
            order.setCertID(attr.getStringValues().nextElement());
        }

        List<ACMEIdentifier> identifiers = new ArrayList<>();
        attr = entry.getAttribute(ATTR_IDENTIFIER);
        for (String identifier : attr.getStringValueArray()) {
            String[] parts = StringUtils.split(identifier, ":", 2);
            if (parts.length != 2) {
                throw new Exception("Invalid order identifier: " + identifier);
            }

            String type = parts[0];
            String value = parts[1];

            identifiers.add(new ACMEIdentifier(type, value));
        }
        order.setIdentifiers(identifiers.toArray(new ACMEIdentifier[0]));

        attr = entry.getAttribute(ATTR_AUTHORIZATION_ID);
        order.setAuthzIDs(attr.getStringValueArray());

        return order;
    }

    public void addOrder(ACMEOrder order) throws Exception {
        LDAPAttribute[] attrs = {
            new LDAPAttribute(ATTR_OBJECTCLASS, OBJ_ORDER),
            new LDAPAttribute(ATTR_ORDER_ID, order.getID()),
            new LDAPAttribute(ATTR_ACCOUNT_ID, order.getAccountID()),
            new LDAPAttribute(ATTR_CREATED, dateFormat.format(order.getCreationTime())),
            new LDAPAttribute(ATTR_STATUS, order.getStatus()),
            new LDAPAttribute(ATTR_AUTHORIZATION_ID, order.getAuthzIDs())
        };
        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);

        Date expirationTime = order.getExpirationTime();
        if (expirationTime != null) {
            attrSet.add(
                new LDAPAttribute(ATTR_EXPIRES, dateFormat.format(expirationTime))
            );
        }

        // identifiers
        ACMEIdentifier[] identifiers = order.getIdentifiers();
        for (ACMEIdentifier identifier : identifiers) {
            attrSet.add(
                new LDAPAttribute(
                    ATTR_IDENTIFIER,
                    identifier.getType() + ":" + identifier.getValue())
            );
        }

        String error = order.getError();
        if (error != null) {
            attrSet.add(new LDAPAttribute(ATTR_ERROR, error));
        }

        String dn = ATTR_ORDER_ID + "=" + order.getID() + "," + RDN_ORDER + "," + basedn;
        LDAPEntry entry = new LDAPEntry(dn, attrSet);
        ldapAdd(entry);
    }

    public void updateOrder(ACMEOrder order) throws Exception {
        String dn = ATTR_ORDER_ID + "=" + order.getID() + "," + RDN_ORDER + "," + basedn;
        LDAPModificationSet mods = new LDAPModificationSet();
        mods.add(
            LDAPModification.REPLACE,
            new LDAPAttribute(ATTR_STATUS, order.getStatus())
        );
        mods.add(
            LDAPModification.REPLACE,
            new LDAPAttribute(ATTR_CERTIFICATE_ID, order.getCertID())
        );

        // update error value
        String error = order.getError();
        LDAPAttribute attrError;
        if (error == null) {
            // LDAP attribute with no value in REPLACE change causes
            // attribute to be removed.
            attrError = new LDAPAttribute(ATTR_ERROR);
        } else {
            attrError = new LDAPAttribute(ATTR_ERROR, error);
        }
        mods.add(LDAPModification.REPLACE, attrError);

        // update expiration time
        Date expirationTime = order.getExpirationTime();
        LDAPAttribute attrExpires;
        if (expirationTime == null) {
            // LDAP attribute with no value in REPLACE change causes
            // attribute to be removed.
            attrExpires = new LDAPAttribute(ATTR_EXPIRES);
        } else {
            attrExpires = new LDAPAttribute(ATTR_EXPIRES, dateFormat.format(expirationTime));
        }
        mods.add(LDAPModification.REPLACE, attrExpires);

        ldapModify(dn, mods);
    }

    public void removeExpiredOrders(Date currentTime) throws Exception {
        String[] attrs = {"1.1"};  // suppress attrs for performance; we only need DN
        List<LDAPEntry> entries = ldapSearch(
            RDN_ORDER + "," + basedn,
            "(" + ATTR_EXPIRES + "<=" + dateFormat.format(currentTime) + ")",
            attrs
        );
        for (LDAPEntry entry : entries) {
            ldapDelete(entry.getDN(), OnNoSuchObject.Ignore);
        }
    }

    public ACMEAuthorization getAuthorization(String authzID) throws Exception {
        return getAuthorization(authzID, LoadChallenges.DoLoad);
    }

    private ACMEAuthorization getAuthorization(String authzID, LoadChallenges clc)
            throws Exception {
        String dn = ATTR_AUTHORIZATION_ID + "=" + authzID + "," + RDN_AUTHORIZATION + "," + basedn;
        LDAPEntry entry = ldapGet(dn);
        if (entry == null) return null;

        LDAPAttribute attr;

        ACMEAuthorization authz = new ACMEAuthorization();
        authz.setID(authzID);

        attr = entry.getAttribute(ATTR_ACCOUNT_ID);
        authz.setAccountID(attr.getStringValues().nextElement());

        attr = entry.getAttribute(ATTR_CREATED);
        authz.setCreationTime(dateFormat.parse(attr.getStringValues().nextElement()));

        attr = entry.getAttribute(ATTR_EXPIRES);
        if (attr != null) {
            authz.setExpirationTime(dateFormat.parse(attr.getStringValues().nextElement()));
        }

        attr = entry.getAttribute(ATTR_STATUS);
        authz.setStatus(attr.getStringValues().nextElement());

        attr = entry.getAttribute(ATTR_IDENTIFIER);
        String identifier = attr.getStringValues().nextElement();

        String[] parts = StringUtils.split(identifier, ":", 2);
        if (parts.length != 2) {
            throw new Exception("Invalid authorization identifier: " + identifier);
        }

        String type = parts[0];
        String value = parts[1];

        authz.setIdentifier(new ACMEIdentifier(type, value));

        attr = entry.getAttribute(ATTR_AUTHORIZATION_WILDCARD);
        if (attr != null) {
            if ("TRUE".equalsIgnoreCase(attr.getStringValues().nextElement())) {
                authz.setWildcard(true);
            }
        }

        if (clc == LoadChallenges.DoLoad) {
            List<ACMEChallenge> challenges = new ArrayList<>();
            Collection<LDAPEntry> entries = ldapSearch(
                RDN_CHALLENGE + "," + basedn,
                "(&(" + ATTR_OBJECTCLASS + "=" + OBJ_CHALLENGE +
                    ")(" + ATTR_AUTHORIZATION_ID + "=" + authzID + "))"
            );
            for (LDAPEntry challengeEntry : entries) {
                challenges.add(loadChallenge(challengeEntry));
            }
            authz.setChallenges(challenges);
        }

        return authz;
    }

    private ACMEChallenge getChallenge(String challengeID)
            throws Exception {
        String dn = ATTR_CHALLENGE_ID + "=" + challengeID
                        + "," + RDN_CHALLENGE + "," + basedn;
        LDAPEntry entry = ldapGet(dn);
        if (entry == null) return null;
        return loadChallenge(entry);
    }

    private ACMEChallenge loadChallenge(LDAPEntry entry)
            throws ParseException {
        ACMEChallenge challenge = new ACMEChallenge();

        LDAPAttribute attr = entry.getAttribute(ATTR_CHALLENGE_ID);
        challenge.setID(attr.getStringValues().nextElement());

        attr = entry.getAttribute(ATTR_OBJECTCLASS);
        List<String> classes = Collections.list(attr.getStringValues());
        if (classes.contains(OBJ_CHALLENGE_DNS01)) {
            challenge.setType("dns-01");
        } else if (classes.contains(OBJ_CHALLENGE_HTTP01)) {
            challenge.setType("http-01");
        } else {
            throw new RuntimeException(
                "unable to determine challenge type from objectclass "
                + classes.stream().collect(Collectors.joining(", ", "{", "}"))
            );
        }

        attr = entry.getAttribute(ATTR_AUTHORIZATION_ID);
        challenge.setAuthzID(attr.getStringValues().nextElement());

        attr = entry.getAttribute(ATTR_TOKEN);
        challenge.setToken(attr.getStringValues().nextElement());

        attr = entry.getAttribute(ATTR_STATUS);
        challenge.setStatus(attr.getStringValues().nextElement());

        attr = entry.getAttribute(ATTR_ERROR);
        if (attr != null) {
            challenge.setError(attr.getStringValues().nextElement());
        }

        attr = entry.getAttribute(ATTR_VALIDATED_AT);
        if (attr != null) {
            challenge.setValidationTime(
                dateFormat.parse(attr.getStringValues().nextElement()));
        }

        return challenge;
    }

    /**
     * Get the authorization for the given challenge.
     */
    public ACMEAuthorization getAuthorizationByChallenge(String challengeID) throws Exception {
        ACMEChallenge challenge = getChallenge(challengeID);
        if (challenge == null) return null;

        // Load all challenges for the authorization such that
        // other challenges do not unintentionally get deleted
        // when the authorization is updated.
        return getAuthorization(challenge.getAuthzID());
    }

    public void addAuthorization(ACMEAuthorization authorization) throws Exception {
        ACMEIdentifier identifier = authorization.getIdentifier();
        LDAPAttribute[] attrs = {
            new LDAPAttribute(ATTR_OBJECTCLASS, OBJ_AUTHORIZATION),
            new LDAPAttribute(ATTR_AUTHORIZATION_ID, authorization.getID()),
            new LDAPAttribute(ATTR_ACCOUNT_ID, authorization.getAccountID()),
            new LDAPAttribute(ATTR_CREATED, dateFormat.format(authorization.getCreationTime())),
            new LDAPAttribute(ATTR_STATUS, authorization.getStatus()),
            new LDAPAttribute(ATTR_IDENTIFIER, identifier.getType() + ":" + identifier.getValue())
        };
        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);

        Date expirationTime = authorization.getExpirationTime();
        if (expirationTime != null) {
            attrSet.add(new LDAPAttribute(ATTR_EXPIRES, dateFormat.format(expirationTime)));
        }

        Boolean wildcard = authorization.getWildcard();
        String wildcardValue = wildcard != null && wildcard == true ? "TRUE" : "FALSE";
        attrSet.add(new LDAPAttribute(ATTR_AUTHORIZATION_WILDCARD, wildcardValue));

        String dn = ATTR_AUTHORIZATION_ID + "=" + authorization.getID()
                        + "," + RDN_AUTHORIZATION + "," + basedn;
        LDAPEntry entry = new LDAPEntry(dn, attrSet);
        ldapAdd(entry);
    }

    public void addChallenge(String accountID, ACMEChallenge challenge)
            throws Exception {
        String type = challenge.getType();
        String objclass = null;
        if (type.equals("dns-01")) {
            objclass = OBJ_CHALLENGE_DNS01;
        } else if (type.equals("http-01")) {
            objclass = OBJ_CHALLENGE_HTTP01;
        } else {
            throw new RuntimeException("unrecognised challenge type: " + type);
        }

        String[] classes = {OBJ_CHALLENGE, objclass};
        LDAPAttribute[] attrs = {
            new LDAPAttribute(ATTR_OBJECTCLASS, classes),
            new LDAPAttribute(ATTR_CHALLENGE_ID, challenge.getID()),
            new LDAPAttribute(ATTR_AUTHORIZATION_ID, challenge.getAuthzID()),
            new LDAPAttribute(ATTR_ACCOUNT_ID, accountID),
            new LDAPAttribute(ATTR_STATUS, challenge.getStatus()),
            new LDAPAttribute(ATTR_TOKEN, challenge.getToken())
        };
        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);

        String dn = ATTR_CHALLENGE_ID + "=" + challenge.getID()
                        + "," + RDN_CHALLENGE + "," + basedn;
        LDAPEntry entry = new LDAPEntry(dn, attrSet);
        ldapAdd(entry);
    }

    public void updateAuthorization(ACMEAuthorization authorization) throws Exception {
        String dn = ATTR_AUTHORIZATION_ID + "=" + authorization.getID()
                        + "," + RDN_AUTHORIZATION + "," + basedn;
        LDAPModificationSet mods = new LDAPModificationSet();
        mods.add(
            LDAPModification.REPLACE,
            new LDAPAttribute(ATTR_STATUS, authorization.getStatus())
        );

        // update expiration time
        Date expirationTime = authorization.getExpirationTime();
        LDAPAttribute attrExpires;
        if (expirationTime == null) {
            // LDAP attribute with no value in REPLACE change causes
            // attribute to be removed.
            attrExpires = new LDAPAttribute(ATTR_EXPIRES);
        } else {
            attrExpires = new LDAPAttribute(ATTR_EXPIRES, dateFormat.format(expirationTime));
        }
        mods.add(LDAPModification.REPLACE, attrExpires);

        ldapModify(dn, mods);

        // Delete and re-add challenge objects.  First reload this
        // authz so we can delete all existing challenges.
        ACMEAuthorization authzORIG =
            getAuthorization(authorization.getID(), LoadChallenges.DoLoad);
        for (ACMEChallenge challenge : authzORIG.getChallenges()) {
            dn = ATTR_CHALLENGE_ID + "=" + challenge.getID()
                    + "," + RDN_CHALLENGE + "," + basedn;
            ldapDelete(dn, OnNoSuchObject.Ignore);
        }
        // now add the possibly-changed challenges.
        for (ACMEChallenge challenge : authorization.getChallenges()) {
            dn = ATTR_CHALLENGE_ID + "=" + challenge.getID()
                    + "," + RDN_CHALLENGE + "," + basedn;
            addChallenge(authorization.getAccountID(), challenge);
        }
        // NOTE: there are optimisation opportunities here.
        //
        // 1) With proper equality checks for challenge objects,
        //    we could avoid redundant deletes/adds and devolve
        //    delete/add to modify when updating a challenge.
        //
        // 2) If we record the "original" set of challenge objects
        //    after loading from database, we can also avoid the
        //    searches to reload the authz and challenge objects.
    }

    @Override
    public boolean hasRevocationAuthorization(
            String accountID, Date time, ACMEIdentifier identifier)
            throws Exception {

        boolean wildcard = false;
        String ident = identifier.getValue();
        if (IDENTIFIER_TYPE_DNS.equals(identifier.getType()) && ident.startsWith("*.")) {
            wildcard = true;
            ident = ident.substring(2);  // strip wildcard
        }

        /* RFC 8555 is unclear about whether wildcard revocations
         * authorise non-wildcard identifiers, or vice-versa.
         *
         * This implementation matches strictly, i.e.:
         *
         * AUTHZ-ID    WILDCARD   ID-TO-REVOKE  AUTHORISED?
         *
         * foo.example.com  Y    *.foo.example.com  Y
         * foo.example.com  N    *.foo.example.com  N
         *
         * foo.example.com  Y      foo.example.com  N
         * foo.example.com  N      foo.example.com  Y
         *
         * foo.example.com  Y  bar.foo.example.com  N
         * foo.example.com  N  bar.foo.example.com  N
         *
         * In terms of the filter, this means:
         *
         * - assert an exact match for the "base identifier"
         *
         * - set acmeAuthorizationWildcard=TRUE|FALSE depending on
         *   whether the identifier began with "*." or not.
         */
        List<LDAPEntry> entries = ldapSearch(
            RDN_AUTHORIZATION + "," + basedn,
            "(&(" + ATTR_OBJECTCLASS + "=" + OBJ_AUTHORIZATION
                + ")(" + ATTR_ACCOUNT_ID + "=" + accountID
                + ")(!(" + ATTR_EXPIRES + "<=" + dateFormat.format(time) + ")"
                + ")(" + ATTR_STATUS + "=valid"
                + ")(" + ATTR_IDENTIFIER + "=" + identifier.getType() + ":" + ident
                + ")(" + ATTR_AUTHORIZATION_WILDCARD + "=" + (wildcard ? "TRUE" : "FALSE")
                + "))"
        );
        return !entries.isEmpty();
    }

    public void removeExpiredAuthorizations(Date currentTime) throws Exception {
        String[] attrs = {"1.1"};  // suppress attrs for performance; we only need DN
        List<LDAPEntry> entries = ldapSearch(
            RDN_AUTHORIZATION + "," + basedn,
            "(" + ATTR_EXPIRES + "<=" + dateFormat.format(currentTime) + ")",
            attrs
        );
        for (LDAPEntry entry : entries) {
            ldapDelete(entry.getDN(), OnNoSuchObject.Ignore);
        }
    }

    public ACMECertificate getCertificate(String certID) throws Exception {
        String dn = ATTR_CERTIFICATE_ID + "=" + certID + "," + RDN_CERTIFICATE + "," + basedn;
        LDAPEntry entry = ldapGet(dn);
        if (entry == null) return null;

        ACMECertificate certificate = new ACMECertificate();
        certificate.setID(certID);

        LDAPAttribute attr = entry.getAttribute(ATTR_CREATED);
        certificate.setCreationTime(dateFormat.parse(attr.getStringValues().nextElement()));

        attr = entry.getAttribute(ATTR_USER_CERTIFICATE);
        certificate.setData(attr.getByteValueArray()[0]);

        attr = entry.getAttribute(ATTR_EXPIRES);
        if (attr != null) {
            certificate.setExpirationTime(dateFormat.parse(attr.getStringValues().nextElement()));
        }

        return certificate;
    }

    public void addCertificate(String certID, ACMECertificate certificate) throws Exception {

        String dn = ATTR_CERTIFICATE_ID + "=" + certID + "," + RDN_CERTIFICATE + "," + basedn;
        LDAPAttribute[] attrs = {
                new LDAPAttribute(ATTR_OBJECTCLASS, OBJ_CERTIFICATE),
                new LDAPAttribute(ATTR_CERTIFICATE_ID, certID),
                new LDAPAttribute(ATTR_CREATED, dateFormat.format(certificate.getCreationTime())),
                new LDAPAttribute(ATTR_USER_CERTIFICATE, certificate.getData())
        };
        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);

        Date expirationTime = certificate.getExpirationTime();
        if (expirationTime != null) {
            attrSet.add(
                new LDAPAttribute(ATTR_EXPIRES, dateFormat.format(expirationTime))
            );
        }

        LDAPEntry entry = new LDAPEntry(dn, attrSet);
        ldapAdd(entry);
    }

    public void removeExpiredCertificates(Date currentTime) throws Exception {
        String[] attrs = {"1.1"};  // suppress attrs for performance; we only need DN
        List<LDAPEntry> entries = ldapSearch(
            RDN_CERTIFICATE + "," + basedn,
            "(" + ATTR_EXPIRES + "<=" + dateFormat.format(currentTime) + ")",
            attrs
        );
        for (LDAPEntry entry : entries) {
            ldapDelete(entry.getDN(), OnNoSuchObject.Ignore);
        }
    }


    /* LOW LEVEL LDAP METHODS */

    void ldapAdd(LDAPEntry entry) throws Exception {

        logger.info("LDAP: add " + entry.getDN());

        LDAPConnection conn = connFactory.getConn();
        try {
            conn.add(entry);
        } catch (LDAPException e) {
            throw new Exception("LDAP add failed: " + e, e);
        } finally {
            connFactory.returnConn(conn);
        }
    }

    void ldapModify(String dn, LDAPModificationSet mods) throws Exception {

        logger.info("LDAP: modify " + dn);

        LDAPConnection conn = connFactory.getConn();
        try {
            conn.modify(dn, mods);
        } catch (LDAPException e) {
            throw new Exception("LDAP modify failed: " + e, e);
        } finally {
            connFactory.returnConn(conn);
        }
    }

    void ldapDelete(String dn, OnNoSuchObject action) throws Exception {

        logger.info("LDAP: delete " + dn);

        LDAPConnection conn = connFactory.getConn();
        try {
            conn.delete(dn);
        } catch (LDAPException e) {
            if (
                e.getLDAPResultCode() != LDAPException.NO_SUCH_OBJECT
                || action == OnNoSuchObject.Throw
            ) {
                throw e;
            }
        } finally {
            connFactory.returnConn(conn);
        }
    }

    /** Search for a single entry (SCOPE_BASE).  If it exists return it,
     * if it does not exist return null, and raise Exception on error
     */
    LDAPEntry ldapGet(String dn) throws Exception {

        logger.info("LDAP: search " + dn);

        LDAPConnection conn = connFactory.getConn();
        try {
            return conn.search(
                dn,
                LDAPConnection.SCOPE_BASE,
                null /* filter */,
                null /* attrs */,
                false /* attrsOnly */
            ).next();
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                return null;
            } else {
                throw new Exception("LDAP search failed: " + e, e);
            }
        } finally {
            connFactory.returnConn(conn);
        }
    }

    List<LDAPEntry> ldapSearch(String searchBase, String filter)
            throws Exception {
        return ldapSearch(searchBase, filter, null);
    }

    /** Subtree search with given filter. */
    List<LDAPEntry> ldapSearch(String searchBase, String filter, String[] attrs)
            throws Exception {

        logger.info("LDAP: search " + searchBase);

        List<LDAPEntry> l = new ArrayList<>();

        LDAPConnection conn = connFactory.getConn();
        try {
            LDAPSearchResults results = conn.search(
                searchBase,
                LDAPConnection.SCOPE_SUB,
                filter,
                attrs,
                false /* attrsOnly */
            );
            if (results != null) {
                while (results.hasMoreElements()) {
                    l.add(results.next());
                }
            }
        } finally {
            connFactory.returnConn(conn);
        }

        return l;
    }
}
