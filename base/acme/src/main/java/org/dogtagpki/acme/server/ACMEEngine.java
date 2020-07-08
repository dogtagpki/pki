//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.Consumer;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.lang.StringUtils;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ACMEMetadata;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.ACMEPolicy;
import org.dogtagpki.acme.ACMERevocation;
import org.dogtagpki.acme.JWK;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.database.ACMEDatabase;
import org.dogtagpki.acme.database.ACMEDatabaseConfig;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.dogtagpki.acme.issuer.ACMEIssuerConfig;
import org.dogtagpki.acme.validator.ACMEValidator;
import org.dogtagpki.acme.validator.ACMEValidatorConfig;
import org.dogtagpki.acme.validator.ACMEValidatorsConfig;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attribute;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attributes;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertAttrSet;
import org.mozilla.jss.netscape.security.x509.DNSName;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

/**
 * @author Endi S. Dewata
 */
@WebListener
public class ACMEEngine implements ServletContextListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEEngine.class);

    public static ACMEEngine INSTANCE;

    private String name;

    private ACMEEngineConfigSource engineConfigSource = null;

    private ACMEMetadata metadata;

    private ACMEDatabaseConfig databaseConfig;
    private ACMEDatabase database;

    private ACMEValidatorsConfig validatorsConfig;
    private Map<String, ACMEValidator> validators = new HashMap<>();

    private ACMEIssuerConfig issuerConfig;
    private ACMEIssuer issuer;

    private boolean enabled = true;

    private ACMEPolicy policy;

    public static ACMEEngine getInstance() {
        return INSTANCE;
    }

    public ACMEEngine() {
        INSTANCE = this;
        policy = new ACMEPolicy(true /* enable wildcards by default */);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public ACMEMetadata getMetadata() {
        return metadata;
    }

    public void setMetadata(ACMEMetadata metadata) {
        this.metadata = metadata;
    }

    public ACMEDatabaseConfig getDatabaseConfig() {
        return databaseConfig;
    }

    public void setDatabaseConfig(ACMEDatabaseConfig databaseConfig) {
        this.databaseConfig = databaseConfig;
    }

    public ACMEDatabase getDatabase() {
        return database;
    }

    public void setDatabase(ACMEDatabase database) {
        this.database = database;
    }

    public Collection<ACMEValidator> getValidators() {
        return validators.values();
    }

    public ACMEValidator getValidator(String name) {
        return validators.get(name);
    }

    public void addValidator(String name, ACMEValidator validator) {
        validators.put(name, validator);
    }

    public ACMEIssuerConfig getIssuerConfig() {
        return issuerConfig;
    }

    public void setIssuerConfig(ACMEIssuerConfig issuerConfig) {
        this.issuerConfig = issuerConfig;
    }

    public ACMEIssuer getIssuer() {
        return issuer;
    }

    public void setIssuer(ACMEIssuer issuer) {
        this.issuer = issuer;
    }

    /**
     * Whether the whole ACME service is enabled or not.
     */
    public boolean isEnabled() {
        return this.enabled;
    }

    private void setEnabled(boolean b) {
        this.enabled = b;
    }

    /**
     * Get the local policy configuration object.
     */
    public ACMEPolicy getPolicy() {
        return policy;
    }

    public void loadEngineConfig(Properties cfg) throws Exception {
        // the default class just sends the default config values
        Class<? extends ACMEEngineConfigSource> configSourceClass
            = ACMEEngineConfigDefaultSource.class;

        String className = cfg.getProperty("engine.class");
        if (className != null && !className.isEmpty()) {
            configSourceClass =
                (Class<ACMEEngineConfigSource>) Class.forName(className);
        }
        engineConfigSource = configSourceClass.newInstance();

        // We pass to the ConfigSource only the callbacks needed to set
        // the configuration (Consumer<T>).  This abstraction ensures the
        // ConfigSource has no direct access to the ACMEEngine instance.

        engineConfigSource.setEnabledConsumer(new Consumer<Boolean>() {
            @Override public void accept(Boolean b) {
                setEnabled(b);
                logger.info(
                    "ACME service is "
                    + (b ? "enabled" : "DISABLED")
                    + " by configuration"
                );
            }
        });

        engineConfigSource.setWildcardConsumer(new Consumer<Boolean>() {
            @Override public void accept(Boolean b) {
                getPolicy().setEnableWildcards(b);
                logger.info(
                    "ACME wildcard issuance is "
                    + (b ? "enabled" : "DISABLED")
                    + " by configuration"
                );
            }
        });

        engineConfigSource.init(cfg);
    }

    public void loadMetadata(String filename) throws Exception {

        File metadataConfigFile = new File(filename);

        if (metadataConfigFile.exists()) {
            logger.info("Loading ACME metadata from " + metadataConfigFile);
            Properties props = new Properties();
            try (FileReader reader = new FileReader(metadataConfigFile)) {
                props.load(reader);
            }
            metadata = ACMEMetadata.fromProperties(props);

        } else {
            logger.info("Loading default ACME metadata");
            metadata = new ACMEMetadata();
        }
    }

    public void loadDatabaseConfig(String filename) throws Exception {

        File databaseConfigFile = new File(filename);

        if (databaseConfigFile.exists()) {
            logger.info("Loading ACME database config from " + databaseConfigFile);
            Properties props = new Properties();
            try (FileReader reader = new FileReader(databaseConfigFile)) {
                props.load(reader);
            }
            databaseConfig = ACMEDatabaseConfig.fromProperties(props);

        } else {
            logger.info("Loading default ACME database config");
            databaseConfig = new ACMEDatabaseConfig();
        }
    }

    public void initDatabase() throws Exception {

        logger.info("Initializing ACME database");

        String className = databaseConfig.getClassName();
        Class<ACMEDatabase> databaseClass = (Class<ACMEDatabase>) Class.forName(className);

        database = databaseClass.newInstance();
        database.setConfig(databaseConfig);
        database.init();
    }

    public void shutdownDatabase() throws Exception {
        if (database != null)
            database.close();
    }

    public void loadValidatorsConfig(String filename) throws Exception {

        File validatorsConfigFile = new File(filename);

        if (!validatorsConfigFile.exists()) {
            validatorsConfigFile = new File("/usr/share/pki/acme/conf/validators.conf");
        }

        logger.info("Loading ACME validators config from " + validatorsConfigFile);
        Properties props = new Properties();
        try (FileReader reader = new FileReader(validatorsConfigFile)) {
            props.load(reader);
        }
        validatorsConfig = ACMEValidatorsConfig.fromProperties(props);
    }

    public void initValidators() throws Exception {

        logger.info("Initializing ACME validators");

        for (String name : validatorsConfig.keySet()) {

            logger.info("Initializing " + name + " validator");

            ACMEValidatorConfig validatorConfig = validatorsConfig.get(name);

            String className = validatorConfig.getClassName();
            Class<ACMEValidator> validatorClass = (Class<ACMEValidator>) Class.forName(className);

            ACMEValidator validator = validatorClass.newInstance();
            validator.setConfig(validatorConfig);
            validator.init();

            addValidator(name, validator);
        }
    }

    public void shutdownValidators() throws Exception {

        for (ACMEValidator validator : validators.values()) {
            validator.close();
        }
    }

    public void loadIssuerConfig(String filename) throws Exception {

        File issuerConfigFile = new File(filename);

        if (issuerConfigFile.exists()) {
            logger.info("Loading ACME issuer config from " + issuerConfigFile);
            Properties props = new Properties();
            try (FileReader reader = new FileReader(issuerConfigFile)) {
                props.load(reader);
            }
            issuerConfig = ACMEIssuerConfig.fromProperties(props);

        } else {
            logger.info("Loading default ACME issuer config");
            issuerConfig = new ACMEIssuerConfig();
        }
    }

    public void initIssuer() throws Exception {

        logger.info("Initializing ACME issuer");

        String className = issuerConfig.getClassName();
        Class<ACMEIssuer> issuerClass = (Class<ACMEIssuer>) Class.forName(className);

        issuer = issuerClass.newInstance();
        issuer.setConfig(issuerConfig);
        issuer.init();
    }

    public void shutdownIssuer() throws Exception {
        if (issuer != null)
            issuer.close();
    }

    public void start() throws Exception {

        logger.info("Starting ACME engine");

        String catalinaBase = System.getProperty("catalina.base");
        String serverConfDir = catalinaBase + File.separator + "conf";
        String acmeConfDir = serverConfDir + File.separator + name;

        logger.info("ACME configuration directory: " + acmeConfDir);

        // load config source configuration
        Properties monitorCfg = new Properties();
        String monitorCfgFilename = acmeConfDir + File.separator + "configsources.conf";
        logger.info("Loading ACME engine config from " + monitorCfgFilename);
        File f = new File(monitorCfgFilename);
        if (f.exists()) {
            try (FileReader reader = new FileReader(f)) {
                monitorCfg.load(reader);
            }
        } else {
            logger.info(
                "  '" + monitorCfgFilename + "' does not exist; "
                + "proceeding with default config sources"
            );
        }

        loadEngineConfig(monitorCfg);

        loadMetadata(acmeConfDir + File.separator + "metadata.conf");

        loadDatabaseConfig(acmeConfDir + File.separator + "database.conf");
        initDatabase();

        loadValidatorsConfig(acmeConfDir + File.separator + "validators.conf");
        initValidators();

        loadIssuerConfig(acmeConfDir + File.separator + "issuer.conf");
        initIssuer();

        logger.info("ACME engine started");
    }

    public void stop() throws Exception {

        logger.info("Stopping ACME engine");

        if (engineConfigSource != null) {
            engineConfigSource.shutdown();
            engineConfigSource = null;
        }

        shutdownIssuer();
        shutdownValidators();
        shutdownDatabase();

        logger.info("ACME engine stopped");
    }

    public ACMENonce createNonce() throws Exception {

        ACMENonce nonce = new ACMENonce();

        // generate 128-bit nonce with JSS
        // TODO: make it configurable

        byte[] bytes = new byte[16];
        SecureRandom random = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
        random.nextBytes(bytes);
        String value = Base64.encodeBase64URLSafeString(bytes);

        nonce.setValue(value);

        // set nonce to expire in 30 minutes
        // TODO: make it configurable

        long currentTime = System.currentTimeMillis();
        long expirationTime = currentTime + 30 * 60 * 1000;

        nonce.setExpirationTime(new Date(expirationTime));

        database.addNonce(nonce);
        logger.info("Created nonce: " + nonce);

        return nonce;
    }

    public void validateNonce(String value) throws Exception {

        ACMENonce nonce = database.removeNonce(value);

        if (nonce == null) {
            // TODO: generate proper exception
            throw new Exception("Invalid nonce: " + value);
        }

        long currentTime = System.currentTimeMillis();
        long expirationTime = nonce.getExpirationTime().getTime();

        if (expirationTime <= currentTime) {
            // TODO: generate proper exception
            throw new Exception("Expired nonce: " + value);
        }

        logger.info("Valid nonce: " + value);
    }

    public void purgeNonces() throws Exception {
        database.removeExpiredNonces(new Date());
    }

    public void validateJWS(JWS jws, String alg, JWK jwk) throws Exception {

        // TODO: support other algorithms

        Signature signer;
        PublicKey publicKey;

        if ("RS256".equals(alg)) {

            signer = Signature.getInstance("SHA256withRSA", "Mozilla-JSS");

            String kty = jwk.getKty();
            KeyFactory keyFactory = KeyFactory.getInstance(kty, "Mozilla-JSS");

            String n = jwk.getN();
            BigInteger modulus = new BigInteger(1, Base64.decodeBase64(n));

            String e = jwk.getE();
            BigInteger publicExponent = new BigInteger(1, Base64.decodeBase64(e));

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
            publicKey = keyFactory.generatePublic(keySpec);

        } else {
            throw new Exception("Unsupported JWS algorithm: " + alg);
        }

        validateJWS(jws, signer, publicKey);
    }

    public void validateJWS(JWS jws, Signature signer, PublicKey publicKey) throws Exception {

        logger.info("Validating JWS");

        // https://tools.ietf.org/html/rfc7515

        String message = jws.getProtectedHeader() + "." + jws.getPayload();
        byte[] signature = Base64.decodeBase64(jws.getSignature());

        signer.initVerify(publicKey);
        signer.update(message.getBytes());

        if (!signer.verify(signature)) {
            throw new Exception("Invalid JWS");
        }
    }

    public String generateThumbprint(JWK jwk) throws Exception {

        // JWK thumbprint
        // https://tools.ietf.org/html/rfc7638
        // TODO: make it configurable

        String data = jwk.toJSON();
        MessageDigest digest = MessageDigest.getInstance("SHA-256", "Mozilla-JSS");
        byte[] hash = digest.digest(data.getBytes("UTF-8"));
        return Base64.encodeBase64URLSafeString(hash);
    }

    public void createAccount(ACMEAccount account) throws Exception {
        database.addAccount(account);
    }

    public ACMEAccount getAccount(String accountID) throws Exception {
        return getAccount(accountID, true);
    }

    public ACMEAccount getAccount(String accountID, boolean validate) throws Exception {

        ACMEAccount account = database.getAccount(accountID);

        if (validate) {

            if (account == null) {
                throw createAccountDoesNotExistException(accountID);
            }

            validateAccount(accountID, account);
        }

        return account;
    }

    public void validateAccount(String accountID, ACMEAccount account) throws Exception {
        if (!"valid".equals(account.getStatus())) {

            logger.info("Invalid account: " + accountID);

            ResponseBuilder builder = Response.status(Response.Status.UNAUTHORIZED);
            builder.type("application/problem+json");

            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:unauthorized");
            error.setDetail("Invalid account: " + accountID);
            builder.entity(error);

            throw new WebApplicationException(builder.build());
        }
    }

    public Exception createAccountDoesNotExistException(String accountID) {

        logger.info("Account does not exist: " + accountID);

        ResponseBuilder builder = Response.status(Response.Status.BAD_REQUEST);
        builder.type("application/problem+json");

        ACMEError error = new ACMEError();
        error.setType("urn:ietf:params:acme:error:accountDoesNotExist");
        error.setDetail("Account does not exist on the server: " + accountID + "\n" +
                "Remove the account from the client, for example:\n" +
                "$ rm -rf /etc/letsencrypt/accounts/<ACME server>");
        builder.entity(error);

        return new WebApplicationException(builder.build());
    }

    public void updateAccount(ACMEAccount account) throws Exception {
        database.updateAccount(account);
    }

    public void addAuthorization(ACMEAccount account, ACMEAuthorization authorization) throws Exception {

        authorization.setAccountID(account.getID());

        // set authorizations to expire in 30 minutes
        // TODO: make it configurable

        long currentTime = System.currentTimeMillis();
        Date expirationTime = new Date(currentTime + 30 * 60 * 1000);

        authorization.setExpirationTime(expirationTime);

        database.addAuthorization(authorization);
    }

    public void validateAuthorization(ACMEAccount account, ACMEAuthorization authorization) throws Exception {

        String authzID = authorization.getID();

        if (!authorization.getAccountID().equals(account.getID())) {
            // TODO: generate proper exception
            throw new Exception("Unable to access authorization " + authzID);
        }

        long currentTime = System.currentTimeMillis();
        long expirationTime = authorization.getExpirationTime().getTime();

        if (expirationTime <= currentTime) {
            // TODO: generate proper exception
            throw new Exception("Expired authorization: " + authzID);
        }

        logger.info("Valid authorization: " + authzID);
    }

    public ACMEAuthorization getAuthorization(ACMEAccount account, String authzID) throws Exception {
        ACMEAuthorization authorization = database.getAuthorization(authzID);
        validateAuthorization(account, authorization);
        return authorization;
    }

    public ACMEAuthorization getAuthorizationByChallenge(ACMEAccount account, String challengeID) throws Exception {
        ACMEAuthorization authorization = database.getAuthorizationByChallenge(challengeID);
        validateAuthorization(account, authorization);
        return authorization;
    }

    public void updateAuthorization(ACMEAccount account, ACMEAuthorization authorization) throws Exception {
        validateAuthorization(account, authorization);
        database.updateAuthorization(authorization);
    }

    public void addOrder(ACMEAccount account, ACMEOrder order) throws Exception {

        order.setAccountID(account.getID());

        // set order to expire in 30 minutes
        // TODO: make it configurable

        long currentTime = System.currentTimeMillis();
        Date expirationTime = new Date(currentTime + 30 * 60 * 1000);

        order.setExpirationTime(expirationTime);

        database.addOrder(order);
    }

    enum CheckOrderResult { OrderAccountMismatch , OrderExpired , OrderAccessOK };

    public CheckOrderResult checkOrder(ACMEAccount account, ACMEOrder order) {

        String orderID = order.getID();

        if (!order.getAccountID().equals(account.getID())) {
            return CheckOrderResult.OrderAccountMismatch;
        }

        long currentTime = System.currentTimeMillis();
        long expirationTime = order.getExpirationTime().getTime();

        if (expirationTime <= currentTime) {
            return CheckOrderResult.OrderExpired;
        }

        return CheckOrderResult.OrderAccessOK;
    }

    public void validateOrder(ACMEAccount account, ACMEOrder order) throws Exception {
        switch (checkOrder(account, order)) {
            case OrderAccountMismatch:
                // TODO: generate proper exception
                throw new Exception("Unable to access order " + order.getID());
            case OrderExpired:
                // TODO: generate proper exception
                throw new Exception("Expired order: " + order.getID());
            case OrderAccessOK:
                logger.info("Valid order: " + order.getID());
                return;
        }
    }

    public ACMEOrder getOrder(ACMEAccount account, String orderID) throws Exception {
        ACMEOrder order = database.getOrder(orderID);
        validateOrder(account, order);
        return order;
    }

    public Collection<ACMEOrder> getOrdersByAuthorizationAndStatus(
            ACMEAccount account, String authzID, String status)
            throws Exception {
        Collection<ACMEOrder> orders = database.getOrdersByAuthorizationAndStatus(authzID, status);
        // remove orders that are expired or don't match the account ID
        orders.removeIf(o -> checkOrder(account, o) != CheckOrderResult.OrderAccessOK);
        return orders;
    }

    public void updateOrder(ACMEAccount account, ACMEOrder order) throws Exception {
        validateOrder(account, order);
        database.updateOrder(order);
    }

    public void validateCSR(ACMEAccount account, ACMEOrder order, PKCS10 pkcs10) throws Exception {

        logger.info("Getting authorized identifiers");
        Set<String> authorizedDNSNames = new HashSet<>();

        for (String authzID : order.getAuthzIDs()) {
            ACMEAuthorization authz = database.getAuthorization(authzID);

            // authz is guaranteed to be valid at this point

            ACMEIdentifier identifier = authz.getIdentifier();
            String type = identifier.getType();
            String value = identifier.getValue();

            // TODO: support other identifier types

            if ("dns".equals(type)) {

                Boolean b = authz.getWildcard();
                if (null != b && b) {
                    value = "*." + value; // add *. prefix
                }

                // store normalized authorized DNS names
                authorizedDNSNames.add(value.toLowerCase());
            }
        }

        logger.info("Authorized DNS names:");
        for (String dnsName : authorizedDNSNames) {
            logger.info("- " + dnsName);
        }

        logger.info("Parsing CSR");
        Set<String> dnsNames = new HashSet<>();
        parseCSR(pkcs10, dnsNames);

        logger.info("Validating DNS names in CSR");
        for (String dnsName : dnsNames) {
            logger.info("- " + dnsName);
        }

        // RFC 8555 §7.4 says: The CSR MUST indicate the exact same
        // set of requested identifiers as the initial newOrder request.

        // check for unauthorized names in CSR
        Set<String> unauthorizedDNSNames = new HashSet<>(dnsNames);
        unauthorizedDNSNames.removeAll(authorizedDNSNames);
        if (!unauthorizedDNSNames.isEmpty()) {
            // TODO: generate proper exception
            throw new Exception(
                "Unauthorized DNS names: "
                + StringUtils.join(unauthorizedDNSNames, ", "));
        }

        // check for authorized names missing from CSR
        Set<String> extraAuthorizedDNSNames = new HashSet<>(authorizedDNSNames);
        extraAuthorizedDNSNames.removeAll(dnsNames);
        if (!extraAuthorizedDNSNames.isEmpty()) {
            // TODO: generate proper exception
            throw new Exception(
                "Missing DNS names from order: "
                + StringUtils.join(extraAuthorizedDNSNames, ", "));
        }

        // TODO: validate other things in CSR

        logger.info("CSR is valid");
    }

    public void parseCSR(PKCS10 pkcs10, Set<String> dnsNames) throws Exception {

        X500Name subjectDN = pkcs10.getSubjectName();
        logger.info("Parsing subject DN: " + subjectDN);

        String cn;
        try {
            cn = subjectDN.getCommonName();

        } catch (NullPointerException e) {
            // X500Name.getCommonName() throws NPE if subject DN is blank
            // TODO: fix X500Name.getCommonName() to return null
            cn = null;
        }

        if (cn != null) {
            dnsNames.add(cn.toLowerCase());
        }

        logger.info("Parsing CSR Attributes:");
        PKCS10Attributes attributes = pkcs10.getAttributes();
        for (PKCS10Attribute attribute : attributes) {

            ObjectIdentifier attrID = attribute.getAttributeId();
            CertAttrSet attrValues = attribute.getAttributeValue();
            String attrName = attrValues.getName();
            logger.info("- " + attrID + ": " + attrName);

            // TODO: support other attributes

            if (attrValues instanceof Extensions) {
                Extensions extensions = (Extensions) attrValues;
                parseCSRExtensions(extensions, dnsNames);
            }
        }
    }

    public void parseCSRExtensions(Extensions extensions, Set<String> dnsNames) throws Exception {

        Enumeration<String> extNames = extensions.getAttributeNames();
        while (extNames.hasMoreElements()) {

            String name = extNames.nextElement();
            Object value = extensions.get(name);
            logger.info("  - " + name);

            // TODO: support other extensions

            if (value instanceof SubjectAlternativeNameExtension) {
                SubjectAlternativeNameExtension sanExt = (SubjectAlternativeNameExtension) value;
                parseCSRSAN(sanExt, dnsNames);
            }
        }
    }

    public void parseCSRSAN(SubjectAlternativeNameExtension sanExt, Set<String> dnsNames) throws Exception {

        GeneralNames generalNames = sanExt.getGeneralNames();
        for (GeneralNameInterface generalName : generalNames) {
            logger.info("    - " + generalName);

            if (generalName instanceof GeneralName) {
                generalName = ((GeneralName) generalName).unwrap();
            }

            // TODO: support other GeneralName types

            if (generalName instanceof DNSName) {
                String dnsName = ((DNSName) generalName).getValue();
                dnsNames.add(dnsName.toLowerCase());
            } else {
                // Unrecognised identifier type
                //
                // We cannot allow this to pass through, otherwise a CSR
                // with unvalidated SAN values will be passed along to the
                // CA, and these are likely to be accepted as-is.
                //
                // This is also required by RFC 8555 §7.4:
                //
                //    The CSR MUST indicate the exact same set of requested
                //    identifiers as the initial newOrder request.
                //
                throw new Exception("Unauthorized identifier: " + generalName.toString());
            }
        }
    }

    public void validateRevocation(ACMEAccount account, ACMERevocation revocation) throws Exception {

        // RFC 8555 Section 7.6: Certificate Revocation
        //
        // The server MUST consider at least the following accounts authorized
        // for a given certificate:
        // -  the account that issued the certificate.
        // -  an account that holds authorizations for all of the identifiers in
        //    the certificate.

        Date now = new Date();
        String certBase64 = revocation.getCertificate();
        byte[] certData = Utils.base64decode(certBase64);

        X509Certificate cert;
        try (ByteArrayInputStream is = new ByteArrayInputStream(certData)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(is);
        }

        String certID = issuer.getCertificateID(cert);

        // Case 1: validate using order record (if available)

        logger.info("Finding order that issued the certificate");
        ACMEOrder order = database.getOrderByCertificate(certID);

        if (order != null) {
            logger.info("Order ID: " + order.getID());

            // check order ownership
            if (order.getAccountID().equals(account.getID())) {
                // No need to check order status since it's guaranteed to be valid.
                // No need to check order expiration since it's irrelevant for revocation.
                logger.info("Account issued the certificate; revocation OK");
                return;
            } else {
                logger.info("Account did not issue the certificate");
            }
        }

        // Case 2: validate using authorization records (if available)

        logger.info("Getting certificate identifiers");
        // The identifiers obtained from the certificate may contain wildcards.
        Collection<ACMEIdentifier> identifiers = getCertIdentifiers(cert);

        if (identifiers.isEmpty()) {
            /* Protect against vacuous authorisation.  If there are no
             * identifiers, it could be e.g. a user or CA certificate.
             * Without this check that there are at least /some/ identifiers
             * to authorise, every account would be vacuously authorised
             * to revoke it.  */
            throw new Exception("Certificate has no ACME identifiers.");
        }

        try {
            for (ACMEIdentifier identifier : identifiers) {

                logger.info("Checking revocation authorization for " + identifier);

                if (!database.hasRevocationAuthorization(account.getID(), now, identifier)) {
                    logger.info("Account has no authorizations for " + identifier);

                    // TODO: generate proper exception
                    throw new Exception("Account has no authorizations for " + identifier);
                }
            }

        } catch (NotImplementedException e) {

            logger.info("Getting revocation authorizations");
            Collection<ACMEAuthorization> authzs = database.getRevocationAuthorizations(account.getID(), now);

            // remove authorized identifiers from the list
            for (ACMEAuthorization authz : authzs) {

                ACMEIdentifier authzIdentifier = authz.getIdentifier();
                String type = authzIdentifier.getType();

                if ("dns".equals(type) && authz.getWildcard()) {

                    // append *. prefix so the identifiers can be compared
                    String value = "*." + authzIdentifier.getValue();

                    authzIdentifier = new ACMEIdentifier();
                    authzIdentifier.setType(type);
                    authzIdentifier.setValue(value);
                }

                identifiers.remove(authzIdentifier);
            }

            if (!identifiers.isEmpty()) {
                logger.info("Account has no authorizations for:");
                for (ACMEIdentifier identifier : identifiers) {
                    logger.info("- " + identifier.getType() + ": " + identifier.getValue());
                 }

                // TODO: generate proper exception
                throw new Exception("Account has no authorizations for " + identifiers);
            }
        }

        logger.info("Account has authorizations for all identifiers");
    }

    public Collection<ACMEIdentifier> getCertIdentifiers(X509Certificate cert) throws Exception {

        // use HashSet to store cert identifiers without duplicates
        Collection<ACMEIdentifier> identifiers = new HashSet<>();

        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
        X500Name subjectDN = certImpl.getSubjectObj().getX500Name();
        logger.info("Subject DN: " + subjectDN);

        String cn;
        try {
            cn = subjectDN.getCommonName();

        } catch (NullPointerException e) {
            // X500Name.getCommonName() throws NPE if subject DN is blank
            // TODO: fix X500Name.getCommonName() to return null
            cn = null;
        }

        if (cn != null) {
            ACMEIdentifier identifier = new ACMEIdentifier("dns", cn.toLowerCase());
            identifiers.add(identifier);
        }

        logger.info("SAN extensions:");
        Collection<List<?>> sanExtensions = cert.getSubjectAlternativeNames();

        if (sanExtensions != null) {
            for (List<?> sanExtension : sanExtensions) {
                Integer type = (Integer) sanExtension.get(0);
                Object value = sanExtension.get(1);
                logger.info("- " + value);

                if (type == 2) {
                    String dnsName = (String) value;
                    ACMEIdentifier identifier = new ACMEIdentifier("dns", dnsName);
                    identifiers.add(identifier);
                }

                // TODO: support other identifier types
            }
        }

        return identifiers;
    }

    public void contextInitialized(ServletContextEvent event) {

        String path = event.getServletContext().getContextPath();
        if ("".equals(path)) {
            name = "ROOT";
        } else {
            name = path.substring(1);
        }

        try {
            start();

        } catch (Exception e) {
            logger.error("Unable to start ACME engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to start ACME engine: " + e.getMessage(), e);
        }
    }

    public void contextDestroyed(ServletContextEvent event) {

        try {
            stop();

        } catch (Exception e) {
            logger.error("Unable to stop ACME engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to stop ACME engine: " + e.getMessage(), e);
        }
    }
}
