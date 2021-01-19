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
import java.security.Principal;
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
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.apache.catalina.realm.RealmBase;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ACMEMetadata;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.ACMERevocation;
import org.dogtagpki.acme.JWK;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.database.ACMEDatabase;
import org.dogtagpki.acme.database.ACMEDatabaseConfig;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.dogtagpki.acme.issuer.ACMEIssuerConfig;
import org.dogtagpki.acme.realm.ACMERealm;
import org.dogtagpki.acme.realm.ACMERealmConfig;
import org.dogtagpki.acme.scheduler.ACMEScheduler;
import org.dogtagpki.acme.scheduler.ACMESchedulerConfig;
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

import com.netscape.cms.tomcat.ProxyRealm;

/**
 * @author Endi S. Dewata
 */
@WebListener
public class ACMEEngine implements ServletContextListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEEngine.class);

    public static ACMEEngine INSTANCE;

    private String name;

    private ACMEEngineConfig config;
    private ACMEPolicy policy;

    private Properties monitorsConfig;
    private ACMEEngineConfigSource engineConfigSource = null;

    public Random random;

    private ACMEMetadata metadata;

    private ACMEDatabaseConfig databaseConfig;
    private ACMEDatabase database;

    private ACMEValidatorsConfig validatorsConfig;
    private Map<String, ACMEValidator> validators = new HashMap<>();

    private ACMEIssuerConfig issuerConfig;
    private ACMEIssuer issuer;

    private ACMESchedulerConfig schedulerConfig;
    private ACMEScheduler scheduler;

    private ACMERealmConfig realmConfig;
    private ACMERealm realm;

    private boolean noncesPersistent;
    private Map<String, ACMENonce> nonces = new ConcurrentHashMap<>();

    public static ACMEEngine getInstance() {
        return INSTANCE;
    }

    public ACMEEngine() {
        INSTANCE = this;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the local policy configuration object.
     */
    public ACMEPolicy getPolicy() {
        return policy;
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
        return config.isEnabled();
    }

    public void setEnabled(boolean enabled) {
        config.setEnabled(enabled);
    }

    public void loadConfig(String filename) throws Exception {

        File configFile = new File(filename);

        if (!configFile.exists()) {
            configFile = new File("/usr/share/pki/acme/conf/engine.conf");
        }

        logger.info("Loading ACME engine config from " + configFile);
        Properties props = new Properties();
        try (FileReader reader = new FileReader(configFile)) {
            props.load(reader);
        }

        config = ACMEEngineConfig.fromProperties(props);
        logger.info("- enabled: " + config.isEnabled());
        logger.info("- nonces persistent: " + config.getNoncesPersistent());

        ACMEPolicyConfig policyConfig = config.getPolicyConfig();
        logger.info("- wildcard: " + policyConfig.getEnableWildcards());
        logger.info("- nonce retention: " + policyConfig.getRetention().getNonces());
        logger.info("- authorization retention:");
        logger.info("  - pending: " + policyConfig.getRetention().getPendingAuthorizations());
        logger.info("  - invalid: " + policyConfig.getRetention().getInvalidAuthorizations());
        logger.info("  - valid: " + policyConfig.getRetention().getValidAuthorizations());
        logger.info("- order retention:");
        logger.info("  - pending: " + policyConfig.getRetention().getPendingOrders());
        logger.info("  - invalid: " + policyConfig.getRetention().getInvalidOrders());
        logger.info("  - ready: " + policyConfig.getRetention().getReadyOrders());
        logger.info("  - processing: " + policyConfig.getRetention().getProcessingOrders());
        logger.info("  - valid: " + policyConfig.getRetention().getValidOrders());
        logger.info("- certificate retention: " + policyConfig.getRetention().getCertificates());

        policy = new ACMEPolicy(policyConfig);
    }

    public void initRandomGenerator() throws Exception {
        random = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
    }

    public void initMetadata(String filename) throws Exception {

        File metadataConfigFile = new File(filename);

        if (!metadataConfigFile.exists()) {
            metadataConfigFile = new File("/usr/share/pki/acme/conf/metadata.conf");
        }

        logger.info("Loading ACME metadata from " + metadataConfigFile);
        Properties props = new Properties();
        try (FileReader reader = new FileReader(metadataConfigFile)) {
            props.load(reader);
        }
        metadata = ACMEMetadata.fromProperties(props);
    }

    public void initDatabase(String filename) throws Exception {

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

        logger.info("Initializing ACME database");

        String className = databaseConfig.getClassName();
        Class<ACMEDatabase> databaseClass = (Class<ACMEDatabase>) Class.forName(className);

        database = databaseClass.newInstance();
        database.setConfig(databaseConfig);
        database.init();
    }

    public void initValidators(String filename) throws Exception {

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

    public void initIssuer(String filename) throws Exception {

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

        logger.info("Initializing ACME issuer");

        String className = issuerConfig.getClassName();
        Class<ACMEIssuer> issuerClass = (Class<ACMEIssuer>) Class.forName(className);

        issuer = issuerClass.newInstance();
        issuer.setConfig(issuerConfig);
        issuer.init();
    }

    public void initScheduler(String filename) throws Exception {

        File schedulerConfigFile = new File(filename);

        if (!schedulerConfigFile.exists()) {
            schedulerConfigFile = new File("/usr/share/pki/acme/conf/scheduler.conf");
        }

        logger.info("Loading ACME scheduler config from " + schedulerConfigFile);
        Properties props = new Properties();
        try (FileReader reader = new FileReader(schedulerConfigFile)) {
            props.load(reader);
        }
        schedulerConfig = ACMESchedulerConfig.fromProperties(props);

        logger.info("Initializing ACME scheduler");

        scheduler = new ACMEScheduler();
        scheduler.setConfig(schedulerConfig);
        scheduler.init();
    }

    public void initMonitors(String filename) throws Exception {

        File monitorsConfigFile = new File(filename);
        monitorsConfig = new Properties();

        if (monitorsConfigFile.exists()) {
            logger.info("Loading ACME monitors config from " + filename);
            try (FileReader reader = new FileReader(monitorsConfigFile)) {
                monitorsConfig.load(reader);
            }

        } else {
            logger.info("Using default ACME monitors config");
        }

        // the default class just sends the default config values
        Class<? extends ACMEEngineConfigSource> configSourceClass
            = ACMEEngineConfigDefaultSource.class;

        String className = monitorsConfig.getProperty("engine.class");
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
                config.setEnabled(b);
                logger.info(
                    "ACME service is "
                    + (b ? "enabled" : "DISABLED")
                    + " by configuration"
                );
            }
        });

        engineConfigSource.setWildcardConsumer(new Consumer<Boolean>() {
            @Override public void accept(Boolean b) {
                config.getPolicyConfig().setEnableWildcards(b);
                logger.info(
                    "ACME wildcard issuance is "
                    + (b ? "enabled" : "DISABLED")
                    + " by configuration"
                );
            }
        });

        engineConfigSource.init(monitorsConfig);
    }

    public void initRealm(String filename) throws Exception {

        File realmConfigFile = new File(filename);

        if (realmConfigFile.exists()) {
            logger.info("Loading ACME realm config from " + realmConfigFile);
            Properties props = new Properties();
            try (FileReader reader = new FileReader(realmConfigFile)) {
                props.load(reader);
            }
            realmConfig = ACMERealmConfig.fromProperties(props);

        } else {
            logger.info("Loading default ACME realm config");
            realmConfig = new ACMERealmConfig();
        }

        logger.info("Initializing ACME realm");

        String className = realmConfig.getClassName();
        Class<ACMERealm> realmClass = (Class<ACMERealm>) Class.forName(className);

        realm = realmClass.newInstance();
        realm.setConfig(realmConfig);
        realm.init();

        ProxyRealm.registerRealm(name, new RealmBase() {
            @Override
            public Principal getPrincipal(String username) {
                return null;
            }

            @Override
            public String getPassword(String username) {
                return null;
            }

            @Override
            public Principal authenticate(String username, String password) {
                try {
                    return realm.authenticate(username, password);
                } catch (Exception e) {
                    logger.warn("Unable to authenticate with username: " + e.getMessage(), e);
                    throw new RuntimeException(e);
                }
            }

            @Override
            public Principal authenticate(final X509Certificate[] certs) {
                try {
                    return realm.authenticate(certs);
                } catch (Exception e) {
                    logger.warn("Unable to authenticate with certificate: " + e.getMessage(), e);
                    throw new RuntimeException(e);
                }
            }
        });
    }

    public void start() throws Exception {

        logger.info("Starting ACME engine");

        String catalinaBase = System.getProperty("catalina.base");
        String serverConfDir = catalinaBase + File.separator + "conf";
        String acmeConfDir = serverConfDir + File.separator + name;

        logger.info("ACME configuration directory: " + acmeConfDir);
        loadConfig(acmeConfDir + File.separator + "engine.conf");

        Boolean noncePersistent = config.getNoncesPersistent();
        this.noncesPersistent =  noncePersistent != null ? noncePersistent : false;

        initRandomGenerator();
        initMetadata(acmeConfDir + File.separator + "metadata.conf");
        initDatabase(acmeConfDir + File.separator + "database.conf");
        initValidators(acmeConfDir + File.separator + "validators.conf");
        initIssuer(acmeConfDir + File.separator + "issuer.conf");
        initScheduler(acmeConfDir + File.separator + "scheduler.conf");
        initMonitors(acmeConfDir + File.separator + "configsources.conf");
        initRealm(acmeConfDir + File.separator + "realm.conf");

        logger.info("ACME engine started");
    }

    public void shutdownDatabase() throws Exception {
        if (database == null) return;

        database.close();
        database = null;
    }

    public void shutdownValidators() throws Exception {

        for (ACMEValidator validator : validators.values()) {
            validator.close();
        }

        validators.clear();
    }

    public void shutdownIssuer() throws Exception {
        if (issuer == null) return;

        issuer.close();
        issuer = null;
    }

    public void shutdownScheduler() throws Exception {
        if (scheduler == null) return;

        scheduler.shutdown();
        scheduler = null;
    }

    public void shutdownMonitors() throws Exception {
        if (engineConfigSource == null) return;

        engineConfigSource.shutdown();
        engineConfigSource = null;
    }

    public void shutdownRealm() throws Exception {
        if (realm == null) return;

        realm.close();
        realm = null;
    }

    public void stop() throws Exception {

        logger.info("Stopping ACME engine");

        shutdownRealm();
        shutdownMonitors();
        shutdownScheduler();
        shutdownIssuer();
        shutdownValidators();
        shutdownDatabase();

        logger.info("ACME engine stopped");
    }

    public String randomAlphanumeric(int length) {
        // Wrap RandomStringUtils.random instead of calling randomAlphanumeric
        // so that we control choice of RNG.
        return RandomStringUtils.random(length, 0, 0, true, true, null, random);
    }

    public ACMENonce createNonce() throws Exception {

        Date currentTime = new Date();
        ACMENonce nonce = new ACMENonce();

        // generate 128-bit nonce with JSS
        // TODO: make it configurable

        byte[] bytes = new byte[16];
        SecureRandom random = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
        random.nextBytes(bytes);
        String nonceID = Base64.encodeBase64URLSafeString(bytes);

        nonce.setID(nonceID);
        nonce.setCreationTime(currentTime);

        Date expirationTime = policy.getNonceExpirationTime(currentTime);
        nonce.setExpirationTime(expirationTime);

        if (noncesPersistent) {
            database.addNonce(nonce);
        } else {
            nonces.put(nonce.getID(), nonce);
        }

        logger.info("Created nonce: " + nonce);

        return nonce;
    }

    public void validateNonce(String value) throws Exception {

        ACMENonce nonce;

        if (noncesPersistent) {
            nonce = database.removeNonce(value);
        } else {
            nonce = nonces.remove(value);
        }

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

    public void removeExpiredRecords(Date currentTime) throws Exception {

        if (noncesPersistent) {
            database.removeExpiredNonces(currentTime);
        } else {
            nonces.values().removeIf(n -> !currentTime.before(n.getExpirationTime()));
        }

        database.removeExpiredAuthorizations(currentTime);
        database.removeExpiredOrders(currentTime);
        database.removeExpiredCertificates(currentTime);
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
        database.addAuthorization(authorization);
    }

    public void validateAuthorization(ACMEAccount account, ACMEAuthorization authorization) throws Exception {

        String authzID = authorization.getID();

        if (!authorization.getAccountID().equals(account.getID())) {
            // TODO: generate proper exception
            throw new Exception("Unable to access authorization " + authzID);
        }

        long currentTime = System.currentTimeMillis();
        Date expirationTime = authorization.getExpirationTime();

        if (expirationTime != null && expirationTime.getTime() <= currentTime) {
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
        database.addOrder(order);
    }

    enum CheckOrderResult { OrderAccountMismatch , OrderExpired , OrderAccessOK };

    public CheckOrderResult checkOrder(ACMEAccount account, ACMEOrder order) {

        String orderID = order.getID();
        if (!order.getAccountID().equals(account.getID())) {
            return CheckOrderResult.OrderAccountMismatch;
        }

        Date expirationTime = order.getExpirationTime();
        if (expirationTime == null) {
            return CheckOrderResult.OrderAccessOK;
        }

        long currentTime = System.currentTimeMillis();
        if (expirationTime.getTime() <= currentTime) {
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

    public Collection<ACMEOrder> getOrdersByAccount(ACMEAccount account) throws Exception {
        return database.getOrdersByAccount(account.getID());
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

        // RFC 8555 Section 7.4 says: The CSR MUST indicate the exact same
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
                // This is also required by RFC 8555 Section 7.4:
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
