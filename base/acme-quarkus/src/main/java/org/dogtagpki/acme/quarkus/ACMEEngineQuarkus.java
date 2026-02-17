//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.net.URL;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEException;
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
import org.dogtagpki.acme.scheduler.ACMEScheduler;
import org.dogtagpki.acme.scheduler.ACMESchedulerConfig;
import org.dogtagpki.acme.server.ACMEEngineConfig;
import org.dogtagpki.acme.server.ACMEPolicy;
import org.dogtagpki.acme.server.ACMEPolicyConfig;
import org.dogtagpki.acme.validator.ACMEValidator;
import org.dogtagpki.acme.validator.ACMEValidatorConfig;
import org.dogtagpki.acme.validator.ACMEValidatorsConfig;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.QuarkusInstanceConfig;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;

/**
 * ACME Engine for Quarkus.
 *
 * Replicates ACMEEngine's lifecycle and business logic using CDI
 * instead of extending CMSEngine (which depends on Tomcat).
 * Uses @ApplicationScoped and @Observes StartupEvent/ShutdownEvent
 * for lifecycle management.
 *
 * @author Endi S. Dewata (original ACMEEngine)
 */
@ApplicationScoped
public class ACMEEngineQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(ACMEEngineQuarkus.class);

    // Singleton reference for access from non-CDI classes (e.g., challenge processor)
    public static ACMEEngineQuarkus INSTANCE;

    private String id = "acme";
    private ACMEEngineConfig config;
    private ACMEPolicy policy;

    // ACMEEngineConfigSource is package-private in pki-acme, so we use
    // Object and reflection to manage it from this package.
    private Object engineConfigSource = null;

    public Random random;

    private ACMEMetadata metadata;

    private ACMEDatabaseConfig databaseConfig;
    private ACMEDatabase database;

    private ACMEValidatorsConfig validatorsConfig;
    private Map<String, ACMEValidator> validators = new HashMap<>();

    private ACMEIssuerConfig issuerConfig;
    private ACMEIssuer issuer;

    private ACMEScheduler scheduler;

    private boolean noncesPersistent;
    private Map<String, ACMENonce> nonces = new ConcurrentHashMap<>();

    public static ACMEEngineQuarkus getInstance() {
        return INSTANCE;
    }

    void onStart(@Observes StartupEvent event) {
        INSTANCE = this;
        try {
            start();
        } catch (Throwable e) {
            logger.error("Failed to start ACME engine: " + e.getMessage(), e);
            throw new RuntimeException("Failed to start ACME engine", e);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Failed to stop ACME engine: " + e.getMessage(), e);
        }
    }

    // ---- Accessors ----

    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    public ACMEPolicy getPolicy() {
        return policy;
    }

    public ACMEMetadata getMetadata() {
        return metadata;
    }

    public ACMEDatabase getDatabase() {
        return database;
    }

    public Collection<ACMEValidator> getValidators() {
        return validators.values();
    }

    public ACMEValidator getValidator(String name) {
        return validators.get(name);
    }

    public ACMEIssuer getIssuer() {
        return issuer;
    }

    public boolean isEnabled() {
        return config.isEnabled();
    }

    public URL getBaseURL() {
        return config.getBaseURL();
    }

    // ---- Lifecycle ----

    public void start() throws Exception {

        logger.info("Starting ACME engine (Quarkus)");

        // Configure InstanceConfig for Quarkus deployment
        String instanceDir = System.getProperty(QuarkusInstanceConfig.INSTANCE_DIR_PROPERTY);
        if (instanceDir != null) {
            CMS.setInstanceConfig(new QuarkusInstanceConfig());
            logger.info("ACME: Using Quarkus instance dir: {}", instanceDir);
        }

        String confDir = CMS.getInstanceDir();
        String acmeConfDir = confDir + File.separator + "conf" + File.separator + id;

        logger.info("ACME configuration directory: " + acmeConfDir);

        loadEngineConfig(acmeConfDir + File.separator + "engine.conf");

        Boolean noncePersistent = config.getNoncesPersistent();
        this.noncesPersistent = noncePersistent != null ? noncePersistent : false;

        initRandomGenerator();
        initMetadata(acmeConfDir + File.separator + "metadata.conf");
        initDatabase(acmeConfDir + File.separator + "database.conf");
        initValidators(acmeConfDir + File.separator + "validators.conf");
        initIssuer(acmeConfDir + File.separator + "issuer.conf");
        initScheduler(acmeConfDir + File.separator + "scheduler.conf");
        initMonitors(acmeConfDir + File.separator + "configsources.conf");

        logger.info("ACME engine started");
    }

    public void stop() throws Exception {

        logger.info("Stopping ACME engine");

        shutdownMonitors();
        shutdownScheduler();
        shutdownIssuer();
        shutdownValidators();
        shutdownDatabase();

        logger.info("ACME engine stopped");
    }

    // ---- Initialization Methods ----

    public void loadEngineConfig(String filename) throws Exception {

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
        logger.info("- base URL: " + config.getBaseURL());
        logger.info("- nonces persistent: " + config.getNoncesPersistent());

        ACMEPolicyConfig policyConfig = config.getPolicyConfig();
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

    @SuppressWarnings("unchecked")
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

        database = databaseClass.getDeclaredConstructor().newInstance();
        database.setConfig(databaseConfig);
        database.init();
    }

    @SuppressWarnings("unchecked")
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

            ACMEValidator validator = validatorClass.getDeclaredConstructor().newInstance();
            validator.setConfig(validatorConfig);
            validator.init();

            validators.put(name, validator);
        }
    }

    @SuppressWarnings("unchecked")
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

        issuer = issuerClass.getDeclaredConstructor().newInstance();
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
        ACMESchedulerConfig schedulerConfig = ACMESchedulerConfig.fromProperties(props);

        logger.info("Initializing ACME scheduler");

        scheduler = new ACMEScheduler();
        scheduler.setConfig(schedulerConfig);
        scheduler.init();
    }

    public void initMonitors(String filename) throws Exception {

        File monitorsConfigFile = new File(filename);
        Properties monitorsConfig = new Properties();

        if (monitorsConfigFile.exists()) {
            logger.info("Loading ACME monitors config from " + filename);
            try (FileReader reader = new FileReader(monitorsConfigFile)) {
                monitorsConfig.load(reader);
            }
        } else {
            logger.info("Using default ACME monitors config");
        }

        String className = monitorsConfig.getProperty("engine.class");
        if (className == null || className.isEmpty()) {
            logger.info("No engine config source class specified, skipping monitors");
            return;
        }

        // ACMEEngineConfigSource is package-private in org.dogtagpki.acme.server,
        // so we use reflection to instantiate and configure it.
        Class<?> configSourceClass = Class.forName(className);
        engineConfigSource = configSourceClass.getDeclaredConstructor().newInstance();

        // Set consumers via reflection
        java.lang.reflect.Method setEnabledConsumer =
            configSourceClass.getMethod("setEnabledConsumer", Consumer.class);
        setEnabledConsumer.invoke(engineConfigSource, new Consumer<Boolean>() {
            @Override public void accept(Boolean b) {
                config.setEnabled(b);
                logger.info(
                    "ACME service is "
                    + (b ? "enabled" : "DISABLED")
                    + " by configuration"
                );
            }
        });

        java.lang.reflect.Method setWildcardConsumer =
            configSourceClass.getMethod("setWildcardConsumer", Consumer.class);
        setWildcardConsumer.invoke(engineConfigSource, new Consumer<Boolean>() {
            @Override public void accept(Boolean b) {
                config.getPolicyConfig().setEnableWildcards(b);
                logger.info(
                    "ACME wildcard issuance is "
                    + (b ? "enabled" : "DISABLED")
                    + " by configuration"
                );
            }
        });

        java.lang.reflect.Method init =
            configSourceClass.getMethod("init", Properties.class);
        init.invoke(engineConfigSource, monitorsConfig);
    }

    // ---- Shutdown Methods ----

    public void shutdownDatabase() {
        if (database == null) return;
        try {
            database.close();
        } catch (Exception e) {
            logger.error("Error closing the database", e);
        }
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
        try {
            java.lang.reflect.Method shutdown =
                engineConfigSource.getClass().getMethod("shutdown");
            shutdown.invoke(engineConfigSource);
        } catch (NoSuchMethodException e) {
            // shutdown() may not exist in all implementations
        }
        engineConfigSource = null;
    }

    // ---- Nonce Management ----

    public String randomAlphanumeric(int length) {
        return RandomStringUtils.random(length, 0, 0, true, true, null, random);
    }

    public ACMENonce createNonce() throws Exception {

        Date currentTime = new Date();
        ACMENonce nonce = new ACMENonce();

        byte[] bytes = new byte[16];
        SecureRandom rng = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
        rng.nextBytes(bytes);
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
            throw new Exception("Invalid nonce: " + value);
        }

        long currentTime = System.currentTimeMillis();
        long expirationTime = nonce.getExpirationTime().getTime();

        if (expirationTime <= currentTime) {
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

    // ---- JWS / Cryptography ----

    public void validateJWS(JWS jws, String alg, JWK jwk) throws Exception {

        Signature signer;
        PublicKey publicKey;
        byte[] jwsSignature;

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
            jwsSignature = Base64.decodeBase64(jws.getSignature());

        } else if ("ES256".equals(alg)) {

            signer = Signature.getInstance("SHA256withECDSA", "Mozilla-JSS");

            String kty = jwk.getKty();
            KeyFactory keyFactory = KeyFactory.getInstance(kty, "Mozilla-JSS");
            AlgorithmParameters algoParameters = AlgorithmParameters.getInstance(kty);

            String crv = jwk.getCrv();
            ECGenParameterSpec ecGenParameterSpec;
            if ("P-256".equals(crv)) {
                ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
            } else {
                ACMEError error = new ACMEError();
                error.setType("urn:ietf:params:acme:error:badSignatureAlgorithm");
                error.setDetail("EC curve of type " + crv + " not supported\n" +
                                "Try again with P-256.");
                throw new ACMEException(400, error);
            }
            algoParameters.init(ecGenParameterSpec);
            ECParameterSpec ecParameterSpec = algoParameters.getParameterSpec(ECParameterSpec.class);

            String x = jwk.getX();
            BigInteger biX = new BigInteger(1, Base64.decodeBase64(x));

            String y = jwk.getY();
            BigInteger biY = new BigInteger(1, Base64.decodeBase64(y));

            ECPoint ecPoint = new ECPoint(biX, biY);
            ECPublicKeySpec ecKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
            publicKey = keyFactory.generatePublic(ecKeySpec);

            byte[] rawSign = Base64.decodeBase64(jws.getSignature());

            // JWS signature is the combination of the pair (R, S) but JSS expects
            // the pair in an ASN1 Sequence
            SEQUENCE seq = new SEQUENCE();
            INTEGER i1 = new INTEGER(Arrays.copyOfRange(rawSign, 0, 32));
            INTEGER i2 = new INTEGER(Arrays.copyOfRange(rawSign, 32, 64));
            seq.addElement(i1);
            seq.addElement(i2);
            jwsSignature = ASN1Util.encode(seq);

        } else {
            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:badSignatureAlgorithm");
            error.setDetail("Signature of type " + alg + " not supported\n" +
                    "Try again with RS256.");
            throw new ACMEException(400, error);
        }

        logger.info("Validating JWS");

        String message = jws.getProtectedHeader() + "." + jws.getPayload();

        signer.initVerify(publicKey);
        signer.update(message.getBytes());

        if (!signer.verify(jwsSignature)) {
            throw new Exception("Invalid JWS");
        }
    }

    public String generateThumbprint(JWK jwk) throws Exception {
        String data = jwk.toJSON();
        MessageDigest digest = MessageDigest.getInstance("SHA-256", "Mozilla-JSS");
        byte[] hash = digest.digest(data.getBytes("UTF-8"));
        return Base64.encodeBase64URLSafeString(hash);
    }

    // ---- Account Management ----

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

            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:unauthorized");
            error.setDetail("Invalid account: " + accountID);

            throw new ACMEException(401, error);
        }
    }

    public ACMEException createAccountDoesNotExistException(String accountID) {
        logger.info("Account does not exist: " + accountID);

        ACMEError error = new ACMEError();
        error.setType("urn:ietf:params:acme:error:accountDoesNotExist");
        error.setDetail("Account does not exist on the server: " + accountID + "\n" +
                "Remove the account from the client, for example:\n" +
                "$ rm -rf /etc/letsencrypt/accounts/<ACME server>");

        return new ACMEException(400, error);
    }

    public ACMEException createMalformedException(String desc) {
        ACMEError error = new ACMEError();
        error.setType("urn:ietf:params:acme:error:malformed");
        error.setDetail("Malformed request: " + desc);

        return new ACMEException(400, error);
    }

    public void updateAccount(ACMEAccount account) throws Exception {
        database.updateAccount(account);
    }

    // ---- Authorization Management ----

    public void addAuthorization(ACMEAccount account, ACMEAuthorization authorization) throws Exception {
        authorization.setAccountID(account.getID());
        database.addAuthorization(authorization);
    }

    public void validateAuthorization(ACMEAccount account, ACMEAuthorization authorization) throws Exception {
        String authzID = authorization.getID();

        if (!authorization.getAccountID().equals(account.getID())) {
            throw new Exception("Unable to access authorization " + authzID);
        }

        long currentTime = System.currentTimeMillis();
        Date expirationTime = authorization.getExpirationTime();

        if (expirationTime != null && expirationTime.getTime() <= currentTime) {
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

    // ---- Order Management ----

    public void addOrder(ACMEAccount account, ACMEOrder order) throws Exception {
        order.setAccountID(account.getID());
        database.addOrder(order);
    }

    enum CheckOrderResult { ORDER_ACCOUNT_MISMATCH, ORDER_EXPIRED, ORDER_ACCESS_OK, ORDER_NULL }

    public CheckOrderResult checkOrder(ACMEAccount account, ACMEOrder order) {
        if (order == null) {
            return CheckOrderResult.ORDER_NULL;
        }
        if (!order.getAccountID().equals(account.getID())) {
            return CheckOrderResult.ORDER_ACCOUNT_MISMATCH;
        }
        Date expirationTime = order.getExpirationTime();
        if (expirationTime == null) {
            return CheckOrderResult.ORDER_ACCESS_OK;
        }
        long currentTime = System.currentTimeMillis();
        if (expirationTime.getTime() <= currentTime) {
            return CheckOrderResult.ORDER_EXPIRED;
        }
        return CheckOrderResult.ORDER_ACCESS_OK;
    }

    public void validateOrder(ACMEAccount account, ACMEOrder order) throws Exception {
        switch (checkOrder(account, order)) {
            case ORDER_ACCOUNT_MISMATCH -> throw new Exception("Unable to access order " + order.getID());
            case ORDER_EXPIRED -> throw new Exception("Expired order: " + order.getID());
            case ORDER_NULL -> throw new Exception("Order not found");
            case ORDER_ACCESS_OK -> logger.info("Valid order: " + order.getID());
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
            ACMEAccount account, String authzID, String status) throws Exception {
        Collection<ACMEOrder> orders = database.getOrdersByAuthorizationAndStatus(authzID, status);
        orders.removeIf(o -> checkOrder(account, o) != CheckOrderResult.ORDER_ACCESS_OK);
        return orders;
    }

    public void updateOrder(ACMEAccount account, ACMEOrder order) throws Exception {
        validateOrder(account, order);
        database.updateOrder(order);
    }

    // ---- CSR Validation ----

    public void validateCSR(ACMEAccount account, ACMEOrder order, PKCS10 pkcs10) throws Exception {

        logger.info("Getting authorized identifiers");
        Set<String> authorizedDNSNames = new HashSet<>();

        for (String authzID : order.getAuthzIDs()) {
            ACMEAuthorization authz = database.getAuthorization(authzID);

            ACMEIdentifier identifier = authz.getIdentifier();
            String type = identifier.getType();
            String value = identifier.getValue();

            if ("dns".equals(type)) {
                Boolean b = authz.getWildcard();
                if (null != b && b) {
                    value = "*." + value;
                }
                authorizedDNSNames.add(value.toLowerCase());
            }
        }

        logger.info("Getting DNS names from CSR");
        Set<String> dnsNames = CertUtil.getDNSNames(pkcs10);

        Set<String> unauthorizedDNSNames = new HashSet<>(dnsNames);
        unauthorizedDNSNames.removeAll(authorizedDNSNames);
        if (!unauthorizedDNSNames.isEmpty()) {
            throw new Exception(
                "Unauthorized DNS names: "
                + StringUtils.join(unauthorizedDNSNames, ", "));
        }

        Set<String> extraAuthorizedDNSNames = new HashSet<>(authorizedDNSNames);
        extraAuthorizedDNSNames.removeAll(dnsNames);
        if (!extraAuthorizedDNSNames.isEmpty()) {
            throw new Exception(
                "Missing DNS names from order: "
                + StringUtils.join(extraAuthorizedDNSNames, ", "));
        }

        logger.info("CSR is valid");
    }

    // ---- Revocation Validation ----

    public void validateRevocation(ACMEAccount account, ACMERevocation revocation) throws Exception {

        Date now = new Date();
        String certBase64 = revocation.getCertificate();
        byte[] certData = Utils.base64decode(certBase64);
        X509CertImpl cert = new X509CertImpl(certData);

        String certID = issuer.getCertificateID(cert);

        logger.info("Finding order that issued the certificate");
        ACMEOrder order = database.getOrderByCertificate(certID);

        if (order != null) {
            logger.info("Order ID: " + order.getID());
            if (order.getAccountID().equals(account.getID())) {
                logger.info("Account issued the certificate; revocation OK");
                return;
            }
            logger.info("Account did not issue the certificate");
        }

        logger.info("Getting certificate identifiers");
        Collection<ACMEIdentifier> identifiers = getCertIdentifiers(cert);

        if (identifiers.isEmpty()) {
            throw new Exception("Certificate has no ACME identifiers.");
        }

        try {
            for (ACMEIdentifier identifier : identifiers) {
                logger.info("Checking revocation authorization for " + identifier);
                if (!database.hasRevocationAuthorization(account.getID(), now, identifier)) {
                    logger.info("Account has no authorizations for " + identifier);
                    throw new Exception("Account has no authorizations for " + identifier);
                }
            }
        } catch (NotImplementedException e) {
            logger.info("Getting revocation authorizations");
            Collection<ACMEAuthorization> authzs = database.getRevocationAuthorizations(account.getID(), now);

            for (ACMEAuthorization authz : authzs) {
                ACMEIdentifier authzIdentifier = authz.getIdentifier();
                String type = authzIdentifier.getType();
                if ("dns".equals(type) && authz.getWildcard()) {
                    String value = "*." + authzIdentifier.getValue();
                    authzIdentifier = new ACMEIdentifier();
                    authzIdentifier.setType(type);
                    authzIdentifier.setValue(value);
                }
                identifiers.remove(authzIdentifier);
            }

            if (!identifiers.isEmpty()) {
                throw new Exception("Account has no authorizations for " + identifiers);
            }
        }

        logger.info("Account has authorizations for all identifiers");
    }

    public Collection<ACMEIdentifier> getCertIdentifiers(X509Certificate cert) throws Exception {

        Collection<ACMEIdentifier> identifiers = new HashSet<>();

        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
        X500Name subjectDN = certImpl.getSubjectObj().getX500Name();

        String cn;
        try {
            cn = subjectDN.getCommonName();
        } catch (NullPointerException e) {
            cn = null;
        }

        if (cn != null) {
            ACMEIdentifier identifier = new ACMEIdentifier("dns", cn.toLowerCase());
            identifiers.add(identifier);
        }

        Collection<List<?>> sanExtensions = cert.getSubjectAlternativeNames();
        if (sanExtensions != null) {
            for (List<?> sanExtension : sanExtensions) {
                Integer type = (Integer) sanExtension.get(0);
                Object value = sanExtension.get(1);
                if (type == 2) {
                    String dnsName = (String) value;
                    ACMEIdentifier identifier = new ACMEIdentifier("dns", dnsName);
                    identifiers.add(identifier);
                }
            }
        }

        return identifiers;
    }
}
