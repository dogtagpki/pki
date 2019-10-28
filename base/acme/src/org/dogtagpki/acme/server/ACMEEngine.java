//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.apache.commons.codec.binary.Base64;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEMetadata;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWK;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.backend.ACMEBackend;
import org.dogtagpki.acme.backend.ACMEBackendConfig;
import org.dogtagpki.acme.database.ACMEDatabase;
import org.dogtagpki.acme.database.ACMEDatabaseConfig;

/**
 * @author Endi S. Dewata
 */
@WebListener
public class ACMEEngine implements ServletContextListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEEngine.class);

    public static ACMEEngine INSTANCE;

    private String name;

    private ACMEMetadata metadata;

    private ACMEDatabaseConfig databaseConfig;
    private ACMEDatabase database;

    private ACMEBackendConfig backendConfig;
    private ACMEBackend backend;

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

    public ACMEBackendConfig getBackendConfig() {
        return backendConfig;
    }

    public void setBackendConfig(ACMEBackendConfig backendConfig) {
        this.backendConfig = backendConfig;
    }

    public ACMEBackend getBackend() {
        return backend;
    }

    public void setBackend(ACMEBackend backend) {
        this.backend = backend;
    }

    public void loadMetadata(String filename) throws Exception {

        File metadataConfigFile = new File(filename);

        if (metadataConfigFile.exists()) {
            logger.info("Loading ACME metadata from " + metadataConfigFile);
            String content = new String(Files.readAllBytes(metadataConfigFile.toPath()));
            metadata = ACMEMetadata.fromJSON(content);

        } else {
            logger.info("Loading default ACME metadata");
            metadata = new ACMEMetadata();
        }

        logger.info("Metadata:\n" + metadata);
    }

    public void loadDatabaseConfig(String filename) throws Exception {

        File databaseConfigFile = new File(filename);

        if (databaseConfigFile.exists()) {
            logger.info("Loading ACME database config from " + databaseConfigFile);
            String content = new String(Files.readAllBytes(databaseConfigFile.toPath()));
            databaseConfig = ACMEDatabaseConfig.fromJSON(content);

        } else {
            logger.info("Loading default ACME database config");
            databaseConfig = new ACMEDatabaseConfig();
        }

        logger.info("Database:\n" + databaseConfig);
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
        database.close();
    }

    public void loadBackendConfig(String filename) throws Exception {

        File backendConfigFile = new File(filename);

        if (backendConfigFile.exists()) {
            logger.info("Loading ACME backend config from " + backendConfigFile);
            String content = new String(Files.readAllBytes(backendConfigFile.toPath()));
            backendConfig = ACMEBackendConfig.fromJSON(content);

        } else {
            logger.info("Loading default ACME backend config");
            backendConfig = new ACMEBackendConfig();
        }

        logger.info("Backend:\n" + backendConfig);
    }

    public void initBackend() throws Exception {

        logger.info("Initializing ACME backend");

        String className = backendConfig.getClassName();
        Class<ACMEBackend> backendClass = (Class<ACMEBackend>) Class.forName(className);

        backend = backendClass.newInstance();
        backend.setConfig(backendConfig);
        backend.init();
    }

    public void shutdownBackend() throws Exception {
        backend.close();
    }

    public void contextInitialized(ServletContextEvent event) {

        logger.info("Initializing ACME engine");

        String path = event.getServletContext().getContextPath();
        if ("".equals(path)) {
            name = "ROOT";
        } else {
            name = path.substring(1);
        }

        String catalinaBase = System.getProperty("catalina.base");
        String serverConfDir = catalinaBase + File.separator + "conf";
        String acmeConfDir = serverConfDir + File.separator + name;

        logger.info("ACME configuration directory: " + acmeConfDir);

        try {
            loadMetadata(acmeConfDir + File.separator + "metadata.json");

            loadDatabaseConfig(acmeConfDir + File.separator + "database.json");
            initDatabase();

            loadBackendConfig(acmeConfDir + File.separator + "backend.json");
            initBackend();

        } catch (Exception e) {
            logger.error("Unable to initialize ACME engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to initialize ACME engine: " + e.getMessage(), e);
        }
    }

    public void contextDestroyed(ServletContextEvent event) {

        logger.info("Shutting down ACME engine");

        try {
            shutdownBackend();
            shutdownDatabase();

        } catch (Exception e) {
            logger.error("Unable to initialize ACME engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to shutdown ACME engine: " + e.getMessage(), e);
        }
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
        logger.info("Nonce: " + nonce);

        return nonce;
    }

    public void validateNonce(String value) throws Exception {

        ACMENonce nonce = database.removeNonce(value);

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

    public void purgeNonces() throws Exception {
        database.removeExpiredNonces(new Date());
    }

    public void validateJWS(JWS jws, String alg, JWK jwk) throws Exception {

        logger.info("Validating " + alg + " JWS");

        String message = jws.getProtectedHeader() + "." + jws.getPayload();
        byte[] signature = Base64.decodeBase64(jws.getSignature());

        // JWS validation
        // https://tools.ietf.org/html/rfc7515
        // TODO: support other algorithms

        if ("RS256".equals(alg)) {

            String kty = jwk.getKty();
            KeyFactory keyFactory = KeyFactory.getInstance(kty, "Mozilla-JSS");

            String n = jwk.getN();
            BigInteger modulus = new BigInteger(1, Base64.decodeBase64(n));

            String e = jwk.getE();
            BigInteger publicExponent = new BigInteger(1, Base64.decodeBase64(e));

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Signature signer = Signature.getInstance("SHA256withRSA", "Mozilla-JSS");
            signer.initVerify(publicKey);
            signer.update(message.getBytes());

            if (!signer.verify(signature)) {
                throw new Exception("Invalid " + alg + " JWS");
            }

        } else {
            throw new Exception("Unsupported JWS algorithm: " + alg);
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

    public ACMEAccount validateAccount(String accountID) throws Exception {

        ACMEAccount account = database.getAccount(accountID);

        if (account != null) {
            return account;
        }

        logger.info("Account does not exist: " + accountID);

        ResponseBuilder builder = Response.status(Response.Status.BAD_REQUEST);
        builder.type("application/problem+json");

        ACMEError error = new ACMEError();
        error.setType("urn:ietf:params:acme:error:accountDoesNotExist");
        error.setDetail("Account does not exist on the server: " + accountID + "\n" +
                "Remove the local account with the following command:\n" +
                "$ rm -rf /etc/letsencrypt/accounts/<ACME server>");
        builder.entity(error);

        throw new WebApplicationException(builder.build());
    }
}
