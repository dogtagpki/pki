//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
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
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
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
import org.dogtagpki.acme.backend.ACMEBackend;
import org.dogtagpki.acme.backend.ACMEBackendConfig;
import org.dogtagpki.acme.database.ACMEDatabase;
import org.dogtagpki.acme.database.ACMEDatabaseConfig;
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

import com.netscape.cmsutil.crypto.CryptoUtil;

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

    private ACMEValidatorsConfig validatorsConfig;
    private Map<String, ACMEValidator> validators = new HashMap<>();

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

    public Collection<ACMEValidator> getValidators() {
        return validators.values();
    }

    public ACMEValidator getValidator(String name) {
        return validators.get(name);
    }

    public void addValidator(String name, ACMEValidator validator) {
        validators.put(name, validator);
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

        if (validatorsConfigFile.exists()) {
            logger.info("Loading ACME validators config from " + validatorsConfigFile);
            String content = new String(Files.readAllBytes(validatorsConfigFile.toPath()));
            validatorsConfig = ACMEValidatorsConfig.fromJSON(content);

        } else {
            logger.info("Loading default ACME validators config");
            validatorsConfig = new ACMEValidatorsConfig();
        }
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
        if (backend != null)
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

            loadValidatorsConfig(acmeConfDir + File.separator + "validators.json");
            initValidators();

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
            shutdownValidators();
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

    public void validateCSR(ACMEAccount account, ACMEOrder order, String csr) throws Exception {

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
        parseCSR(csr, dnsNames);

        logger.info("Validating DNS names in CSR");
        for (String dnsName : dnsNames) {
            logger.info("- " + dnsName);
        }

        Set<String> unauthorizedDNSNames = new HashSet<>(dnsNames);
        unauthorizedDNSNames.removeAll(authorizedDNSNames);

        if (!unauthorizedDNSNames.isEmpty()) {
            // TODO: generate proper exception
            throw new Exception("Unauthorized DNS names: " + StringUtils.join(unauthorizedDNSNames, ", "));
        }

        // TODO: validate other things in CSR

        logger.info("CSR is valid");
    }

    public void parseCSR(String csr, Set<String> dnsNames) throws Exception {

        String strCSR = CryptoUtil.normalizeCertAndReq(csr);
        byte[] binCSR = Utils.base64decode(strCSR);
        PKCS10 pkcs10 = new PKCS10(binCSR);

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

        // Case 1: validate using order information (if it still exists)

        String certBase64 = revocation.getCertificate();
        byte[] certData = Utils.base64decode(certBase64);

        X509Certificate cert;
        try (ByteArrayInputStream is = new ByteArrayInputStream(certData)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(is);
        }

        String certID = backend.getCertificateID(cert);

        logger.info("Finding order that issued the certificate");
        ACMEOrder order = database.getOrderByCertificate(certID);

        if (order != null) {
            logger.info("Order ID: " + order.getID());

            // check order ownership
            if (!order.getAccountID().equals(account.getID())) {
                // TODO: generate proper exception
                throw new Exception("Account did not issue the certificate");
            }

            // No need to check order status since it's guaranteed to be valid.
            // No need to check order expiration since it's irrelevant for revocation.

            logger.info("Account authorized to revoke certificate");
            return;
        }

        logger.info("Order not found");

        // TODO: Case 2: validate using cert identifiers authorizations

        // TODO: generate proper exception
        throw new Exception("Account unauthorized to revoke certificate");
    }
}
