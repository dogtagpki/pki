// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.test;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;

import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.AsymKeyGenerationRequest;
import com.netscape.certsrv.key.Key;
import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestInfoCollection;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.certsrv.key.KeyResource;
import com.netscape.certsrv.key.SymKeyGenerationRequest;
import com.netscape.certsrv.kra.KRAClient;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.certsrv.system.SystemCertClient;
import com.netscape.certsrv.util.NSSCryptoProvider;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

public class DRMTest {

    public static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("DRMTest", options);
        System.exit(1);
    }

    public static void main(String args[]) throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, SignatureException, IOException {
        String host = null;
        String port = null;
        String token_pwd = null;
        String db_dir = "./";
        String protocol = "http";
        String clientCertNickname = "KRA Administrator of Instance pki-kra's SjcRedhat Domain ID";

        // parse command line arguments
        Options options = new Options();
        options.addOption("h", true, "Hostname of the DRM");
        options.addOption("p", true, "Port of the DRM");
        options.addOption("w", true, "Token password");
        options.addOption("d", true, "Directory for tokendb");
        options.addOption("s", true, "Attempt Optional Secure SSL connection");
        options.addOption("c", true, "Optional SSL Client cert Nickname");

        try {
            CommandLineParser parser = new PosixParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("h")) {
                host = cmd.getOptionValue("h");
            } else {
                System.err.println("Error: no hostname provided.");
                usage(options);
            }

            if (cmd.hasOption("p")) {
                port = cmd.getOptionValue("p");
            } else {
                System.err.println("Error: no port provided");
                usage(options);
            }

            if (cmd.hasOption("w")) {
                token_pwd = cmd.getOptionValue("w");
            } else {
                System.err.println("Error: no token password provided");
                usage(options);
            }

            if (cmd.hasOption("d")) {
                db_dir = cmd.getOptionValue("d");
            }

            if (cmd.hasOption("s")) {
                if (cmd.getOptionValue("s") != null && cmd.getOptionValue("s").equals("true")) {
                    protocol = "https";
                }
            }

            if (cmd.hasOption("c")) {
                String nick = cmd.getOptionValue("c");

                if (nick != null && protocol.equals("https")) {
                    clientCertNickname = nick;
                }
            }

        } catch (ParseException e) {
            System.err.println("Error in parsing command line options: " + e.getMessage());
            usage(options);
        }

        // used for crypto operations
        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };

        try {
            iv = genIV(8);
        } catch (Exception e) {
            log("Can't generate initialization vector use default: " + e.toString());
        }

        // used for wrapping to send data to DRM
        String transportCert = null;

        // Data to be archived
        SymmetricKey vek = null;
        String passphrase = null;

        // Session keys and passphrases for recovery
        SymmetricKey sessionKey = null;
        byte[] wrappedRecoveryKey = null;
        String recoveryPassphrase = null;
        byte[] wrappedRecoveryPassphrase = null;

        // retrieved data (should match archived data)
        byte[] encryptedData = null;
        String recoveredKey = null;

        // various ids used in recovery/archival operations
        KeyId keyId = null;
        String clientKeyId = null;
        RequestId recoveryRequestId = null;

        // Variables for data structures from calls
        KeyRequestResponse requestResponse = null;
        Key keyData = null;
        KeyInfo keyInfo = null;

        // Initialize token
        try {
            CryptoManager.initialize(db_dir);
        } catch (AlreadyInitializedException e) {
            // it is ok if it is already initialized
        } catch (Exception e) {
            log("INITIALIZATION ERROR: " + e.toString());
            System.exit(1);
        }

        // Set base URI and get client

        KRAClient client;
        SystemCertClient systemCertClient;
        KeyClient keyClient;
        NSSCryptoProvider nssCrypto;
        try {
            ClientConfig config = new ClientConfig();
            config.setServerURI(protocol + "://" + host + ":" + port + "/kra");
            config.setCertNickname(clientCertNickname);
            config.setCertDatabase(db_dir);
            config.setCertPassword(token_pwd);
            nssCrypto = new NSSCryptoProvider(config);

            client = new KRAClient(new PKIClient(config, nssCrypto));
            systemCertClient = (SystemCertClient) client.getClient("systemcert");
            keyClient = (KeyClient) client.getClient("key");

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // Test 1: Get transport certificate from DRM
        transportCert = systemCertClient.getTransportCert().getEncoded();
        transportCert = transportCert.substring(CertData.HEADER.length(),
                transportCert.indexOf(CertData.FOOTER));
        keyClient.setTransportCert(transportCert);

        log("Transport Cert retrieved from DRM: " + transportCert);

        // Test 2: Get list of completed key archival requests
        log("\n\nList of completed archival requests");
        KeyRequestInfoCollection list = keyClient.listRequests("complete", "securityDataEnrollment");
        if (list.getTotal() == 0) {
            log("No requests found");
        } else {
            Iterator<KeyRequestInfo> iter = list.getEntries().iterator();
            while (iter.hasNext()) {
                KeyRequestInfo info = iter.next();
                printRequestInfo(info);
            }
        }

        // Test 3: Get list of key recovery requests
        log("\n\nList of completed recovery requests");
        KeyRequestInfoCollection list2 = keyClient.listRequests("complete", "securityDataRecovery");
        if (list2.getTotal() == 0) {
            log("No requests found");
        } else {
            Iterator<KeyRequestInfo> iter2 = list2.getEntries().iterator();
            while (iter2.hasNext()) {
                KeyRequestInfo info = iter2.next();
                printRequestInfo(info);
            }
        }

        // Test 4: Generate and archive a symmetric key
        log("Archiving symmetric key");
        clientKeyId = "UUID: 123-45-6789 VEK " + Calendar.getInstance().getTime().toString();
        try {
            vek = nssCrypto.generateSessionKey();
            byte[] encoded = nssCrypto.createPKIArchiveOptions(transportCert, vek, null,
                    KeyRequestResource.DES3_ALGORITHM, 0, iv);

            KeyRequestResponse info = keyClient.archivePKIOptions(clientKeyId, KeyRequestResource.SYMMETRIC_KEY_TYPE,
                    KeyRequestResource.DES3_ALGORITHM, 0, encoded);
            log("Archival Results:");
            printRequestInfo(info.getRequestInfo());
            keyId = info.getKeyId();
        } catch (Exception e) {
            log("Exception in archiving symmetric key:" + e.getMessage());
            e.printStackTrace();
        }

        //Test 5: Get keyId for active key with client ID

        log("Getting key ID for symmetric key");
        keyInfo = keyClient.getActiveKeyInfo(clientKeyId);
        printKeyInfo(keyInfo);
        KeyId keyId2 = keyInfo.getKeyId();
        if (keyId2 == null) {
            log("No archived key found");
        } else {
            log("Archived Key found: " + keyId);
        }

        if (!keyId.equals(keyId2)) {
            log("Error: key ids from search and archival do not match");
        } else {
            log("Success: keyids from search and archival match.");
        }

        // Test 6: Submit a recovery request for the symmetric key using a session key
        log("Submitting a recovery request for the  symmetric key using session key");
        try {
            sessionKey = nssCrypto.generateSessionKey();
            wrappedRecoveryKey = CryptoUtil.wrapSymmetricKey(nssCrypto.getManager(), nssCrypto.getToken(),
                    transportCert, sessionKey);
            keyData = keyClient.retrieveKey(keyId, wrappedRecoveryKey);
        } catch (Exception e) {
            log("Exception in recovering symmetric key using session key: " + e.getMessage());
        }

        encryptedData = keyData.getEncryptedData();

        try {
            recoveredKey = Utils.base64encode(nssCrypto.unwrapWithSessionKey(
                    encryptedData, sessionKey,
                    KeyRequestResource.DES3_ALGORITHM, keyData.getNonceData()));
        } catch (Exception e) {
            log("Exception in unwrapping key: " + e.toString());
            e.printStackTrace();
        }

        if (!recoveredKey.equals(Utils.base64encode(vek.getEncoded()))) {
            log("Error: recovered and archived keys do not match!");
        } else {
            log("Success: recoverd and archived keys match!");
        }

        // Test 7: Submit a recovery request for the symmetric key using a passphrase
        log("Submitting a recovery request for the  symmetric key using a passphrase");
        recoveryPassphrase = "Gimme me keys please";

        try {
            sessionKey = nssCrypto.generateSessionKey();
            wrappedRecoveryPassphrase = nssCrypto.wrapWithSessionKey(recoveryPassphrase, iv, sessionKey,
                    KeyRequestResource.DES3_ALGORITHM);
            wrappedRecoveryKey = nssCrypto.wrapSessionKeyWithTransportCert(sessionKey, transportCert);

            keyData = keyClient.retrieveKeyUsingWrappedPassphrase(keyId, wrappedRecoveryKey, wrappedRecoveryPassphrase,
                    iv);
        } catch (Exception e) {
            log("Exception in recovering symmetric key using passphrase" + e.toString());
            e.printStackTrace();
        }

        encryptedData = keyData.getEncryptedData();

        try {
            recoveredKey = Utils.base64encode(nssCrypto.unwrapWithPassphrase(encryptedData, recoveryPassphrase));
        } catch (Exception e) {
            log("Error: unable to unwrap key using passphrase");
            e.printStackTrace();
        }

        if (recoveredKey == null || !recoveredKey.equals(Utils.base64encode(vek.getEncoded()))) {
            log("Error: recovered and archived keys do not match!");
        } else {
            log("Success: recovered and archived keys do match!");
        }

        passphrase = "secret12345";
        // Test 8: Generate and archive a passphrase
        clientKeyId = "UUID: 123-45-6789 RKEK " + Calendar.getInstance().getTime().toString();
        try {
            requestResponse = keyClient.archivePassphrase(clientKeyId, passphrase);

            log("Archival Results:");
            printRequestInfo(requestResponse.getRequestInfo());
            keyId = requestResponse.getKeyId();
        } catch (Exception e) {
            log("Exception in archiving symmetric key:" + e.toString());
            e.printStackTrace();
        }

        //Test 9: Get keyId for active passphrase with client ID
        log("Getting key ID for passphrase");
        keyInfo = keyClient.getActiveKeyInfo(clientKeyId);
        printKeyInfo(keyInfo);
        keyId2 = keyInfo.getKeyId();
        if (keyId2 == null) {
            log("No archived key found");
        } else {
            log("Archived Key found: " + keyId);
        }

        if (!keyId.equals(keyId2)) {
            log("Error: key ids from search and archival do not match");
        } else {
            log("Success: key ids from search and archival do match!");
        }

        // Test 10: Submit a recovery request for the passphrase using a session key
        log("Submitting a recovery request for the passphrase using session key");
        sessionKey = null;
        wrappedRecoveryKey = null;
        try {
            keyData = keyClient.retrieveKeyByPassphrase(keyId, recoveryPassphrase);
        } catch (Exception e) {
            log("Exception in recovering passphrase using session key: " + e.getMessage());
        }
        encryptedData = keyData.getEncryptedData();
        try {
            recoveredKey = new String(nssCrypto.unwrapWithPassphrase(encryptedData, recoveryPassphrase), "UTF-8");
        } catch (Exception e) {
            log("Exception in unwrapping key: " + e.toString());
            e.printStackTrace();
        }

        if (recoveredKey == null || !recoveredKey.equals(passphrase)) {
            log("Error: recovered and archived passphrases do not match!");
        } else {
            log("Success: recovered and archived passphrases do match!");
        }

        // Test 11: Submit a recovery request for the passphrase using a passphrase
        try {
            sessionKey = nssCrypto.generateSessionKey();
            wrappedRecoveryKey = nssCrypto.wrapSessionKeyWithTransportCert(sessionKey, transportCert);
            wrappedRecoveryPassphrase = nssCrypto.wrapWithSessionKey(recoveryPassphrase, iv, sessionKey,
                    KeyRequestResource.DES3_ALGORITHM);
            keyData = keyClient.retrieveKeyUsingWrappedPassphrase(keyId, wrappedRecoveryKey, wrappedRecoveryPassphrase,
                    iv);
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Test 17: " + e1.getMessage());
            System.exit(-1);
        }
        encryptedData = keyData.getEncryptedData();
        try {
            recoveredKey = new String(nssCrypto.unwrapWithPassphrase(encryptedData, recoveryPassphrase), "UTF-8");
        } catch (Exception e) {
            log("Error: cannot unwrap key using passphrase");
            e.printStackTrace();
        }

        if (recoveredKey == null || !recoveredKey.equals(passphrase)) {
            log("Error: recovered and archived passphrases do not match!");
        } else {
            log("Success: recovered and archived passphrases do match!");
        }

        // Test 12: Get key
        log("Getting passphrase: " + keyId);
        try {
            keyData = keyClient.retrieveKeyByPassphrase(keyId, recoveryPassphrase);
        } catch (Exception e1) {
            e1.printStackTrace();
        }
        encryptedData = keyData.getEncryptedData();
        try {
            recoveredKey = new String(nssCrypto.unwrapWithPassphrase(encryptedData, recoveryPassphrase), "UTF-8");
        } catch (Exception e) {
            log("Error: Can't unwrap recovered key using passphrase");
            e.printStackTrace();
        }

        if (recoveredKey == null || !recoveredKey.equals(passphrase)) {
            log("Error: recovered and archived passphrases do not match!");
        } else {
            log("Success: recovered and archived passphrases do match!");
        }

        // Test 13: Get non-existent request
        RequestId requestId = new RequestId("0xabcdef");
        log("Getting non-existent request: " + requestId.toHexString());
        try {
            keyClient.getRequestInfo(requestId);
            log("Error: getting non-existent request does not throw an exception");
        } catch (RequestNotFoundException e) {
            log("Success: getting non-existent request throws an exception: " + e.getMessage() + " ("
                    + e.getRequestId().toHexString() + ")");
        }

        // Test 14: Request x509 key recovery
        // This test requires to retrieve keyId and matching certificate
        // from installed instances of CA and DRM
        String keyID = "1";
        String b64Certificate = "MIIC+TCCAeGgAwIBAgIBDDANBgkqhkiG9w0BAQsFADBOMSswKQYDVQQKDCJ1c2Vy" +
                "c3lzLnJlZGhhdC5jb20gU2VjdXJpdHkgRG9tYWluMR8wHQYDVQQDDBZDQSBTaWdu" +
                "aW5nIENlcnRpZmljYXRlMB4XDTEzMTAyNTE5MzQwM1oXDTE0MDQyMzE5MzQwM1ow" +
                "EzERMA8GCgmSJomT8ixkAQEMAXgwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB" +
                "ALhLfGmKvxFsKXPh49q1QsluXU3WlyS1XnpDLgOAhgTNgO4sG6CpPdv6hZYIvQBb" +
                "ZQ5bhuML+NXK+Q+EIiNk1cUTxgL3a30sPzy6QaFWxwM8i4uXm4nCBYv7T+n4V6/O" +
                "xHIM2Ch/dviAb3vz+M9trErv9t+d2H8jNXT3sHuDb/kvAgMBAAGjgaAwgZ0wHwYD" +
                "VR0jBBgwFoAUh1cxWFRY+nMsx4odQQI1GqyFxP8wSwYIKwYBBQUHAQEEPzA9MDsG" +
                "CCsGAQUFBzABhi9odHRwOi8vZG9ndGFnMjAudXNlcnN5cy5yZWRoYXQuY29tOjgw" +
                "ODAvY2Evb2NzcDAOBgNVHQ8BAf8EBAMCBSAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG" +
                "CCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4IBAQCvmbUzQOouE2LgQQcKfmgwwJMJ" +
                "9tMrPwDUtyFdaIFoPL4uZaujSscaN4IWK2r5vIMJ65jwYCI7sI9En2ZfO28J9dQj" +
                "lpqu6TaJ+xtaMk7OvXpVB7lJk73HAttMGjETlkoq/6EjxcugmJsDqVD0b2tO7Vd0" +
                "hroBe2uPDHM2ASewZF415lUcRh0URtmxSazTInbyxpmy1wgSJQ0C6fMCeT+hUFlA" +
                "0P4k1TIprapGVq7FpKcqlhK2gTBfTSnoO7gmXG/9MxJiYpb/Aph8ptXq6quHz1Mj" +
                "greWr3xTsy6gF2yphUEkGHh4v22XvK+FLx9Jb6zloMWA2GG9gpUpvMnl1fH4";

        log("Requesting X509 key recovery.");
        recoveryRequestId = keyClient.recoverKey(new KeyId(keyID), null, null, null, b64Certificate).getRequestInfo()
                .getRequestId();
        log("Requesting X509 key recovery request: " + recoveryRequestId);

        // Test 55: Approve x509 key recovery
        log("Approving X509 key recovery request: " + recoveryRequestId);
        keyClient.approveRequest(recoveryRequestId);

        // Test 16: Recover x509 key
        log("Recovering X509 key based on request: " + recoveryRequestId);
        try {
            // KeyData recoveredX509Key = client.recoverKey(recoveryRequestId, "netscape");
            // log("Success: X509Key recovered: "+ recoveredX509Key.getP12Data());
        } catch (RequestNotFoundException e) {
            log("Error: recovering X509Key");
        }

        // Test 1: Get transport certificate from DRM
        transportCert = systemCertClient.getTransportCert().getEncoded();
        transportCert = transportCert.substring(CertData.HEADER.length(),
                transportCert.indexOf(CertData.FOOTER));

        log("Transport Cert retrieved from DRM: " + transportCert);

        // Test 17: Get list of completed key archival requests
        log("\n\nList of completed archival requests");
        list = keyClient.listRequests("complete", IRequest.SYMKEY_GENERATION_REQUEST);
        if (list.getTotal() == 0) {
            log("No requests found");
        } else {
            Iterator<KeyRequestInfo> iter = list.getEntries().iterator();
            while (iter.hasNext()) {
                KeyRequestInfo info = iter.next();
                printRequestInfo(info);
            }
        }

        // test 18: Generate symmetric key
        clientKeyId = "Symmetric Key #1234f " + Calendar.getInstance().getTime().toString();
        List<String> usages = new ArrayList<String>();
        usages.add(SymKeyGenerationRequest.DECRYPT_USAGE);
        usages.add(SymKeyGenerationRequest.ENCRYPT_USAGE);
        KeyRequestResponse genKeyResponse = keyClient.generateSymmetricKey(clientKeyId,
                KeyRequestResource.AES_ALGORITHM,
                128, usages, null);
        printRequestInfo(genKeyResponse.getRequestInfo());
        keyId = genKeyResponse.getKeyId();

        // test 19: Get keyId for active key with client ID
        log("Getting key ID for symmetric key");
        keyInfo = keyClient.getActiveKeyInfo(clientKeyId);
        printKeyInfo(keyInfo);
        keyId2 = keyInfo.getKeyId();
        if (keyId2 == null) {
            log("No archived key found");
        } else {
            log("Archived Key found: " + keyId);
        }

        if (!keyId.equals(keyId2)) {
            log("Error: key ids from search and archival do not match");
        } else {
            log("Success: keyids from search and archival match.");
        }

        // Test 20: Submit a recovery request for the symmetric key using a session key
        log("Submitting a recovery request for the  symmetric key using session key");
        try {
            sessionKey = nssCrypto.generateSessionKey();
            wrappedRecoveryKey = nssCrypto.wrapSessionKeyWithTransportCert(sessionKey, transportCert);
            keyData = keyClient.retrieveKey(keyId, wrappedRecoveryKey);
        } catch (Exception e) {
            log("Exception in recovering symmetric key using session key: " + e.getMessage());
        }

        encryptedData = keyData.getEncryptedData();

        try {
            recoveredKey = new String(nssCrypto.unwrapWithSessionKey(
                    encryptedData, sessionKey, KeyRequestResource.DES3_ALGORITHM,
                    keyData.getNonceData()));
        } catch (Exception e) {
            log("Exception in unwrapping key: " + e.toString());
            e.printStackTrace();
        }

        // test 21: Generate symmetric key - invalid algorithm
        try {
            genKeyResponse = keyClient.generateSymmetricKey("Symmetric Key #1235", "AFS", 128, usages, null);
        } catch (Exception e) {
            log("Exception: " + e);
        }

        // test 22: Generate symmetric key - invalid key size
        try {
            genKeyResponse = keyClient.generateSymmetricKey("Symmetric Key #1236", "AES", 0, usages, null);
        } catch (Exception e) {
            log("Exception: " + e);
        }

        // test 23: Generate symmetric key - usages not defined
        try {
            genKeyResponse = keyClient.generateSymmetricKey("Symmetric Key #1236", "DES", 56, null, null);
        } catch (Exception e) {
            log("Exception: " + e);
        }

        // Test 24: Generate and archive a symmetric key of type AES
        log("Archiving symmetric key");
        clientKeyId = "UUID: 123-45-6789 VEK " + Calendar.getInstance().getTime().toString();
        try {
            vek = nssCrypto.generateSymmetricKey(KeyRequestResource.AES_ALGORITHM, 128);

            byte[] encoded = CryptoUtil.createPKIArchiveOptions(nssCrypto.getManager(), nssCrypto.getToken(),
                    transportCert, vek, null,
                    KeyGenAlgorithm.DES3, 0, new IVParameterSpec(iv));

            KeyRequestResponse response = keyClient.archivePKIOptions(clientKeyId,
                    KeyRequestResource.SYMMETRIC_KEY_TYPE, KeyRequestResource.AES_ALGORITHM, 128, encoded);
            log("Archival Results:");
            printRequestInfo(response.getRequestInfo());
            keyId = response.getKeyId();
        } catch (Exception e) {
            log("Exception in archiving symmetric key:" + e.getMessage());
            e.printStackTrace();
        }

        //Test 25: Get keyId for active key with client ID
        log("Getting key ID for symmetric key");
        keyInfo = keyClient.getActiveKeyInfo(clientKeyId);
        printKeyInfo(keyInfo);
        keyId2 = keyInfo.getKeyId();
        if (keyId2 == null) {
            log("No archived key found");
        } else {
            log("Archived Key found: " + keyId);
        }

        if (!keyId.equals(keyId2)) {
            log("Error: key ids from search and archival do not match");
        } else {
            log("Success: keyids from search and archival match.");
        }

        // Test 26: Submit a recovery request for the symmetric key
        log("Submitting a recovery request for the  symmetric key without using session key");
        try {
            keyData = keyClient.retrieveKey(keyId);
        } catch (Exception e) {
            log("Exception in recovering symmetric key using session key: " + e.getMessage());
        }

        // Since no session key is provided externally, the retrieveKey method
        // generates a session key, wraps it with transport cert and completes the request.
        // The encrypted data is then unwrapped using the temporary session key and set to
        // the attribute privateData.
        recoveredKey = Utils.base64encode(keyData.getData());

        if (!recoveredKey.equals(Utils.base64encode(vek.getEncoded()))) {
            log("Error: recovered and archived keys do not match!");
        } else {
            log("Success: recoverd and archived keys match!");
        }

        // Test 27: Get key info
        log("getting key info for existing key");
        printKeyInfo(keyClient.getKeyInfo(keyId));

        //Test 28: Modify status
        log("modify the key status");
        keyClient.modifyKeyStatus(keyId, KeyResource.KEY_STATUS_INACTIVE);
        keyInfo = keyClient.getKeyInfo(keyId);
        printKeyInfo(keyInfo);

        //Test 29:  Confirm no more active keys with this ID
        log("look for active keys with this id");
        clientKeyId = keyInfo.getClientKeyID();
        try {
            keyInfo = keyClient.getActiveKeyInfo(clientKeyId);
            printKeyInfo(keyInfo);
        } catch (ResourceNotFoundException e) {
            log("Success: ResourceNotFound exception thrown: " + e);
        }

        // Test asymmetric key generation.

        String[] algs = { "RSA", "DSA" };
        for (int i = 0; i < algs.length; i++) {
            // Test 30: Generate Asymmetric keys - RSA key
            System.out.println("\nTesting asymmetric key generation for algorithm " + algs[i]);
            clientKeyId = "AsymKey #" + Calendar.getInstance().getTimeInMillis();
            usages.clear();
            usages.add(AsymKeyGenerationRequest.SIGN);
            usages.add(AsymKeyGenerationRequest.VERIFY);
            KeyRequestResponse response = keyClient.generateAsymmetricKey(clientKeyId, algs[i], 1024, usages, null);
            printRequestInfo(response.getRequestInfo());
            System.out.println();

            // Test 31: Get information of the newly generated asymmetric keys
            System.out.println("Fetch information of the newly generated asymmetric keys.");
            System.out.println();
            KeyInfo info = keyClient.getKeyInfo(response.getKeyId());
            printKeyInfo(info);
            System.out.println();

            // Test 32: Retrieve private key data
            System.out.println("Retrieving and verifying the generated private key.");
            try {
                keyData = keyClient.retrieveKey(response.getKeyId());
            } catch (Exception e) {
                log("Exception retrieving the private key data.");
                e.printStackTrace();
            }

            // Test 33: Verify the generated key pair.
            if (isKeyPairValid(algs[i], keyData.getData(), info.getPublicKey())) {
                log("The key pair generated using " + algs[i] + " algorithm is valid.");
            } else {
                log("The key pair generated using " + algs[i] + " algorithm is invalid.");
            }
            System.out.println();
        }

        // Test 34:
    }

    /**
     * Verify the generated asymmetric key pair.
     *
     * @param keyAlgorithm - Algorithm used to generate keys.
     * @param privateKey - binary data of the private key.
     * @param publicKey - binary data of he public key.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static boolean isKeyPairValid(String keyAlgorithm, byte[] privateKey, byte[] publicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException,
            IOException {
        String algorithm = keyAlgorithm.toUpperCase();
        String signingAlgorithm = "SHA1with" + algorithm;
        KeyFactory factory = KeyFactory.getInstance(algorithm);
        PrivateKey priKey = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKey = factory.generatePublic(new X509EncodedKeySpec(publicKey));
        Signature sig = Signature.getInstance(signingAlgorithm);
        sig.initSign(priKey);
        String s = "Data to test asymmetric keys.";
        sig.update(s.getBytes());

        // Sign the data with the private key.
        byte[] realSig = sig.sign();

        Signature sig2 = Signature.getInstance(signingAlgorithm);
        sig2.initVerify(pubKey);

        sig2.update(s.getBytes());
        // Verify the signature with the public key.
        return sig2.verify(realSig);
    }

    private static void printKeyInfo(KeyInfo keyInfo) {
        log("Printing keyInfo:");
        log("Client Key ID:  " + keyInfo.getClientKeyID());
        log("Key URL:   " + keyInfo.getKeyURL());
        log("Algorithm: " + keyInfo.getAlgorithm());
        log("Strength:  " + keyInfo.getSize());
        log("Status:    " + keyInfo.getStatus());
        if (keyInfo.getPublicKey() != null) {
            log("Public Key: ");
            String publicKey = Utils.base64encode(keyInfo.getPublicKey());
            log(publicKey);
        }
    }

    private static void log(String string) {
        System.out.println(string);
    }

    private static void printRequestInfo(KeyRequestInfo info) {
        log("KeyRequestURL: " + info.getRequestURL());
        log("Key URL:       " + info.getKeyURL());
        log("Status:        " + info.getRequestStatus());
        log("Type:          " + info.getRequestType());
    }

    //Use this when we actually create random initialization vectors
    private static byte[] genIV(int blockSize) throws Exception {
        // generate an IV
        byte[] iv = new byte[blockSize];

        Random rnd = new Random();
        rnd.nextBytes(iv);

        return iv;
    }
}