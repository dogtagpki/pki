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

import java.util.Calendar;
import java.util.Collection;
import java.util.Iterator;
import java.util.Random;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.key.KeyDataInfo;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.kra.KRAClient;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

public class DRMTest {

    public static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("DRMTest", options);
        System.exit(1);
    }

    public static void main(String args[]) {
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
                if(cmd.getOptionValue("s") != null && cmd.getOptionValue("s").equals("true")) {
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
        IVParameterSpec ivps = null;
        IVParameterSpec ivps_server = null;

        try {
            ivps = genIV(8);
        } catch (Exception e) {
            log("Can't generate initialization vector use default: " + e.toString());
            ivps = new IVParameterSpec(iv);
        }

        CryptoManager manager = null;
        CryptoToken token = null;

        // used for wrapping to send data to DRM
        String transportCert = null;

        // Data to be archived
        SymmetricKey vek = null;
        String passphrase = null;

        // Session keys and passphrases for recovery
        SymmetricKey recoveryKey = null;
        byte[] wrappedRecoveryKey = null;
        String recoveryPassphrase = null;
        byte[] wrappedRecoveryPassphrase = null;

        // retrieved data (should match archived data)
        String wrappedRecoveredKey = null;
        String recoveredKey = null;

        // various ids used in recovery/archival operations
        KeyId keyId = null;
        String clientId = null;
        RequestId recoveryRequestId = null;

        // Variables for data structures from calls
        KeyRequestInfo requestInfo = null;
        KeyData keyData = null;
        KeyDataInfo keyInfo = null;

        // Initialize token
        try {
            CryptoManager.initialize(db_dir);
        } catch (AlreadyInitializedException e) {
            // it is ok if it is already initialized
        } catch (Exception e) {
            log("INITIALIZATION ERROR: " + e.toString());
            System.exit(1);
        }

        // log into token
        try {
            manager = CryptoManager.getInstance();
            token = manager.getInternalKeyStorageToken();
            Password password = new Password(token_pwd.toCharArray());
            try {
                token.login(password);
            } catch (Exception e) {
                log("login Exception: " + e.toString());
                if (!token.isLoggedIn()) {
                    token.initPassword(password, password);
                }
            }
        } catch (Exception e) {
            log("Exception in logging into token:" + e.toString());
        }

        // Set base URI and get client


        KRAClient client;
        try {
            ClientConfig config = new ClientConfig();
            config.setServerURI(protocol + "://" + host + ":" + port + "/kra");
            config.setCertNickname(clientCertNickname);

            client = new KRAClient(new PKIClient(config));

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // Test 1: Get transport certificate from DRM
        transportCert = client.getTransportCert();
        transportCert = transportCert.substring(PKIService.HEADER.length(),
                                                transportCert.indexOf(PKIService.TRAILER));

        log("Transport Cert retrieved from DRM: " + transportCert);

        // Test 2: Get list of completed key archival requests
        log("\n\nList of completed archival requests");
        Collection<KeyRequestInfo> list = client.listRequests("complete", "securityDataEnrollment");
        if (list == null) {
            log("No requests found");
        } else {
            Iterator<KeyRequestInfo> iter = list.iterator();
            while (iter.hasNext()) {
                KeyRequestInfo info = iter.next();
                printRequestInfo(info);
            }
        }

        // Test 3: Get list of key recovery requests
        log("\n\nList of completed recovery requests");
        Collection<KeyRequestInfo> list2 = client.listRequests("complete", "securityDataRecovery");
        if (list2 == null) {
            log("No requests found");
        } else {
            Iterator<KeyRequestInfo> iter2 = list2.iterator();
            while (iter2.hasNext()) {
                KeyRequestInfo info = iter2.next();
                printRequestInfo(info);
            }
        }

        // Test 4: Generate and archive a symmetric key
        log("Archiving symmetric key");
        clientId = "UUID: 123-45-6789 VEK " + Calendar.getInstance().getTime().toString();
        try {
            vek = CryptoUtil.generateKey(token, KeyGenAlgorithm.DES3);
            byte[] encoded = CryptoUtil.createPKIArchiveOptions(manager, token, transportCert, vek, null,
                    KeyGenAlgorithm.DES3, ivps);

            KeyRequestInfo info = client.archiveSecurityData(encoded, clientId, KeyRequestResource.SYMMETRIC_KEY_TYPE);
            log("Archival Results:");
            printRequestInfo(info);
            keyId = info.getKeyId();
        } catch (Exception e) {
            log("Exception in archiving symmetric key:" + e.getMessage());
            e.printStackTrace();
        }

        //Test 5: Get keyId for active key with client ID

        log("Getting key ID for symmetric key");
        keyInfo = client.getKeyData(clientId, "active");
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
            recoveryKey = CryptoUtil.generateKey(token, KeyGenAlgorithm.DES3);
            wrappedRecoveryKey = CryptoUtil.wrapSymmetricKey(manager, token, transportCert, recoveryKey);
            KeyRequestInfo info = client.requestRecovery(keyId, null, wrappedRecoveryKey, ivps.getIV());
            recoveryRequestId = info.getRequestId();
        } catch (Exception e) {
            log("Exception in recovering symmetric key using session key: " + e.getMessage());
        }

        // Test 7: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 8: Get key
        log("Getting key: " + keyId);

        keyData = client.retrieveKey(keyId, recoveryRequestId, null, wrappedRecoveryKey, ivps.getIV());
        wrappedRecoveredKey = keyData.getWrappedPrivateData();

        ivps_server = new IVParameterSpec(Utils.base64decode(keyData.getNonceData()));
        try {
            recoveredKey = CryptoUtil.unwrapUsingSymmetricKey(token, ivps_server,
                    Utils.base64decode(wrappedRecoveredKey),
                    recoveryKey, EncryptionAlgorithm.DES3_CBC_PAD);
        } catch (Exception e) {
            log("Exception in unwrapping key: " + e.toString());
            e.printStackTrace();
        }

        if (!recoveredKey.equals(Utils.base64encode(vek.getEncoded()))) {
            log("Error: recovered and archived keys do not match!");
        } else {
            log("Success: recoverd and archived keys match!");
        }

        // Test 9: Submit a recovery request for the symmetric key using a passphrase
        log("Submitting a recovery request for the  symmetric key using a passphrase");
        recoveryPassphrase = "Gimme me keys please";

        try {
            recoveryKey = CryptoUtil.generateKey(token, KeyGenAlgorithm.DES3);
            wrappedRecoveryPassphrase = CryptoUtil.wrapPassphrase(token, recoveryPassphrase, ivps, recoveryKey,
                    EncryptionAlgorithm.DES3_CBC_PAD);
            wrappedRecoveryKey = CryptoUtil.wrapSymmetricKey(manager, token, transportCert, recoveryKey);

            requestInfo = client.requestRecovery(keyId, wrappedRecoveryPassphrase, wrappedRecoveryKey, ivps.getIV());
            recoveryRequestId = requestInfo.getRequestId();
        } catch (Exception e) {
            log("Exception in recovering symmetric key using passphrase" + e.toString());
            e.printStackTrace();
        }

        //Test 10: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 11: Get key
        log("Getting key: " + keyId);
        keyData = client.retrieveKey(keyId, recoveryRequestId, wrappedRecoveryPassphrase, wrappedRecoveryKey, ivps.getIV());
        wrappedRecoveredKey = keyData.getWrappedPrivateData();

        try {
            recoveredKey = CryptoUtil.unwrapUsingPassphrase(wrappedRecoveredKey, recoveryPassphrase);
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
        // Test 12: Generate and archive a passphrase
        clientId = "UUID: 123-45-6789 RKEK " + Calendar.getInstance().getTime().toString();
        try {
            byte[] encoded = CryptoUtil.createPKIArchiveOptions(manager, token, transportCert, null, passphrase,
                    KeyGenAlgorithm.DES3, ivps);
            requestInfo = client.archiveSecurityData(encoded, clientId, KeyRequestResource.PASS_PHRASE_TYPE);
            log("Archival Results:");
            printRequestInfo(requestInfo);
            keyId = requestInfo.getKeyId();
        } catch (Exception e) {
            log("Exception in archiving symmetric key:" + e.toString());
            e.printStackTrace();
        }

        //Test 13: Get keyId for active passphrase with client ID
        log("Getting key ID for passphrase");
        keyInfo = client.getKeyData(clientId, "active");
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

        // Test 14: Submit a recovery request for the passphrase using a session key
        log("Submitting a recovery request for the passphrase using session key");
        recoveryKey = null;
        recoveryRequestId = null;
        wrappedRecoveryKey = null;
        try {
            recoveryKey = CryptoUtil.generateKey(token, KeyGenAlgorithm.DES3);
            wrappedRecoveryKey = CryptoUtil.wrapSymmetricKey(manager, token, transportCert, recoveryKey);
            wrappedRecoveryPassphrase = CryptoUtil.wrapPassphrase(token, recoveryPassphrase, ivps, recoveryKey,
                    EncryptionAlgorithm.DES3_CBC_PAD);
            requestInfo = client.requestRecovery(keyId, null, wrappedRecoveryKey, ivps.getIV());
            recoveryRequestId = requestInfo.getRequestId();
        } catch (Exception e) {
            log("Exception in recovering passphrase using session key: " + e.getMessage());
        }

        // Test 15: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 16: Get key
        log("Getting passphrase: " + keyId);

        keyData = client.retrieveKey(keyId, recoveryRequestId, null, wrappedRecoveryKey, ivps.getIV());
        wrappedRecoveredKey = keyData.getWrappedPrivateData();
        ivps_server = new IVParameterSpec( Utils.base64decode(keyData.getNonceData()));
        try {
            recoveredKey = CryptoUtil.unwrapUsingSymmetricKey(token, ivps_server,
                    Utils.base64decode(wrappedRecoveredKey),
                    recoveryKey, EncryptionAlgorithm.DES3_CBC_PAD);
            recoveredKey = new String(Utils.base64decode(recoveredKey), "UTF-8");
        } catch (Exception e) {
            log("Exception in unwrapping key: " + e.toString());
            e.printStackTrace();
        }

        if (recoveredKey == null || !recoveredKey.equals(passphrase)) {
            log("Error: recovered and archived passphrases do not match!");
        } else {
            log("Success: recovered and archived passphrases do match!");
        }

        // Test 17: Submit a recovery request for the passphrase using a passphrase
        log("Submitting a recovery request for the passphrase using a passphrase");
        requestInfo = client.requestRecovery(keyId, wrappedRecoveryPassphrase, wrappedRecoveryKey, ivps.getIV());
        recoveryRequestId = requestInfo.getRequestId();

        //Test 18: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 19: Get key
        log("Getting passphrase: " + keyId);
        keyData = client.retrieveKey(keyId, recoveryRequestId, wrappedRecoveryPassphrase, wrappedRecoveryKey, ivps.getIV());
        wrappedRecoveredKey = keyData.getWrappedPrivateData();
        try {
            recoveredKey = CryptoUtil.unwrapUsingPassphrase(wrappedRecoveredKey, recoveryPassphrase);
            recoveredKey = new String(Utils.base64decode(recoveredKey), "UTF-8");
        } catch (Exception e) {
            log("Error: cannot unwrap key using passphrase");
            e.printStackTrace();
        }

        if (recoveredKey == null || !recoveredKey.equals(passphrase)) {
            log("Error: recovered and archived passphrases do not match!");
        } else {
            log("Success: recovered and archived passphrases do match!");
        }

        // Test 20: Submit a recovery request for the passphrase using a passphrase
        //Wait until retrieving key before sending input data.

        log("Submitting a recovery request for the passphrase using a passphrase, wait till end to provide recovery data.");
        requestInfo = client.requestRecovery(keyId, null, null, null);
        recoveryRequestId = requestInfo.getRequestId();

        //Test 21: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 22: Get key
        log("Getting passphrase: " + keyId);
        keyData = client.retrieveKey(keyId, recoveryRequestId, wrappedRecoveryPassphrase, wrappedRecoveryKey, ivps.getIV());
        wrappedRecoveredKey = keyData.getWrappedPrivateData();
        try {
            recoveredKey = CryptoUtil.unwrapUsingPassphrase(wrappedRecoveredKey, recoveryPassphrase);
            recoveredKey = new String(Utils.base64decode(recoveredKey), "UTF-8");
        } catch (Exception e) {
            log("Error: Can't unwrap recovered key using passphrase");
            e.printStackTrace();
        }

        if (recoveredKey == null || !recoveredKey.equals(passphrase)) {
            log("Error: recovered and archived passphrases do not match!");
        } else {
            log("Success: recovered and archived passphrases do match!");
        }

        // Test 23: Get non-existent request
        RequestId requestId = new RequestId("0xabcdef");
        log("Getting non-existent request: " + requestId.toHexString());
        try {
            client.getRequest(requestId);
            log("Error: getting non-existent request does not throw an exception");
        } catch (RequestNotFoundException e) {
            log("Success: getting non-existent request throws an exception: "+e.getMessage()+" ("+e.getRequestId().toHexString()+")");
        }

        // Test 24: Request x509 key recovery
        // This test requires to retrieve keyId and matching certificate
        // from installed instances of CA and DRM
        String keyID = "1";
        String b64Certificate = "MIIC+TCCAeGgAwIBAgIBDDANBgkqhkiG9w0BAQsFADBOMSswKQYDVQQKDCJ1c2Vy"+
                                "c3lzLnJlZGhhdC5jb20gU2VjdXJpdHkgRG9tYWluMR8wHQYDVQQDDBZDQSBTaWdu"+
                                "aW5nIENlcnRpZmljYXRlMB4XDTEzMTAyNTE5MzQwM1oXDTE0MDQyMzE5MzQwM1ow"+
                                "EzERMA8GCgmSJomT8ixkAQEMAXgwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB"+
                                "ALhLfGmKvxFsKXPh49q1QsluXU3WlyS1XnpDLgOAhgTNgO4sG6CpPdv6hZYIvQBb"+
                                "ZQ5bhuML+NXK+Q+EIiNk1cUTxgL3a30sPzy6QaFWxwM8i4uXm4nCBYv7T+n4V6/O"+
                                "xHIM2Ch/dviAb3vz+M9trErv9t+d2H8jNXT3sHuDb/kvAgMBAAGjgaAwgZ0wHwYD"+
                                "VR0jBBgwFoAUh1cxWFRY+nMsx4odQQI1GqyFxP8wSwYIKwYBBQUHAQEEPzA9MDsG"+
                                "CCsGAQUFBzABhi9odHRwOi8vZG9ndGFnMjAudXNlcnN5cy5yZWRoYXQuY29tOjgw"+
                                "ODAvY2Evb2NzcDAOBgNVHQ8BAf8EBAMCBSAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG"+
                                "CCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4IBAQCvmbUzQOouE2LgQQcKfmgwwJMJ"+
                                "9tMrPwDUtyFdaIFoPL4uZaujSscaN4IWK2r5vIMJ65jwYCI7sI9En2ZfO28J9dQj"+
                                "lpqu6TaJ+xtaMk7OvXpVB7lJk73HAttMGjETlkoq/6EjxcugmJsDqVD0b2tO7Vd0"+
                                "hroBe2uPDHM2ASewZF415lUcRh0URtmxSazTInbyxpmy1wgSJQ0C6fMCeT+hUFlA"+
                                "0P4k1TIprapGVq7FpKcqlhK2gTBfTSnoO7gmXG/9MxJiYpb/Aph8ptXq6quHz1Mj"+
                                "greWr3xTsy6gF2yphUEkGHh4v22XvK+FLx9Jb6zloMWA2GG9gpUpvMnl1fH4";

        log("Requesting X509 key recovery.");
        recoveryRequestId = client.requestKeyRecovery(keyID, b64Certificate);
        log("Requesting X509 key recovery request: " + recoveryRequestId);

        // Test 25: Approve x509 key recovery
        log("Approving X509 key recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 26: Recover x509 key
        log("Recovering X509 key based on request: " + recoveryRequestId);
        try {
            KeyData recoveredX509Key = client.recoverKey(recoveryRequestId, "netscape");
            log("Success: X509Key recovered: "+ recoveredX509Key.getP12Data());
        } catch (RequestNotFoundException e) {
            log("Error: recovering X509Key");
        }
    }

    private static void log(String string) {
        // TODO Auto-generated method stub
        System.out.println(string);
    }

    private static void printRequestInfo(KeyRequestInfo info) {
        log("KeyRequestURL: " + info.getRequestURL());
        log("Key URL:       " + info.getKeyURL());
        log("Status:        " + info.getRequestStatus());
        log("Type:          " + info.getRequestType());
    }

    //Use this when we actually create random initialization vectors
    private static IVParameterSpec genIV(int blockSize) throws Exception {
        // generate an IV
        byte[] iv = new byte[blockSize];

        Random rnd = new Random();
        rnd.nextBytes(iv);

        return new IVParameterSpec(iv);
    }
}
