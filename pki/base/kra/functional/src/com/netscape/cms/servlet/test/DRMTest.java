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

import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Iterator;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.BadPaddingException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkix.crmf.EncryptedKey;
import org.mozilla.jss.pkix.crmf.EncryptedValue;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.util.Password;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import com.netscape.cms.servlet.key.model.KeyData;
import com.netscape.cms.servlet.key.model.KeyDataInfo;
import com.netscape.cms.servlet.request.model.KeyRequestInfo;

@SuppressWarnings("deprecation")
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

        // parse command line arguments
        Options options = new Options();
        options.addOption("h", true, "Hostname of the DRM");
        options.addOption("p", true, "Port of the DRM");
        options.addOption("w", true, "Token password");

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

        } catch (ParseException e) {
            System.err.println("Error in parsing command line options: " + e.getMessage());
            usage(options);
        }

        // used for crypto operations
        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        IVParameterSpec IV = null;
        IV = new IVParameterSpec(iv);
        CryptoManager manager = null;
        CryptoToken token = null;
        KeyGenerator kg1 = null;
        String db_dir = "./";
        
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
        String keyId = null;
        String clientId = null;
        String recoveryRequestId = null;
        
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
        String baseUri = "http://" + host + ":" + port + "/pki";
        DRMRestClient client = new DRMRestClient(baseUri);

        // Test 1: Get transport certificate from DRM
        transportCert = client.getTransportCert();
        log("Transport Cert retrieved from DRM: " + transportCert);

        // Test 2: Get list of completed key archival requests
        log("\n\nList of completed archival requests");
        Collection<KeyRequestInfo> list = client.listRequests("complete", "enrolment");
        Iterator<KeyRequestInfo> iter = list.iterator();
        while (iter.hasNext()) {
            KeyRequestInfo info = iter.next();
            printRequestInfo(info);
        }

        // Test 3: Get list of key recovery requests
        log("\n\nList of completed recovery requests");
        Collection<KeyRequestInfo> list2 = client.listRequests("complete", "recovery");
        Iterator<KeyRequestInfo> iter2 = list2.iterator();
        while (iter2.hasNext()) {
            KeyRequestInfo info = iter2.next();
            printRequestInfo(info);
        }

        // Test 4: Generate and archive a symmetric key
        log("Archiving symmetric key");
        clientId = "UUID: 123-45-6789 VEK " + Calendar.getInstance().getTime().toString();
        try {
            kg1 = token.getKeyGenerator(KeyGenAlgorithm.DES3);
            vek = kg1.generate();
            byte[] encoded = createPKIArchiveOptions(manager, token, transportCert, vek, null, kg1);

            KeyRequestInfo info = client.archiveSecurityData(encoded, clientId);
            log("Archival Results:");
            printRequestInfo(info);
            keyId = getId(info.getKeyURL());
        } catch (Exception e) {
            log("Exception in archiving symmetric key:" + e.getMessage());
            e.printStackTrace();
        }

        //Test 5: Get keyId for active key with client ID
        log("Getting key ID for symmetric key");
        keyInfo = client.getKeyData(clientId, "active");
        String keyId2 = getId(keyInfo.getKeyURL());
        if (keyId2 == null) {
            log("No archived key found");
        } else {
            log("Archived Key found: " + keyId);
        }

        if (!keyId.equals(keyId2)) {
            log("Error: key ids from search and archival do not match");
        }

        // Test 6: Submit a recovery request for the symmetric key using a session key
        log("Submitting a recovery request for the  symmetric key using session key");
        try {
            recoveryKey = kg1.generate();
            wrappedRecoveryKey = wrapSymmetricKey(manager, token, transportCert, recoveryKey);
            KeyRequestInfo info = client.requestRecovery(keyId, null, wrappedRecoveryKey);
            recoveryRequestId = getId(info.getRequestURL());
        } catch (Exception e) {
            log("Exception in recovering symmetric key using session key: " + e.getMessage());
        }

        // Test 7: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 8: Get key
        log("Getting key: " + keyId);

        keyData = client.retrieveKey(keyId, recoveryRequestId, null, wrappedRecoveryKey);
        wrappedRecoveredKey = keyData.getWrappedPrivateData();
        try {
            recoveredKey = unwrap(token, IV, wrappedRecoveredKey.getBytes("ISO-8859-1"), recoveryKey);
        } catch (Exception e) {
            log("Exception in unwrapping key: " + e.toString());
            e.printStackTrace();
        }

        if (!recoveredKey.equals(com.netscape.osutil.OSUtil.BtoA(vek.getEncoded()))) {
            log("Error: recovered and archived keys do not match!");
        }

        // Test 9: Submit a recovery request for the symmetric key using a passphrase
        log("Submitting a recovery request for the  symmetric key using a passphrase");
        recoveryPassphrase = "Gimme me keys please";

        try {
            recoveryKey = kg1.generate();
            wrappedRecoveryPassphrase = wrapPassphrase(token, recoveryPassphrase, IV, recoveryKey);
            wrappedRecoveryKey = wrapSymmetricKey(manager, token, transportCert, recoveryKey);
            requestInfo = client.requestRecovery(keyId, wrappedRecoveryPassphrase, wrappedRecoveryKey);
            recoveryRequestId = getId(requestInfo.getRequestURL());
        } catch (Exception e) {
            log("Exception in recovering symmetric key using passphrase" + e.toString());
            e.printStackTrace();
        }

        //Test 10: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 11: Get key
        log("Getting key: " + keyId);
        keyData = client.retrieveKey(keyId, recoveryRequestId, wrappedRecoveryPassphrase, wrappedRecoveryKey);
        wrappedRecoveredKey = keyData.getWrappedPrivateData();
        recoveredKey = unwrap(wrappedRecoveredKey, recoveryPassphrase);

        if (!recoveredKey.equals(com.netscape.osutil.OSUtil.BtoA(vek.getEncoded()))) {
            log("Error: recovered and archived keys do not match!");
        }

        // Test 12: Generate and archive a passphrase
        clientId = "UUID: 123-45-6789 RKEK " + Calendar.getInstance().getTime().toString();
        try {
            byte[] encoded = createPKIArchiveOptions(manager, token, transportCert, null, passphrase, kg1);
            requestInfo = client.archiveSecurityData(encoded, clientId);
            log("Archival Results:");
            printRequestInfo(requestInfo);
            keyId = getId(requestInfo.getKeyURL());
        } catch (Exception e) {
            log("Exception in archiving symmetric key:" + e.toString());
            e.printStackTrace();
        }

        //Test 13: Get keyId for active passphrase with client ID
        log("Getting key ID for passphrase");
        keyInfo = client.getKeyData(clientId, "active");
        keyId2 = getId(keyInfo.getKeyURL());
        if (keyId2 == null) {
            log("No archived key found");
        } else {
            log("Archived Key found: " + keyId);
        }

        if (!keyId.equals(keyId2)) {
            log("Error: key ids from search and archival do not match");
        }

        // Test 14: Submit a recovery request for the passphrase using a session key
        log("Submitting a recovery request for the passphrase using session key");
        recoveryKey = null;
        recoveryRequestId = null;
        wrappedRecoveryKey = null;
        try {
            recoveryKey = kg1.generate();
            wrappedRecoveryKey = wrapSymmetricKey(manager, token, transportCert, recoveryKey);
            requestInfo = client.requestRecovery(keyId, null, wrappedRecoveryKey);
            recoveryRequestId = getId(requestInfo.getRequestURL());
        } catch (Exception e) {
            log("Exception in recovering passphrase using session key: " + e.getMessage());
        }

        // Test 15: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 16: Get key
        log("Getting passphrase: " + keyId);

        keyData = client.retrieveKey(keyId, recoveryRequestId, null, wrappedRecoveryKey);
        wrappedRecoveredKey = keyData.getWrappedPrivateData();
        try {
            recoveredKey = unwrap(token, IV, wrappedRecoveredKey.getBytes("ISO-8859-1"), recoveryKey);
        } catch (Exception e) {
            log("Exception in unwrapping key: " + e.toString());
            e.printStackTrace();
        }

        if (!recoveredKey.equals(passphrase)) {
            log("Error: recovered and archived passphrases do not match!");
        }

        // Test 17: Submit a recovery request for the passphrase using a passphrase
        log("Submitting a recovery request for the passphrase using a passphrase");
        requestInfo = client.requestRecovery(keyId, wrappedRecoveryPassphrase, wrappedRecoveryKey);
        recoveryRequestId = getId(requestInfo.getRequestURL());

        //Test 18: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 19: Get key
        log("Getting passphrase: " + keyId);
        keyData = client.retrieveKey(keyId, recoveryRequestId, wrappedRecoveryPassphrase, wrappedRecoveryKey);
        wrappedRecoveredKey = keyData.getWrappedPrivateData();
        recoveredKey = unwrap(wrappedRecoveredKey, recoveryPassphrase);

        if (!recoveredKey.equals(passphrase)) {
            log("Error: recovered and archived passphrases do not match!");
        }

    }

    private static String unwrap(String wrappedRecoveredKey, String recoveryPassphrase) {
        // TODO Auto-generated method stub
        return null;
    }

    private static void log(String string) {
        // TODO Auto-generated method stub
        System.out.println(string);
    }

    private static String unwrap(CryptoToken token, IVParameterSpec IV, byte[] wrappedRecoveredKey,
            SymmetricKey recoveryKey) throws NoSuchAlgorithmException, TokenException, BadPaddingException,
            IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {

        if (wrappedRecoveredKey == null || recoveryKey == null || token == null) {
            return null;
        }

        Cipher decryptor = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
        decryptor.initDecrypt(recoveryKey, IV);
        byte[] unwrappedData = decryptor.doFinal(wrappedRecoveredKey);
        String unwrappedS = new String(unwrappedData);

        return unwrappedS;
    }

    private static String getId(String link) {
        return link.substring(link.lastIndexOf("/"));
    }

    private static byte[] createPKIArchiveOptions(CryptoManager manager, CryptoToken token, String transportCert,
            SymmetricKey vek, String passphrase, KeyGenerator kg1) throws TokenException, CharConversionException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException,
            CertificateEncodingException, IOException, IllegalStateException, IllegalBlockSizeException,
            BadPaddingException {
        byte[] key_data = null;
        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        IVParameterSpec IV = null;
        IV = new IVParameterSpec(iv);

        //generate session key
        SymmetricKey sk = kg1.generate();

        if (passphrase != null) {
            key_data = wrapPassphrase(token, passphrase, IV, sk);
        } else {
            // wrap payload using session key
            KeyWrapper wrapper1 = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
            wrapper1.initWrap(sk, IV);
            key_data = wrapper1.wrap(vek);
        }

        // wrap session key using transport key
        byte[] session_data = wrapSymmetricKey(manager, token, transportCert, sk);

        // create PKIArchiveOptions structure
        AlgorithmIdentifier algS = new AlgorithmIdentifier(new OBJECT_IDENTIFIER("1.2.840.113549.3.7"),
                new OCTET_STRING(iv));
        EncryptedValue encValue = new EncryptedValue(null, algS, new BIT_STRING(session_data, 0), null, null,
                new BIT_STRING(key_data, 0));
        EncryptedKey key = new EncryptedKey(encValue);
        PKIArchiveOptions opt = new PKIArchiveOptions(key);
        SEQUENCE seq = new SEQUENCE();
        seq.addElement(new AVA(new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.5.1.4"), opt));

        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        seq.encode(bo);
        byte[] encoded = bo.toByteArray();
        return encoded;
    }

    private static byte[] wrapPassphrase(CryptoToken token, String passphrase, IVParameterSpec IV, SymmetricKey sk)
            throws NoSuchAlgorithmException, TokenException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] wrappedPassphrase = null;
        Cipher encryptor = null;

        if (passphrase == null || sk == null || token == null || IV == null) {
            return null;
        }

        encryptor = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
        log("cipher " + encryptor);

        if (encryptor != null) {
            encryptor.initEncrypt(sk, IV);
            wrappedPassphrase = encryptor.doFinal(passphrase.getBytes());
            log("Pass phrase mode key_data: " + wrappedPassphrase);

            // Try to decrypt
            String wrappedS = new String(wrappedPassphrase, "ISO-8859-1");
            byte[] pPhrase = wrappedS.getBytes("ISO-8859-1");
            encryptor.initDecrypt(sk, IV);
            byte[] decrypted = encryptor.doFinal(pPhrase);
            String s = new String(decrypted, "ISO-8859-1");
            log("Re decrypted pass phrase " + s + " decrypted.size " + decrypted.length);
        } else {
            throw new IOException("Failed to create cipher");
        }
        return wrappedPassphrase;
    }

    private static byte[] wrapSymmetricKey(CryptoManager manager, CryptoToken token, String transportCert,
            SymmetricKey sk) throws CertificateEncodingException, TokenException, NoSuchAlgorithmException,
            InvalidKeyException, InvalidAlgorithmParameterException {
        byte transport[] = com.netscape.osutil.OSUtil.AtoB(transportCert);
        X509Certificate tcert = manager.importCACertPackage(transport);
        KeyWrapper rsaWrap = token.getKeyWrapper(KeyWrapAlgorithm.RSA);
        rsaWrap.initWrap(tcert.getPublicKey(), null);
        byte session_data[] = rsaWrap.wrap(sk);
        return session_data;
    }

    private static void printRequestInfo(KeyRequestInfo info) {
        log("KeyRequestURL: " + info.getRequestURL());
        log("Key URL:       " + info.getKeyURL());
        log("Status:        " + info.getRequestStatus());
        log("Type:          " + info.getRequestType());
    }

}
