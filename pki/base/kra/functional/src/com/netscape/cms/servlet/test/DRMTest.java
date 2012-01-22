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

import java.io.ByteArrayInputStream;
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
import java.util.Random;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
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
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs7.EncryptedContentInfo;
import org.mozilla.jss.pkix.crmf.EncryptedKey;
import org.mozilla.jss.pkix.crmf.EncryptedValue;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.util.Password;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.key.model.KeyData;
import com.netscape.cms.servlet.key.model.KeyDataInfo;
import com.netscape.cms.servlet.request.KeyRequestResource;
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
        String db_dir = "./";

        // parse command line arguments
        Options options = new Options();
        options.addOption("h", true, "Hostname of the DRM");
        options.addOption("p", true, "Port of the DRM");
        options.addOption("w", true, "Token password");
        options.addOption("d", true, "Directory for tokendb");

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

        } catch (ParseException e) {
            System.err.println("Error in parsing command line options: " + e.getMessage());
            usage(options);
        }

        // used for crypto operations
        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        IVParameterSpec ivSpec;
        IVParameterSpec ivSpecServer;

        try {
            ivSpec = genIV(8);
        } catch (Exception e) {
            log("Can't generate initialization vector use default: " + e);
            ivSpec = new IVParameterSpec(iv);
        }

        CryptoManager manager = null;
        CryptoToken token = null;
        KeyGenerator kg1 = null;

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
        String baseUri = "http://" + host + ":" + port + "/kra/pki";
        DRMRestClient client = new DRMRestClient(baseUri);

        // Test 1: Get transport certificate from DRM
        transportCert = client.getTransportCert();
        transportCert = transportCert.substring(CMSResourceService.HEADER.length(),
                                                transportCert.indexOf(CMSResourceService.TRAILER));

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
            kg1 = token.getKeyGenerator(KeyGenAlgorithm.DES3);
            vek = kg1.generate();

            byte[] encoded = createPKIArchiveOptions(manager, token, transportCert, vek, null, kg1, ivSpec);

            KeyRequestInfo info = client.archiveSecurityData(encoded, clientId, KeyRequestResource.SYMMETRIC_KEY_TYPE);
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
        } else {
            log("Success: keyids from search and archival match.");
        }

        // Test 6: Submit a recovery request for the symmetric key using a session key
        log("Submitting a recovery request for the  symmetric key using session key");
        try {
            recoveryKey = kg1.generate();
            wrappedRecoveryKey = wrapSymmetricKey(manager, token, transportCert, recoveryKey);
            KeyRequestInfo info = client.requestRecovery(keyId, null, wrappedRecoveryKey, ivSpec.getIV());
            recoveryRequestId = getId(info.getRequestURL());
        } catch (Exception e) {
            log("Exception in recovering symmetric key using session key: " + e.getMessage());
        }

        // Test 7: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 8: Get key
        log("Getting key: " + keyId);

        keyData = client.retrieveKey(keyId, recoveryRequestId, null, wrappedRecoveryKey, ivSpec.getIV());
        wrappedRecoveredKey = keyData.getWrappedPrivateData();

        ivSpecServer = new IVParameterSpec( com.netscape.osutil.OSUtil.AtoB(keyData.getNonceData()));
        try {
            recoveredKey = unwrap(token, ivSpecServer,com.netscape.osutil.OSUtil.AtoB(wrappedRecoveredKey), recoveryKey);
        } catch (Exception e) {
            log("Exception in unwrapping key: " + e.toString());
            e.printStackTrace();
        }

        if (!recoveredKey.equals(com.netscape.osutil.OSUtil.BtoA(vek.getEncoded()))) {
            log("Error: recovered and archived keys do not match!");
        } else {
            log("Success: recoverd and archived keys match!");
        }

        // Test 9: Submit a recovery request for the symmetric key using a passphrase
        log("Submitting a recovery request for the  symmetric key using a passphrase");
        recoveryPassphrase = "Gimme me keys please";

        try {
            recoveryKey = kg1.generate();
            wrappedRecoveryPassphrase = wrapPassphrase(token, recoveryPassphrase, ivSpec, recoveryKey);
            wrappedRecoveryKey = wrapSymmetricKey(manager, token, transportCert, recoveryKey);

            requestInfo = client.requestRecovery(keyId, wrappedRecoveryPassphrase, wrappedRecoveryKey, ivSpec.getIV());
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
        keyData = client.retrieveKey(keyId, recoveryRequestId, wrappedRecoveryPassphrase, wrappedRecoveryKey, ivSpec.getIV());
        wrappedRecoveredKey = keyData.getWrappedPrivateData();

        recoveredKey = unwrap(wrappedRecoveredKey, recoveryPassphrase);


        if (recoveredKey == null || !recoveredKey.equals(com.netscape.osutil.OSUtil.BtoA(vek.getEncoded()))) {
            log("Error: recovered and archived keys do not match!");
        } else {
            log("Success: recovered and archived keys do match!");
        }


        passphrase = "secret12345";
        // Test 12: Generate and archive a passphrase
        clientId = "UUID: 123-45-6789 RKEK " + Calendar.getInstance().getTime().toString();
        try {
            byte[] encoded = createPKIArchiveOptions(manager, token, transportCert, null, passphrase, kg1, ivSpec);
            requestInfo = client.archiveSecurityData(encoded, clientId, KeyRequestResource.PASS_PHRASE_TYPE);
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
        } else {
            log("Success: key ids from search and archival do match!");
        }

        // Test 14: Submit a recovery request for the passphrase using a session key
        log("Submitting a recovery request for the passphrase using session key");
        recoveryKey = null;
        recoveryRequestId = null;
        wrappedRecoveryKey = null;
        try {
            recoveryKey = kg1.generate();
            wrappedRecoveryKey = wrapSymmetricKey(manager, token, transportCert, recoveryKey);
            wrappedRecoveryPassphrase = wrapPassphrase(token, recoveryPassphrase, ivSpec, recoveryKey);
            requestInfo = client.requestRecovery(keyId, null, wrappedRecoveryKey, ivSpec.getIV());
            recoveryRequestId = getId(requestInfo.getRequestURL());
        } catch (Exception e) {
            log("Exception in recovering passphrase using session key: " + e.getMessage());
        }

        // Test 15: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 16: Get key
        log("Getting passphrase: " + keyId);

        keyData = client.retrieveKey(keyId, recoveryRequestId, null, wrappedRecoveryKey, ivSpec.getIV());
        wrappedRecoveredKey = keyData.getWrappedPrivateData();
        ivSpecServer = new IVParameterSpec( com.netscape.osutil.OSUtil.AtoB(keyData.getNonceData()));
        try {
            recoveredKey = unwrap(token, ivSpecServer, com.netscape.osutil.OSUtil.AtoB(wrappedRecoveredKey), recoveryKey);
            recoveredKey = new String(com.netscape.osutil.OSUtil.AtoB(recoveredKey), "UTF-8");
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
        requestInfo = client.requestRecovery(keyId, wrappedRecoveryPassphrase, wrappedRecoveryKey, ivSpec.getIV());
        recoveryRequestId = getId(requestInfo.getRequestURL());

        //Test 18: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 19: Get key
        log("Getting passphrase: " + keyId);
        keyData = client.retrieveKey(keyId, recoveryRequestId, wrappedRecoveryPassphrase, wrappedRecoveryKey, ivSpec.getIV());
        wrappedRecoveredKey = keyData.getWrappedPrivateData();
        recoveredKey = unwrap(wrappedRecoveredKey, recoveryPassphrase);
        try {
            recoveredKey = new String(com.netscape.osutil.OSUtil.AtoB(recoveredKey), "UTF-8");
        } catch (Exception e) {
            log("Error: Can't convert recovered passphrase from binary to ascii!");
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
        recoveryRequestId = getId(requestInfo.getRequestURL());

        //Test 21: Approve recovery
        log("Approving recovery request: " + recoveryRequestId);
        client.approveRecovery(recoveryRequestId);

        // Test 22: Get key
        log("Getting passphrase: " + keyId);
        keyData = client.retrieveKey(keyId, recoveryRequestId, wrappedRecoveryPassphrase, wrappedRecoveryKey, ivSpec.getIV());
        wrappedRecoveredKey = keyData.getWrappedPrivateData();
        recoveredKey = unwrap(wrappedRecoveredKey, recoveryPassphrase);
        try {
            recoveredKey = new String(com.netscape.osutil.OSUtil.AtoB(recoveredKey), "UTF-8");
        } catch (Exception e) {
            log("Error: Can't convert recovered passphrase from binary to ascii!");
        }

        if (recoveredKey == null || !recoveredKey.equals(passphrase)) {
            log("Error: recovered and archived passphrases do not match!");
        } else {
            log("Success: recovered and archived passphrases do match!");
        }
    }

    private static String unwrap(String wrappedRecoveredKey, String recoveryPassphrase) {

        EncryptedContentInfo cInfo = null;
        String unwrappedData = null;

        //We have to do this to get the decoding to work.
        PBEAlgorithm pbeAlg = PBEAlgorithm.PBE_SHA1_DES3_CBC;

        log("pbeAlg: " + pbeAlg);
        try {
            Password pass = new Password(recoveryPassphrase.toCharArray());
            PasswordConverter passConverter = new
                    PasswordConverter();

            byte[] encoded = com.netscape.osutil.OSUtil.AtoB(wrappedRecoveredKey);

            ByteArrayInputStream inStream = new ByteArrayInputStream(encoded);
            cInfo = (EncryptedContentInfo)
                      new EncryptedContentInfo.Template().decode(inStream);

            byte[] decodedData = cInfo.decrypt(pass, passConverter);

            unwrappedData = com.netscape.osutil.OSUtil.BtoA(decodedData);

        } catch (Exception e) {
            log("Problem unwraping PBE wrapped datat! " + e.toString());

        }

        return unwrappedData;
    }

    private static void log(String string) {
        // TODO Auto-generated method stub
        System.out.println(string);
    }

    private static String unwrap(CryptoToken token, IVParameterSpec IV, byte[] wrappedRecoveredKey,
            SymmetricKey recoveryKey) throws NoSuchAlgorithmException, TokenException, BadPaddingException,
            IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {

        Cipher decryptor = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
        decryptor.initDecrypt(recoveryKey, IV);
        byte[] unwrappedData = decryptor.doFinal(wrappedRecoveredKey);
        String unwrappedS = com.netscape.osutil.OSUtil.BtoA( unwrappedData);

        return unwrappedS;
    }

    private static String getId(String link) {
        return link.substring(link.lastIndexOf("/") + 1);
    }

    private static byte[] createPKIArchiveOptions(CryptoManager manager, CryptoToken token, String transportCert,
            SymmetricKey vek, String passphrase, KeyGenerator kg1, IVParameterSpec IV) throws TokenException, CharConversionException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException,
            CertificateEncodingException, IOException, IllegalStateException, IllegalBlockSizeException,
            BadPaddingException {
        byte[] key_data = null;

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
                new OCTET_STRING(IV.getIV()));
        EncryptedValue encValue = new EncryptedValue(null, algS, new BIT_STRING(session_data, 0), null, null,
                new BIT_STRING(key_data, 0));
        EncryptedKey key = new EncryptedKey(encValue);
        PKIArchiveOptions opt = new PKIArchiveOptions(key);

        byte[] encoded = null;

        try {

            //Let's make sure we can decode the encoded PKIArchiveOptions..
          ByteArrayOutputStream oStream = new ByteArrayOutputStream();

          opt.encode(oStream);

          encoded = oStream.toByteArray();
          ByteArrayInputStream inStream = new ByteArrayInputStream( encoded);
          PKIArchiveOptions  options = (PKIArchiveOptions)
                    new PKIArchiveOptions.Template().decode(inStream);
          log("Decoded PKIArchiveOptions: " + options);
        } catch (IOException e) {
            log("Problem with PKIArchiveOptions: " + e.toString());
            return null;

        } catch (InvalidBERException e) {
            log("Problem with PKIArchiveOptions: " + e.toString());
            return null;
        }

        return encoded;
    }

    private static byte[] wrapPassphrase(CryptoToken token, String passphrase, IVParameterSpec IV, SymmetricKey sk)
            throws NoSuchAlgorithmException, TokenException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] wrappedPassphrase = null;
        Cipher encryptor = null;

        encryptor = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
        log("cipher " + encryptor);

        if (encryptor != null) {
            encryptor.initEncrypt(sk, IV);
            wrappedPassphrase = encryptor.doFinal(passphrase.getBytes("UTF-8"));
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

    //Use this when we actually create random initialization vectors
    private static IVParameterSpec genIV(int blockSize) throws Exception {
        // generate an IV
        byte[] iv = new byte[blockSize];

        Random rnd = new Random();
        rnd.nextBytes(iv);

        return new IVParameterSpec(iv);
    }
}
