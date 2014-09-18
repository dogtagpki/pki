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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

import java.net.*;
import java.io.*;
import java.util.*;
import java.math.*;
import java.util.Date;
import java.util.StringTokenizer;
import java.net.URL;
import java.net.URLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.lang.Exception;

import org.mozilla.jss.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.util.*;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.pkcs11.PK11Token;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.crmf.*;

//import netscape.security.provider.RSAPublicKey;
import netscape.security.pkcs.PKCS10;
import netscape.security.x509.X500Name;
import netscape.security.util.BigInt;
import netscape.security.x509.X500Signer;

import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;
import java.security.Signature;

import com.netscape.cmsutil.crypto.CryptoUtil;


/**
 * CMS Test framework .
 * Use this class to initalize,add a certificate ,generate a certificate request from certificate database.
 */


public class ComCrypto {

    private String cdir, certnickname, keysize, keytype, tokenname, tokenpwd;
    private String certpackage, pkcs10request;
    private boolean debug = true;
    private boolean DBlogin = false;
    private boolean generaterequest = false;

    private String transportcert = null;
    private boolean dualkey = false;
    public String CRMF_REQUEST = null;
    int START = 1;
    int END = START + 1;
    Password password = null;

    public static CryptoManager manager = null;
    public static CryptoToken token = null;
    public static final String PR_INTERNAL_TOKEN_NAME = "internal";
    private CryptoStore store = null;
    private Password pass1 = null, pass2 = null;

    private String bstr = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    private String blob, Blob1 = null;
    private String Blob2 = null;
    private String estr = "-----END NEW CERTIFICATE REQUEST-----";

    private String certprefix = null;

    public ComCrypto() {}
    ;

    /**
     * Constructor . Takes the parameter certificatedbdirectory , token name, password for cert database, certificatenickname, keysize, keytype(RSA/DSA/EC)
     * @param certdbdirectory.
     * @param tokenname 
     * @param certdbpassword 
     * @param certnickname 
     * @param keysize (1024/2048/4096) (nistp256, nistp512)
     * @param keytype (RSA/DSA/EC)
     */

    public ComCrypto(String cd, String tpwd, String cn, String ks, String kt) {
        cdir = cd;
        tokenname = PR_INTERNAL_TOKEN_NAME;
        tokenpwd = tpwd;
        certnickname = cn;
        keysize = ks;
        keytype = kt;
    }

    public ComCrypto(String cd, String tname, String tpwd, String cn, String ks, String kt) {
        cdir = cd;
        if ((tname==null) || (tname.equals(""))) {
            tokenname = PR_INTERNAL_TOKEN_NAME;
        } else {
            tokenname = tname;
        }
        tokenpwd = tpwd;
        certnickname = cn;
        keysize = ks;
        keytype = kt;
    }

    // Set and Get functions 

    public void setCertDir(String cd) {
        cdir = cd;
    }

    public void setCertnickname(String cd) {
        certnickname = cd;
    }

    public void setKeySize(String cd) {
        keysize = cd;
    }

    public void setKeyType(String cd) {
        keytype = cd;
    }

    public void setTokenName(String tn) {
        tokenname = tn;
    }
    public void setTokenPWD(String cd) {
        tokenpwd = cd;
    }

    public void setCertPackage(String cd) {
        certpackage = cd;
    }

    public void setGenerateRequest(boolean c) {
        generaterequest = c;
    }

    public void setDebug(boolean t) {
        debug = t;
    }

    public void setCertPrefix(String prefix) {
        certprefix = prefix;
    }

    /*
     * setTransportCert() should only be called when the calling profile
     * needs to do key archivals with the DRM and make sure the function
     * generateCRMFtransport() is called for the CRMF request generation
     * part.
     */
    public void setTransportCert(String tcert) {
        transportcert = tcert;
    }

    public void setDualKey(boolean dkey) {
        dualkey = dkey;
    }

    public String getPkcs10Request() {
        return pkcs10request;
    }

    /**
     * Parses the Certificate and returns SubjectDN . Takes certificate as parameter
     */

    public String getCertificateString(X509Certificate cert) {
        if (cert == null) {
            return null;
        }

        // note that it did not represent a certificate fully
        return cert.getVersion() + ";" + cert.getSerialNumber().toString() + ";"
                + cert.getIssuerDN() + ";" + cert.getSubjectDN();
    }

    /**
     *  Finds and returns  Certificate . Takes certificatenickname as parameter.
     */


    public X509Certificate findCert(String certname) {
        try {

            X509Certificate cert2 = manager.findCertByNickname(certname);

            return cert2;

        } catch (Exception e) {
            System.out.println("exception importing cert " + e.getMessage());
            return null;
        }

    }

    /**
     * Imports a certificate to Certificate Database. Takes certificate and nickname as parameters.
     */


    public boolean importCert(X509Certificate xcert, String nickname) {
        try {

            System.out.println(
                    "importCert x509 : importing with nickname: " + nickname);

            InternalCertificate cert2 = manager.importCertToPerm(xcert, nickname);

            cert2.setSSLTrust(2);
            return true;

        } catch (Exception e) {
            System.out.println("exception importing cert " + e.getMessage());
            return false;
        }

    }

    /**
     * Imports a certificate to Certificate Database. Takes certificate and nickname as parameters.
     */
    public boolean importCert(String cpack, String cn) {

        System.out.println("importCert string: importing with nickname: " + cn);
        try {

            String tmp = normalize(cpack);

            if (DBlogin) { 
                System.out.println("Already logged into to DB");
            }

            if (manager == null) {
                System.out.println("Manager object is null");
            }

            X509Certificate cert = manager.importCertPackage(tmp.getBytes(), cn);

            /*
             *  failing to import cert should not be detrimental. When failed,
             *  allow to continue and user can manually import them later.
             *  Same with trust setting.
             */
            if (cert != null)
                System.out.println("importCert string: importCertPackage() succeeded");
            else
                System.out.println("importCert string: importCertPackage() failed");

            /* set trust bits for the issuer CA cert */
            System.out.println("importCert string: set CA trust bits");
            X509Certificate[] ca_certs = manager.getCACerts();
            for (int i =0; i< ca_certs.length; i++) {
                // look for the signing CA
                if  (ca_certs[i].getSubjectDN().toString().equals(
                    cert.getIssuerDN().toString())) {
                    // set the trust bits
                    InternalCertificate icert =
                        (InternalCertificate) ca_certs[i];
                    icert.setSSLTrust(InternalCertificate.TRUSTED_CA
                          | InternalCertificate.TRUSTED_CLIENT_CA
                          | InternalCertificate.VALID_CA);

                    System.out.println("importCert string: CA trust bits set");
                    break;
                }
            }

        } catch (Exception e) {
            System.out.println(
                    "ERROR: exception importing cert: " + e.getMessage());
            e.printStackTrace();
            // return false;
        }
        return true;
    }

    /* imports CA certificate
     */

    public boolean importCACert(String cpack) {

        try {
            String tmp = normalize(cpack);

            if (DBlogin) { 
                System.out.println("Already logged into to DB");
            }
	
            if (manager == null) {
                System.out.println("Manager object is null");
            }

            X509Certificate cert = manager.importCACertPackage(tmp.getBytes());
            // adjust the trust bits
            InternalCertificate icert = (InternalCertificate) cert;
            icert.setSSLTrust(InternalCertificate.TRUSTED_CA
                          | InternalCertificate.TRUSTED_CLIENT_CA
                          | InternalCertificate.VALID_CA);

            return true;

        } catch (Exception e) {
            System.out.println(
                    "ERROR:exception importing cert " + e.getMessage());
            return false;
        }

    }

    /**
     * Normalizes a given certificate string . Removes the extra \\ in the certificate returned by CMS server.
     */


    public String normalize(String s) {

        String val = "";

        for (int i = 0; i < s.length(); i++) {
            if ((s.charAt(i) == '\\') && (s.charAt(i + 1) == 'n')) {
                val += '\n';
                i++;
                continue;
            } else if ((s.charAt(i) == '\\') && (s.charAt(i + 1) == 'r')) {
                i++;
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            }
            val += s.charAt(i);
        }
        return val;
    }

    /**
     * Normalizes a given certificate string . Removes the extra \\ in the certificate returned by CMS server.
     */


    String normalizeForLDAP(String s) {

        String val = "";

        for (int i = 0; i < s.length(); i++) {
            if ((s.charAt(i) == '\\') && (s.charAt(i + 1) == 'n')) {
                val += '\n' + " ";
                i++;
                continue;
            } else if ((s.charAt(i) == '\\') && (s.charAt(i + 1) == 'r')) {
                i++;
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            }
            val += s.charAt(i);
        }
        return val;
    }

    /**
     * Convert to pkcs7 format
     */


    public String pkcs7Convertcert(String s) {

        String val = "";

        int len = s.length();

        for (int i = 0; i < len; i = i + 64) {

            if (i + 64 < len) {
                val = val + s.substring(i, i + 64) + "\n";
            } else {
                val = val + s.substring(i, len);
            }

        }
        return val;
    }

    /**
     * Delete all keys frim key3.db
     **/

    public void deleteKeys() {
        try {
            int i = 0;

            store = token.getCryptoStore();
            PrivateKey[] keys = store.getPrivateKeys();

            if (debug) {
                System.out.println("Now we shall delete all the keys!");
            }

            keys = store.getPrivateKeys();
            for (i = 0; i < keys.length; i++) {
                PrivateKey key = (PrivateKey) keys[i];

                store.deletePrivateKey(key);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Creates a new certificate database
     **/


    public boolean CreateCertDB() {
        return loginDB();

    }

    /**
     *  Login to cert database
     **/

    public boolean loginDB() {
        Password pass1 = null;

        try {
            if (debug) {
                System.out.println("CRYPTO INIT WITH CERTDB:" + cdir);
            }

            // this piece of code is to create db's with certain prefix
            if (certprefix != null) {
                CryptoManager.InitializationValues vals;

                vals = new CryptoManager.InitializationValues(cdir, certprefix,
                        certprefix, "secmod.db");
                CryptoManager.initialize(vals);
            } else {
                CryptoManager.initialize(cdir);
            }

            manager = CryptoManager.getInstance();
            if (debug) {
                System.out.println("tokenname:" + tokenname);
            }

            if (tokenname.equals(PR_INTERNAL_TOKEN_NAME)) {
                token = manager.getInternalKeyStorageToken();
            } else {
                token = manager.getTokenByName(tokenname);
            }
            if (token == null) {
                System.out.println("loginDB: token null ");
                return false;
            }

            pass1 = new Password(tokenpwd.toCharArray());
            if (token.isLoggedIn() && debug) {
                System.out.println("Already Logged in ");
            }

            if (debug) {
                System.out.println("tokenpwd:" + tokenpwd);
            }

            token.login(pass1);
            pass1.clear();

        } catch (AlreadyInitializedException  e) {
            if (debug) {
                System.out.println("Crypto manager already initialized");
            }
        } catch (NoSuchTokenException e) {
            System.err.println("lolginDB:" + e);
            return false;
        } catch (Exception e) {
            try { 
                if (!token.isLoggedIn()) {
                    token.initPassword(pass1, pass1);
                }	
                return true;
            } catch (Exception er) {
                System.err.println("some exception:" + e);
                return false;
            }
        }
        DBlogin = true;
        return true;
    }

    /**
     * Generate Certificate Request
     **/

    public synchronized boolean generateRequest() {

        System.out.println("generating pkcs10 Request");
        loginDB();

        try {
            debug = true;
            System.out.println("Generating request : keysize :" + keysize);
            System.out.println("Generating request : subject :" + certnickname);
            System.out.println("Generating request : keytype :" + keytype);

            Integer n = new Integer(keysize);

            if (generaterequest) {
                blob = token.generateCertRequest(certnickname, n.intValue(),
                        keytype, (byte[]) null, (byte[]) null, (byte[]) null);

                System.out.println("Cert Request Generated.");

                bstr = "-----BEGIN NEW CERTIFICATE REQUEST-----";
                Blob1 = blob.substring(bstr.length() + 1);
                Blob2 = Blob1.substring(0, Blob1.indexOf(estr));

                System.out.println(Blob2);
                pkcs10request = Blob2;
            }

            return true;

        } catch (Exception e) {
            System.out.println("Exception: Unable to generate request: " + e);
        }

        return false;
    }

    public String generateCRMFrequest() {
        URL url = null;
        URLConnection conn = null;
        InputStream is = null;
        BufferedReader reader = null;
        boolean success = false;
        int num = 1;
        long total_time = 0;
        KeyPair pair = null;
		
        System.out.println("Debug : initialize crypto Manager");		
        try {

            // Step 1. initialize crypto Manager
            try { 
                CryptoManager.initialize(cdir);
            } catch (Exception e) { 
                // it is ok if it is already initialized 
                System.out.println("INITIALIZATION ERROR: " + e.toString());
                System.out.println("cdir = " + cdir);
            }

            // Step 2 log into database 
            try {

                System.out.println("Debug : before getInstance");

                manager = CryptoManager.getInstance(); 
                String token_pwd = tokenpwd;

                System.out.println("Debug : before get token");

                if (tokenname.equals(PR_INTERNAL_TOKEN_NAME)) {
                    token = manager.getInternalKeyStorageToken();
                } else {
                    token = manager.getTokenByName(tokenname);
                }
                if (token == null) {
                    System.err.println("generateCRMFrequest: token null ");
                    return null;
                }

                password = new Password(token_pwd.toCharArray()); 

                System.out.println("Debug : before login password");

                token.login(password); 

                System.out.println("Debug : after login password");
            } catch (NoSuchTokenException e) {
                System.err.println("generateCRMFrequest:" + e.toString());
                return null;
            } catch (Exception e) {
                System.out.println("INITIALIZATION ERROR: " + e.toString());

                if (!token.isLoggedIn()) {
                    token.initPassword(password, password);
                }
            }

            // Generating CRMF request 

            if (keytype.equalsIgnoreCase("rsa")) {
                KeyPairGenerator kg = token.getKeyPairGenerator(KeyPairAlgorithm.RSA); 

                Integer x = new Integer(keysize);
                int key_len = x.intValue();

                kg.initialize(key_len);

                // 1st key pair
                pair = kg.genKeyPair(); 
            } else if (keytype.equalsIgnoreCase("ecc")) {
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage usages_mask[] = {
                    org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DERIVE
                };
                pair = CryptoUtil.generateECCKeyPair(tokenname,
                      keysize /*ECC curve name*/,
                      null,
                      usages_mask,
                      false /*temporary*/,
                      -1 /*sensitive*/, -1 /*extractable*/);
            }

            // create CRMF
            CertTemplate certTemplate = new CertTemplate();

            certTemplate.setVersion(new INTEGER(2));

            if (certnickname != null) {
                X500Name name = new X500Name(certnickname);
                ByteArrayInputStream cs = new ByteArrayInputStream(name.getEncoded()); 
                Name n = (Name) Name.getTemplate().decode(cs);
                certTemplate.setSubject(n);
            }

            certTemplate.setPublicKey(new SubjectPublicKeyInfo(pair.getPublic()));

            SEQUENCE seq = new SEQUENCE();
            CertRequest certReq = new CertRequest(new INTEGER(1), certTemplate,
                    seq);
            byte popdata[] = { 0x0, 0x3, 0x0};

            ProofOfPossession pop = ProofOfPossession.createKeyEncipherment(
                    POPOPrivKey.createThisMessage(new BIT_STRING(popdata, 3)));

            CertReqMsg crmfMsg = new CertReqMsg(certReq, pop, null);

            SEQUENCE s1 = new SEQUENCE();
			
            // 1st : Encryption key 

            s1.addElement(crmfMsg);

            // 2nd : Signing Key
	
            if (dualkey) {
                System.out.println("dualkey = true");
                SEQUENCE seq1 = new SEQUENCE();
                CertRequest certReqSigning = new CertRequest(new INTEGER(1),
                        certTemplate, seq1);
                CertReqMsg signingMsg = new CertReqMsg(certReqSigning, pop, null);		

                s1.addElement(signingMsg);
            }		

            byte encoded[] = ASN1Util.encode(s1); 

            BASE64Encoder encoder = new BASE64Encoder(); 
            String Req1 = encoder.encodeBuffer(encoded);

            // Set CRMF_REQUEST variable 
            CRMF_REQUEST = Req1;

            System.out.println("CRMF_REQUEST = " + CRMF_REQUEST);

        } catch (Exception e) { 
            System.out.println("ERROR: " + e.toString());
            e.printStackTrace();
            return null;
        }

        return CRMF_REQUEST;
    }

    /*
     * This function is used to Generated CRMF requests wrapped with the 
     * transport cert so that we can do key archival with the drm.
     * This function expects transportcert variable to be set in this class.
     * Use setTransportCert() to do the same.
     */

    public String generateCRMFtransport() {

        boolean success = false;
        int num = 1;
        long total_time = 0;
        KeyPair pair = null;

        try {
            // Step 1. initialize crypto Manager
            try { 
                CryptoManager.initialize(cdir);
            } catch (Exception e) { 
                // it is ok if it is already initialized 
                System.out.println("INITIALIZATION ERROR: " + e.toString());
                System.out.println("cdir = " + cdir);
            }

            // Step 2 log into database 
            try {

                System.out.println("Debug : before getInstance");
	
                manager = CryptoManager.getInstance(); 
                String token_pwd = tokenpwd;
	
                System.out.println("Debug : before get token");
	
                if (tokenname.equals(PR_INTERNAL_TOKEN_NAME)) {
                    token = manager.getInternalKeyStorageToken();
                } else {
                    token = manager.getTokenByName(tokenname);
                } 
                if (token == null) {
                    System.err.println("generateCRMFtransport: token null ");
                    return null;
                }

                password = new Password(token_pwd.toCharArray()); 

                System.out.println("Debug : before login password");

                token.login(password); 

                System.out.println("Debug : after login password");
            } catch (NoSuchTokenException e) {
                System.err.println("generateCRMFtransport:" + e.toString());
                return null;
            } catch (Exception e) {
                System.out.println("INITIALIZATION ERROR: " + e.toString());

                if (!token.isLoggedIn()) {
                    token.initPassword(password, password);
                }
            }
	
            // Key Pair Generation
            KeyPairGenerator kg = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);
            Integer x = new Integer(keysize);
            int key_len = x.intValue();

            kg.initialize(key_len);

            pair = kg.genKeyPair();

            // wrap private key
            BASE64Decoder decoder = new BASE64Decoder();
            byte transport[] = decoder.decodeBuffer(transportcert);

            X509Certificate tcert = manager.importCACertPackage(transport);

            byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};

            KeyGenerator kg1 = token.getKeyGenerator(KeyGenAlgorithm.DES3);
            SymmetricKey sk = kg1.generate();

            // wrap private key using session
            KeyWrapper wrapper1 = token.getKeyWrapper(
                    KeyWrapAlgorithm.DES3_CBC_PAD);

            wrapper1.initWrap(sk, new IVParameterSpec(iv));

            byte key_data[] = wrapper1.wrap((
                    org.mozilla.jss.crypto.PrivateKey) pair.getPrivate());

            // wrap session using transport
            KeyWrapper rsaWrap = token.getKeyWrapper(KeyWrapAlgorithm.RSA);

            rsaWrap.initWrap(tcert.getPublicKey(), null);

            byte session_data[] = rsaWrap.wrap(sk);

            // create CRMF
            CertTemplate certTemplate = new CertTemplate();

            certTemplate.setVersion(new INTEGER(2));

            if (certnickname != null) {
                X500Name name = new X500Name(certnickname);
                ByteArrayInputStream cs = new ByteArrayInputStream(name.getEncoded());
                Name n = (Name) Name.getTemplate().decode(cs);
                certTemplate.setSubject(n);
            }

            certTemplate.setPublicKey(new SubjectPublicKeyInfo(pair.getPublic()));

            // set extension
            AlgorithmIdentifier algS = null;
            if (keytype.equalsIgnoreCase("rsa")) {
                algS = new AlgorithmIdentifier(
                    new OBJECT_IDENTIFIER("1.2.840.113549.3.7"),
                    new OCTET_STRING(iv));
            } else if (keytype.equalsIgnoreCase("ecc")) {
                algS = new AlgorithmIdentifier(
                    new OBJECT_IDENTIFIER("1.2.840.10045.2.1"),
                    new OCTET_STRING(iv));
            }

            EncryptedValue encValue = new EncryptedValue(null, algS,
                    new BIT_STRING(session_data, 0), null, null,
                    new BIT_STRING(key_data, 0));

            EncryptedKey key = new EncryptedKey(encValue);
            PKIArchiveOptions opt = new PKIArchiveOptions(key);

            SEQUENCE seq = new SEQUENCE();

            seq.addElement(
                    new AVA(new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.5.1.4"), opt));

            CertRequest certReq = new CertRequest(new INTEGER(1), certTemplate,
                    seq);

            // Adding proof of possesion data
            byte popdata[] = { 0x0, 0x3, 0x0};
            ProofOfPossession pop = ProofOfPossession.createKeyEncipherment(
                    POPOPrivKey.createThisMessage(new BIT_STRING(popdata, 3)));

            CertReqMsg crmfMsg = new CertReqMsg(certReq, pop, null);

            SEQUENCE s1 = new SEQUENCE();

            // 1st : Encryption key 
            s1.addElement(crmfMsg);

            // 2nd : Signing Key
	
            if (dualkey) {
                System.out.println("dualkey = true");
                SEQUENCE seq1 = new SEQUENCE();
                CertRequest certReqSigning = new CertRequest(new INTEGER(1),
                        certTemplate, seq1);
                CertReqMsg signingMsg = new CertReqMsg(certReqSigning, pop, null);		

                s1.addElement(signingMsg);
            }		

            byte encoded[] = ASN1Util.encode(s1);
	
            BASE64Encoder encoder = new BASE64Encoder();

            CRMF_REQUEST = encoder.encodeBuffer(encoded);

            System.out.println("Generated crmf request: ...... ");
            System.out.println("");

            System.out.println(CRMF_REQUEST);
            System.out.println("");
            System.out.println("End crmf Request:");
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
		
        return CRMF_REQUEST;
    }

} // end of class 


