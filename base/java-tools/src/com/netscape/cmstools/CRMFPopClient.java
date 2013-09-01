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
package com.netscape.cmstools;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import netscape.security.x509.X500Name;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.PrintableString;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.TeletexString;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.asn1.UniversalString;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.EncryptedKey;
import org.mozilla.jss.pkix.crmf.EncryptedValue;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.crmf.POPOSigningKey;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.HMACDigest;
import com.netscape.cmsutil.util.Utils;

/**
 * A command-line utility used to generate a Certificate Request Message
 * Format (CRMF) request with proof of possesion (POP).
 *
 * <pre>
 * IMPORTANT:  The file "transport.txt" needs to be created to contain the
 *             transport certificate in its base64 encoded format.  This
 *             file should consist of one line containing a single certificate
 *             in base64 encoded format with the header and footer removed.
 * </pre>
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class CRMFPopClient {

    private static void usage() {

        System.out.println("Usage: CRMFPopClient -d <location of certdb> -p <token password> -h <tokenname> -o <output file which saves the base64 CRMF request> -n <subjectDN> -a <algorithm: 'rsa' or 'ec'> -l <rsa key length> -c <ec curve name> -m <hostname:port> -f <profile name; rsa default caEncUserCert; ec default caEncECUserCert> -u <user name> -r <requestor name> -q <POP_NONE, POP_SUCCESS, or POP_FAIL; default POP_SUCCESS> \n");
        System.out.println("    Optionally, for ECC key generation per definition in JSS pkcs11.PK11KeyPairGenerator:\n");
        System.out.println("    -k <true for enabling encoding of attribute values; false for default encoding of attribute values; default is false>\n");
        System.out.println("    -t <true for temporary(session); false for permanent(token); default is true>\n");
        System.out.println("    -s <1 for sensitive; 0 for non-sensitive; -1 temporaryPairMode dependent; default is -1>\n");
        System.out.println("    -e <1 for extractable; 0 for non-extractable; -1 token dependent; default is -1>\n");
        System.out.println("    Also optional for ECC key generation:\n");
        System.out.println("    -x <true for SSL cert that does ECDH ECDSA; false otherwise; default false>\n");
        System.out.println(" note: '-x true' can only be used with POP_NONE");
        System.out.println("   available ECC curve names (if provided by the crypto module): nistp256 (secp256r1),nistp384 (secp384r1),nistp521 (secp521r1),nistk163 (sect163k1),sect163r1,nistb163 (sect163r2),sect193r1,sect193r2,nistk233 (sect233k1),nistb233 (sect233r1),sect239k1,nistk283 (sect283k1),nistb283 (sect283r1),nistk409 (sect409k1),nistb409 (sect409r1),nistk571 (sect571k1),nistb571 (sect571r1),secp160k1,secp160r1,secp160r2,secp192k1,nistp192 (secp192r1, prime192v1),secp224k1,nistp224 (secp224r1),secp256k1,prime192v2,prime192v3,prime239v1,prime239v2,prime239v3,c2pnb163v1,c2pnb163v2,c2pnb163v3,c2pnb176v1,c2tnb191v1,c2tnb191v2,c2tnb191v3,c2pnb208w1,c2tnb239v1,c2tnb239v2,c2tnb239v3,c2pnb272w1,c2pnb304w1,c2tnb359w1,c2pnb368w1,c2tnb431r1,secp112r1,secp112r2,secp128r1,secp128r2,sect113r1,sect113r2,sect131r1,sect131r2\n");

        System.out.println("\n");
        System.out.println("IMPORTANT:  The file \"transport.txt\" needs to be created to contain the");
        System.out.println("            transport certificate in its base64 encoded format.  This");
        System.out.println("            file should consist of one line containing a single certificate");
        System.out.println("            in base64 encoded format with the header and footer removed.\n");
    }

    private static int getRealArgsLength(String args[]) {

        int len = args.length;

        String curArg = "";
        int finalLen = len;

        for (int i = 0; i < len; i++) {

            curArg = args[i];
            // System.out.println("arg[" + i + "]  " + curArg);

            if (curArg == null || curArg.equalsIgnoreCase("")) {
                finalLen--;
            }

        }

        //System.out.println("getRealArgsLength: returning " + finalLen);

        if (finalLen < 0)
            finalLen = 0;

        return finalLen;

    }

    public static void main(String args[]) {

//        int argsLen =  getRealArgsLength(args);

        System.out.println("\n\nCRMF Proof Of Possession Utility....");
        System.out.println("");

        if (args.length < 4)
        {
             usage();
             System.exit(1);
        }

        String DB_DIR = "./";
        String TOKEN_PWD = null;
        String TOKEN_NAME = null;

        // "rsa" or "ec"
        String alg = "rsa";

        /* default RSA key size */
        int RSA_keylen = 2048;
        /* default ECC key curve name */
        String ECC_curve = "nistp256";
        boolean enable_encoding = false; /* enable encoding attribute values if true */
        boolean ec_temporary = true; /* session if true; token if false */
        int ec_sensitive = -1; /* -1, 0, or 1 */
        int ec_extractable = -1; /* -1, 0, or 1 */
        boolean ec_ssl_ecdh = false;

        String USER_NAME = null;
        String REQUESTOR_NAME = null;
        String PROFILE_NAME = null;

        // format: "host:port"
        String HOST_PORT = null;
        String SUBJ_DN = null;
        int doServerHit = 0;

        // POP_NONE, POP_SUCCESS, or POP_FAIL
        String POP_OPTION = "POP_SUCCESS";
        int dont_do_pop = 0;

        String REQ_OUT_FILE = null;

        for (int i=0; i<args.length; i+=2) {
            String name = args[i];

            if (name.equals("-p")) {
                TOKEN_PWD = args[i+1];
            } else if (name.equals("-d")) {
                DB_DIR = args[i+1];
            } else if (name.equals("-h")) {
                TOKEN_NAME = args[i+1];
            } else if (name.equals("-a")) {
                alg = args[i+1];
                if (!alg.equals("rsa") && !alg.equals("ec")) {
                    System.out.println("CRMFPopClient: ERROR: invalid algorithm: " + alg);
                    System.exit(1);
                }
            } else if (name.equals("-x")) {
                String temp = args[i+1];
                if (temp.equals("true"))
                    ec_ssl_ecdh = true;
                else
                    ec_ssl_ecdh = false;
            } else if (name.equals("-t")) {
                String temp = args[i+1];
                if (temp.equals("true"))
                    ec_temporary = true;
                else
                    ec_temporary = false;
            } else if (name.equals("-k")) {
                String temp = args[i+1];
                if (temp.equals("true"))
                    enable_encoding = true;
                else
                    enable_encoding = false;
            } else if (name.equals("-s")) {
                String ec_sensitive_s = args[i+1];
                ec_sensitive = Integer.parseInt(ec_sensitive_s);
                if ((ec_sensitive != 0) &&
                    (ec_sensitive != 1) &&
                    (ec_sensitive != -1)) {
                      System.out.println("PKCS10Client: Illegal input parameters for -s.");
                      usage();
                      System.exit(1);
                    }
            } else if (name.equals("-e")) {
                String ec_extractable_s = args[i+1];
                ec_extractable = Integer.parseInt(ec_extractable_s);
                if ((ec_extractable != 0) &&
                    (ec_extractable != 1) &&
                    (ec_extractable != -1)) {
                      System.out.println("PKCS10Client: Illegal input parameters for -e.");
                      usage();
                      System.exit(1);
                    }
            } else if (name.equals("-l")) {
                RSA_keylen = Integer.parseInt(args[i+1]);
            } else if (name.equals("-c")) {
                ECC_curve = args[i+1];
            } else if (name.equals("-m")) {
                HOST_PORT = args[i+1];
                doServerHit = 1;
            } else if (name.equals("-f")) {
                PROFILE_NAME = args[i+1];
            } else if (name.equals("-u")) {
                USER_NAME = args[i+1];
            } else if (name.equals("-r")) {
                REQUESTOR_NAME = args[i+1];
            } else if (name.equals("-n")) {
                SUBJ_DN = args[i+1];
            } else if (name.equals("-q")) {
                POP_OPTION = args[i+1];
                if (!POP_OPTION.equals("POP_SUCCESS") &&
                    !POP_OPTION.equals("POP_FAIL") &&
                    !POP_OPTION.equals("POP_NONE")) {
                    System.out.println("CRMFPopClient: ERROR: invalid POP option: "+ POP_OPTION);
                    System.exit(1);
                }
                if (POP_OPTION.equals("POP_NONE"))
                    dont_do_pop = 1;
            } else if (name.equals("-o")) {
                REQ_OUT_FILE = args[i+1];
            } else {
                System.out.println("Unrecognized argument(" + i + "): "
                    + name);
                usage();
                System.exit(1);
            }
        } //for

        URL url = null;
        URLConnection conn = null;
        InputStream is = null;
        BufferedReader reader = null;
        boolean success = false;
        long total_time = 0;
        KeyPair pair = null;

        boolean foundTransport = false;
        String transportCert = null;
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("./transport.txt"));
            transportCert = br.readLine();
            foundTransport = true;
        } catch (Exception e) {
            System.out.println("CRMFPopClient: ERROR: cannot find ./transport.txt, so no key archival");

            System.exit(1);
        } finally {
             if (br != null) {
                 try {
                     br.close();
                 } catch (IOException e) {
                     e.printStackTrace();
                 }
             }
        }

        try {
            CryptoManager.initialize( DB_DIR );
        } catch (AlreadyInitializedException ae) {
            // it is ok if it is already initialized
            System.out.println("CRMFPopClient: already initialized, continue");
        } catch (Exception e) {
            System.out.println("CRMFPopClient: INITIALIZATION ERROR: " + e.toString());
            System.exit(1);
        }

        try {
            CryptoManager manager = CryptoManager.getInstance();
            String token_pwd = TOKEN_PWD;
            if (token_pwd == null) {
               System.out.println("missing password");
               usage();
               System.exit(1);
            }
            CryptoToken token = null;
            if (TOKEN_NAME == null) {
                token = manager.getInternalKeyStorageToken();
                TOKEN_NAME = token.getName();
            } else {
                token = manager.getTokenByName(TOKEN_NAME);
            }
            System.out.println("CRMFPopClient: getting token: "+TOKEN_NAME);
            manager.setThreadToken(token);
            Password password = new Password(token_pwd.toCharArray());
            try {
                token.login(password);
            } catch (Exception e) {
                System.out.println("CRMFPopClient: login Exception: " + e.toString());
                System.exit(1);
            }

            System.out.println("."); //"done with cryptomanager");

            String profileName = PROFILE_NAME;
            if (profileName == null) {
                if (alg.equals("rsa"))
                    profileName = "caEncUserCert";
                else if (alg.equals("ec"))
                    profileName = "caEncECUserCert";
                else {
                    System.out.println("CRMFPopClient: unsupported algorithm: " + alg);
                    usage();
                    System.exit(1);
                }
            }

            if (alg.equals("rsa")) {
                KeyPairGenerator kg = token.getKeyPairGenerator(
                KeyPairAlgorithm.RSA);
                kg.initialize(RSA_keylen);

                pair = kg.genKeyPair();
            } else if (alg.equals("ec")) {
                /*
                 * used with SSL server cert that does ECDH ECDSA
                 *  ** can only be used with POP_NONE **
                 */
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage usages_mask_ECDH[] = {
                    org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN,
                    org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN_RECOVER
                };

                /* used for other certs including SSL server cert that does ECDHE ECDSA */
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage usages_mask[] = {
                    org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DERIVE
                };

                pair = CryptoUtil.generateECCKeyPair(TOKEN_NAME, ECC_curve,
                    null,
                    (ec_ssl_ecdh==true) ? usages_mask_ECDH: usages_mask,
                       ec_temporary /*temporary*/,
                       ec_sensitive /*sensitive*/, ec_extractable /*extractable*/);
            }

            System.out.println("CRMFPopClient: key pair generated."); //key pair generated");

            // wrap private key
            byte transport[] = Utils.base64decode(transportCert);

            X509Certificate tcert = manager.importCACertPackage(transport);

            byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };

            KeyGenerator kg1 = token.getKeyGenerator(KeyGenAlgorithm.DES3);
            SymmetricKey sk = kg1.generate();

            System.out.println(".before KeyWrapper");

            // wrap private key using session
            KeyWrapper wrapper1 =
                token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);

            System.out.println(".key wrapper created");

            wrapper1.initWrap(sk, new IVParameterSpec(iv));

            System.out.println(".key wrapper inited");
            byte key_data[] = wrapper1.wrap((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate());

            System.out.println(".key wrapper wrapped");

            // wrap session key using DRM transport cert
            // currently, a transport cert has to be an RSA cert,
            // regardless of the key you are wrapping
            KeyWrapper rsaWrap = token.getKeyWrapper(
            KeyWrapAlgorithm.RSA);

            System.out.println(".got rsaWrapper");

            rsaWrap.initWrap(tcert.getPublicKey(), null);

            System.out.println(".rsaWrap inited");

            byte session_data[] = rsaWrap.wrap(sk);

            System.out.println(".rsaWrapped");

            try {
                // create CRMF
                CertTemplate certTemplate = new CertTemplate();
                certTemplate.setVersion(new INTEGER(2));

                Name n1 = getJssName(enable_encoding, SUBJ_DN);

                Name n = new Name();

                n.addCommonName("Me");
                n.addCountryName("US");
                n.addElement(new AVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"),  new PrintableString("MyUid")));

                if (n1 != null)
                    certTemplate.setSubject(n1);
                else
                    certTemplate.setSubject(n);

                certTemplate.setPublicKey(new SubjectPublicKeyInfo(pair.getPublic()));
                // set extension
                AlgorithmIdentifier algS = null;
                if (alg.equals("rsa")) {
                    algS = new AlgorithmIdentifier(new OBJECT_IDENTIFIER("1.2.840.113549.3.7"), new OCTET_STRING(iv));
                } else { // ec
                    algS = new AlgorithmIdentifier(new OBJECT_IDENTIFIER("1.2.840.10045.2.1"), new OCTET_STRING(iv));
                }

                EncryptedValue encValue = new EncryptedValue(null, algS, new BIT_STRING(session_data, 0),null, null,new BIT_STRING(key_data, 0));
                EncryptedKey key = new EncryptedKey(encValue);
                PKIArchiveOptions opt = new PKIArchiveOptions(key);
                SEQUENCE seq = new SEQUENCE();
                if (foundTransport) {
                    seq.addElement(new AVA(new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.5.1.4"), opt));
                }

                // Add idPOPLinkWitness control
                String secretValue = "testing";
                byte[] key1 = null;
                byte[] finalDigest = null;
                try {
                    MessageDigest SHA1Digest = MessageDigest.getInstance("SHA1");
                    key1 = SHA1Digest.digest(secretValue.getBytes());
                } catch (NoSuchAlgorithmException ex) {
                    System.exit(1);
                }

                /* Example of adding the POP link witness control to CRMF */
                byte[] b =
                { 0x10, 0x53, 0x42, 0x24, 0x1a, 0x2a, 0x35, 0x3c,
                     0x7a, 0x52, 0x54, 0x56, 0x71, 0x65, 0x66, 0x4c,
                     0x51, 0x34, 0x35, 0x23, 0x3c, 0x42, 0x43, 0x45,
                     0x61, 0x4f, 0x6e, 0x43, 0x1e, 0x2a, 0x2b, 0x31,
                     0x32, 0x34, 0x35, 0x36, 0x55, 0x51, 0x48, 0x14,
                     0x16, 0x29, 0x41, 0x42, 0x43, 0x7b, 0x63, 0x44,
                     0x6a, 0x12, 0x6b, 0x3c, 0x4c, 0x3f, 0x00, 0x14,
                     0x51, 0x61, 0x15, 0x22, 0x23, 0x5f, 0x5e, 0x69 };

                try {
                    MessageDigest SHA1Digest = MessageDigest.getInstance("SHA1");
                    HMACDigest hmacDigest = new HMACDigest(SHA1Digest, key1);
                    hmacDigest.update(b);
                    finalDigest = hmacDigest.digest();
                } catch (NoSuchAlgorithmException ex) {
                    System.exit(1);
                }

                OCTET_STRING ostr = new OCTET_STRING(finalDigest);
                seq.addElement(new AVA(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness, ostr));
                CertRequest certReq = new CertRequest(new INTEGER(1), certTemplate, seq);

                System.out.println(".CertRequest created");

                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                certReq.encode(bo);
                byte[] toBeVerified = bo.toByteArray();

                byte popdata[] = ASN1Util.encode(certReq);
                byte signature[];

                System.out.println(".CertRequest encoded");

                Signature signer = null;
                if (alg.equals("rsa")) {
                    signer =  token.getSignatureContext(
                        SignatureAlgorithm.RSASignatureWithMD5Digest);
                } else { //ec
                    signer =  token.getSignatureContext(
                        SignatureAlgorithm.ECSignatureWithSHA1Digest);
                }

                System.out.println(". signer created");

                signer.initSign((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate());

                System.out.println(".signer inited");

                System.out.println("."); //FAIL_OR_SUCC " + FAIL_OR_SUCC);

                if (POP_OPTION.equals("POP_SUCCESS")) {
                    System.out.println("CRMFPopClient: Generating Legal POP Data.....");
                    signer.update(toBeVerified);
                } else if (POP_OPTION.equals("POP_FAIL")) {
                    System.out.println("CRMFPopClient: Generating Illegal POP Data.....");
                    signer.update(iv);
                } else if (dont_do_pop == 1) {
                     System.out.println("CRMFPopClient: Generating NO POP Data.....");
                }

                System.out.println("."); //signer updated");

                CertReqMsg crmfMsg = null;

                if (dont_do_pop == 0)
                {
                    signature = signer.sign();

                    System.out.println("CRMFPopClient: Signature completed...");
                    System.out.println("");

                    AlgorithmIdentifier algID = null;
                    if (alg.equals("rsa")) {
                        algID = new AlgorithmIdentifier(SignatureAlgorithm.RSASignatureWithMD5Digest.toOID(), null );
                    } else { // "ec"
                        algID = new AlgorithmIdentifier(SignatureAlgorithm.ECSignatureWithSHA1Digest.toOID(), null );
                    }
                    POPOSigningKey popoKey = new POPOSigningKey(null,algID, new BIT_STRING(signature,0));

                    ProofOfPossession pop = ProofOfPossession.createSignature(popoKey);

                    crmfMsg = new CertReqMsg(certReq, pop, null);
                } else {
                    crmfMsg = new CertReqMsg(certReq, null, null);
                }

                //crmfMsg.verify();

                SEQUENCE s1 = new SEQUENCE();
                s1.addElement(crmfMsg);
                byte encoded[] = ASN1Util.encode(s1);

                String Req1 = Utils.base64encode(encoded);

                if (REQ_OUT_FILE != null)
                {
                    System.out.println("CRMFPopClient: Generated Cert Request: ...... ");
                    System.out.println("");

                    System.out.println(Req1);
                    System.out.println("");
                    System.out.println("CRMFPopClient: End Request:");

                    PrintStream ps = null;
                    ps = new PrintStream(new FileOutputStream(REQ_OUT_FILE));
                    ps.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
                    ps.println(Req1);
                    ps.println("-----END NEW CERTIFICATE REQUEST-----");
                    ps.flush();
                    ps.close();
                    System.out.println("CRMFPopClient: done output request to file: "+ REQ_OUT_FILE);

                    if (doServerHit == 0)
                        return;
                    }

                    String Req = URLEncoder.encode(Req1);

                    url =
                            new URL("http://"
                                + HOST_PORT + "/ca/ee/ca/profileSubmit?cert_request_type=crmf&cert_request="
                                + Req + "&renewal=false&uid=" + USER_NAME + "&xmlOutput=false&&profileId="
                                + profileName + "&sn_uid=" + USER_NAME +"&SubId=profile&requestor_name="
                                + REQUESTOR_NAME);

                    System.out.println("CRMFPopClient: Posting " + url);

                    System.out.println("");
                    System.out.println("CRMFPopClient: Server Response.....");
                    System.out.println("--------------------");
                    System.out.println("");

                    long start_time = (new Date()).getTime();
                    conn = url.openConnection();
                    is = conn.getInputStream();
                    reader = new BufferedReader(new InputStreamReader(is));
                    String line = null;

                    while ((line = reader.readLine()) != null) {
                        System.out.println(line);
                        if (line.equals("CMS Enroll Request Success")) {
                            success = true;
                            System.out.println("CRMFPopClient: Enrollment Successful: ......");
                            System.out.println("");
                        }
                    } /* while */

                    long end_time = (new Date()).getTime();
                    total_time += (end_time - start_time);
                } catch (Exception e) {
                    System.out.println("CRMFPopClient: WARNING: " + e.toString());
                    e.printStackTrace();
                }
        } catch (Exception e) {
                System.out.println("CRMFPopClient: ERROR: " + e.toString());
                e.printStackTrace();
        }
    }

    static boolean isEncoded (String elementValue) {
        boolean encoded = false;

        if (elementValue != null && ((elementValue.startsWith("UTF8String:")) ||
                                     (elementValue.startsWith("PrintableString:")) ||
                                     (elementValue.startsWith("BMPString:")) ||
                                     (elementValue.startsWith("TeletexString:")) ||
                                     (elementValue.startsWith("UniversalString:")))) {
            encoded = true;
        }
        return encoded;
    }

    static Name addNameElement (Name name, OBJECT_IDENTIFIER oid, int n, String elementValue) {
        try {
            String encodingType = (n > 0)? elementValue.substring(0, n): null;
            String nameValue = (n > 0)? elementValue.substring(n+1): null;
            if (encodingType != null && encodingType.length() > 0 &&
                nameValue != null && nameValue.length() > 0) {
                if (encodingType.equals("UTF8String")) {
                    name.addElement( new AVA(oid, new UTF8String(nameValue)));
                } else if (encodingType.equals("PrintableString")) {
                    name.addElement( new AVA(oid, new PrintableString(nameValue)));
                } else if (encodingType.equals("BMPString")) {
                    name.addElement( new AVA(oid, new BMPString(nameValue)));
                } else if (encodingType.equals("TeletexString")) {
                    name.addElement( new AVA(oid, new TeletexString(nameValue)));
                } else if (encodingType.equals("UniversalString")) {
                    name.addElement( new AVA(oid, new UniversalString(nameValue)));
                }
            }
        }  catch (Exception e)  {
            System.out.println("CRMFPopClient: Error adding name element: " + elementValue + " Error: "  + e.toString());
        }
        return name;
    }

    static Name getJssName(boolean enable_encoding, String dn) {

        X500Name x5Name = null;

        try {
            x5Name = new X500Name(dn);

        } catch (IOException e) {

            System.out.println("CRMFPopClient: Illegal Subject Name:  " + dn + " Error: " + e.toString());
            System.out.println("CRMFPopClient: Filling in default Subject Name......");
            return null;
        }

        Name ret = new Name();

        netscape.security.x509.RDN[] names = null;

        names = x5Name.getNames();

        int nameLen = x5Name.getNamesLength();

        //            System.out.println("x5Name len: " + nameLen);

        netscape.security.x509.RDN cur = null;

        for (int i = 0; i < nameLen; i++) {
            cur = names[i];

            String rdnStr = cur.toString();

            String[] split = rdnStr.split("=");

            if (split.length != 2)
                continue;
            int n = split[1].indexOf(':');

            try {

                if (split[0].equals("UID")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement(ret, new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"),
                                             n, split[1]);
                    } else {
                        ret.addElement(new AVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"),
                                               new PrintableString(split[1])));
                    }
                    //                    System.out.println("UID found : " + split[1]);

                }

                if (split[0].equals("C")) {
                    ret.addCountryName(split[1]);
                    //                   System.out.println("C found : " + split[1]);
                    continue;

                }

                if (split[0].equals("CN")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement (ret, Name.commonName, n, split[1]);
                    } else {
                        ret.addCommonName(split[1]);
                    }
                    //                  System.out.println("CN found : " + split[1]);
                    continue;
                }

                if (split[0].equals("L")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement (ret, Name.localityName, n, split[1]);
                    } else {
                        ret.addLocalityName(split[1]);
                    }
                    //                 System.out.println("L found : " + split[1]);
                    continue;
                }

                if (split[0].equals("O")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement (ret, Name.organizationName, n, split[1]);
                    } else {
                        ret.addOrganizationName(split[1]);
                    }
                    //                System.out.println("O found : " + split[1]);
                    continue;
                }

                if (split[0].equals("ST")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement (ret, Name.stateOrProvinceName, n, split[1]);
                    } else {
                        ret.addStateOrProvinceName(split[1]);
                    }
                    //               System.out.println("ST found : " + split[1]);
                    continue;
                }

                if (split[0].equals("OU")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement (ret, Name.organizationalUnitName, n, split[1]);
                    } else {
                        ret.addOrganizationalUnitName(split[1]);
                    }
                    //              System.out.println("OU found : " + split[1]);
                    continue;
                }
            } catch (Exception e) {
                System.out.println("CRMFPopClient: Error constructing RDN: " + rdnStr + " Error: " + e.toString());

                continue;
            }

        }

        return ret;

    }
}
