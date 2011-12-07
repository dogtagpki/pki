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
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.PrintableString;
import org.mozilla.jss.asn1.SEQUENCE;
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

import com.netscape.cmsutil.util.HMACDigest;

/**
 * A command-line utility used to generate a Certificate Request Message Format
 * (CRMF) request with proof of possesion (POP).
 * 
 * Usage:
 * 
 * <pre>
 *     CRMFPopClient  TOKEN_PWD
 *                    PROFILE_NAME HOST PORT USER_NAME REQUESTOR_NAME
 *                    POP_OPTION
 *                    SUBJECT_DN [OUTPUT_CERT_REQ]
 * 
 *                    ---  or  ---
 * 
 *     CRMFPopClient  TOKEN_PWD
 *                    POP_OPTION
 *                    OUTPUT_CERT_REQ SUBJECT_DN
 * 
 * 
 *     where POP_OPTION can be [POP_SUCCESS or POP_FAIL or POP_NONE]
 * </pre>
 * <p>
 * Examples:
 * 
 * <pre>
 *     CRMFPopClient  password123
 *                    caEncUserCert host.example.com 1026 MyUid MyUid
 *                    [POP_SUCCESS or POP_FAIL or POP_NONE]
 *                    CN=MyTest,C=US,UID=MyUid
 * 
 *                    ---  or  ---
 * 
 *     CRMFPopClient  password123
 *                    caEncUserCert host.example.com 1026 joe joe
 *                    [POP_SUCCESS or POP_FAIL or POP_NONE]
 *                    CN=MyTest,C=US,UID=MyUid OUTPUT_CERT_REQ 
 * 
 *                    ---  or  ---
 * 
 *     CRMFPopClient  password123
 *                    [POP_SUCCESS or POP_FAIL or POP_NONE]
 *                    OUTPUT_CERT_REQ CN=MyTest,C=US,UID=MyUid
 * </pre>
 * <p>
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
        System.out.println("");
        System.out
                .println("Description:  A command-line utility used to generate a");
        System.out
                .println("              Certificate Request Message Format (CRMF)");
        System.out
                .println("              request with proof of possesion (POP).\n\n");
        System.out.println("Usage:");
        System.out.println("");
        System.out.println("    CRMFPopClient TOKEN_PWD");
        System.out
                .println("                  PROFILE_NAME HOST PORT USER_NAME REQUESTOR_NAME");
        System.out.println("                  POP_OPTION");
        System.out
                .println("                  SUBJECT_DN  [OUTPUT_CERT_REQ]   \n");
        System.out.println("                  ---  or  ---\n");
        System.out.println("    CRMFPopClient TOKEN_PWD");
        System.out.println("                  POP_OPTION");
        System.out.println("                  OUTPUT_CERT_REQ SUBJECT_DN\n\n");
        System.out
                .println("    where POP_OPTION can be [POP_SUCCESS or POP_FAIL or POP_NONE]\n\n");
        System.out.println("Examples:");
        System.out.println("");
        System.out.println("    CRMFPopClient password123");
        System.out
                .println("                  caEncUserCert host.example.com 1026 MyUid MyUid");
        System.out
                .println("                  [POP_SUCCESS or POP_FAIL or POP_NONE]");
        System.out.println("                  CN=MyTest,C=US,UID=MyUid\n");
        System.out.println("                  ---  or  ---\n");
        System.out.println("    CRMFPopClient password123");
        System.out
                .println("                  caEncUserCert host.example.com 1026 MyUid myUid");
        System.out
                .println("                  [POP_SUCCESS or POP_FAIL or POP_NONE]");
        System.out
                .println("                  CN=MyTest,C=US,UID=MyUid OUTPUT_CERT_REQ\n");
        System.out.println("                  ---  or  ---\n");
        System.out.println("    CRMFPopClient password123");
        System.out
                .println("                  [POP_SUCCESS or POP_FAIL or POP_NONE]");
        System.out
                .println("                  OUTPUT_CERT_REQ CN=MyTest,C=US,UID=MyUid");
        System.out.println("\n");
        System.out
                .println("IMPORTANT:  The file \"transport.txt\" needs to be created to contain the");
        System.out
                .println("            transport certificate in its base64 encoded format.  This");
        System.out
                .println("            file should consist of one line containing a single certificate");
        System.out
                .println("            in base64 encoded format with the header and footer removed.\n");
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

        // System.out.println("getRealArgsLength: returning " + finalLen);

        if (finalLen < 0)
            finalLen = 0;

        return finalLen;

    }

    public static void main(String args[]) {
        String USER_PREFIX = "user";

        int argsLen = getRealArgsLength(args);

        // System.out.println("args length " + argsLen);

        System.out.println("\n\nProof Of Possession Utility....");
        System.out.println("");

        if (argsLen == 0
                || (argsLen != 8 && argsLen != 9 && argsLen != 10 && argsLen != 4)) {
            usage();
            return;
        }

        String DB_DIR = "./";
        String TOKEN_PWD = args[0];
        int KEY_LEN = 1024;

        int PORT = 0;
        String USER_NAME = null;
        String REQUESTOR_NAME = null;
        String PROFILE_NAME = null;

        String HOST = null;
        String SUBJ_DN = null;

        if (argsLen >= 8) {
            PROFILE_NAME = args[1];
            HOST = args[2];

            PORT = Integer.parseInt(args[3]);

            USER_NAME = args[4];
            REQUESTOR_NAME = args[5];

            SUBJ_DN = args[7];

        }

        String POP_OPTION = null;
        String OUTPUT_CERT_REQ = null;

        if (argsLen == 4)
            POP_OPTION = args[1];
        else
            POP_OPTION = args[6];

        int doServerHit = 1;

        if (argsLen >= 9) {
            OUTPUT_CERT_REQ = args[8];
        }

        if (argsLen == 4) {
            doServerHit = 0;
            OUTPUT_CERT_REQ = args[2];
            SUBJ_DN = args[3];
        }

        int dont_do_pop = 0;

        if (POP_OPTION.equals("POP_NONE")) {
            dont_do_pop = 1;
        }

        URL url = null;
        URLConnection conn = null;
        InputStream is = null;
        BufferedReader reader = null;
        boolean success = false;
        int num = 1;
        long total_time = 0;
        KeyPair pair = null;

        boolean foundTransport = false;
        String transportCert = null;
        try {
            BufferedReader br = new BufferedReader(new FileReader(
                    "./transport.txt"));
            transportCert = br.readLine();
            foundTransport = true;
        } catch (Exception e) {
            System.out
                    .println("ERROR: cannot find ./transport.txt, so no key archival");

            return;
        }

        try {
            CryptoManager.initialize(DB_DIR);
        } catch (Exception e) {
            // it is ok if it is already initialized
            System.out.println("INITIALIZATION ERROR: " + e.toString());
            // return;
        }

        try {
            CryptoManager manager = CryptoManager.getInstance();
            String token_pwd = TOKEN_PWD;
            CryptoToken token = manager.getInternalKeyStorageToken();
            Password password = new Password(token_pwd.toCharArray());
            try {
                token.login(password);
            } catch (Exception e) {
                // System.out.println("login Exception: " + e.toString());
                if (!token.isLoggedIn()) {
                    token.initPassword(password, password);
                }
            }

            System.out.println("."); // "done with cryptomanager");

            KeyPairGenerator kg = token
                    .getKeyPairGenerator(KeyPairAlgorithm.RSA);
            kg.initialize(KEY_LEN);

            String profileName = PROFILE_NAME;
            pair = kg.genKeyPair();

            System.out.println("."); // key pair generated");

            // wrap private key
            byte transport[] = com.netscape.osutil.OSUtil.AtoB(transportCert);

            X509Certificate tcert = manager.importCACertPackage(transport);

            byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };

            KeyGenerator kg1 = token.getKeyGenerator(KeyGenAlgorithm.DES3);
            SymmetricKey sk = kg1.generate();

            System.out.println("."); // before KeyWrapper");

            // wrap private key using session
            KeyWrapper wrapper1 = token
                    .getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);

            System.out.println("."); // key wrapper created");

            wrapper1.initWrap(sk, new IVParameterSpec(iv));

            System.out.println("."); // key wrapper inited");
            byte key_data[] = wrapper1
                    .wrap((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate());

            System.out.println("."); // key wrapper wrapped");

            // wrap session using transport
            KeyWrapper rsaWrap = token.getKeyWrapper(KeyWrapAlgorithm.RSA);

            System.out.println("."); // got rsaWrapper");

            rsaWrap.initWrap(tcert.getPublicKey(), null);

            System.out.println("."); // rsaWrap inited");

            byte session_data[] = rsaWrap.wrap(sk);

            System.out.println("."); // rsaWrapped");

            try {
                // create CRMF
                CertTemplate certTemplate = new CertTemplate();
                certTemplate.setVersion(new INTEGER(2));

                Name n1 = getJssName(SUBJ_DN);

                Name n = new Name();

                n.addCommonName("Me");
                n.addCountryName("US");
                n.addElement(new AVA(new OBJECT_IDENTIFIER(
                        "0.9.2342.19200300.100.1.1"), new PrintableString(
                        "MyUid")));

                if (n1 != null)
                    certTemplate.setSubject(n1);
                else
                    certTemplate.setSubject(n);

                certTemplate.setPublicKey(new SubjectPublicKeyInfo(pair
                        .getPublic()));
                // set extension
                AlgorithmIdentifier algS = new AlgorithmIdentifier(
                        new OBJECT_IDENTIFIER("1.2.840.113549.3.7"),
                        new OCTET_STRING(iv));
                EncryptedValue encValue = new EncryptedValue(null, algS,
                        new BIT_STRING(session_data, 0), null, null,
                        new BIT_STRING(key_data, 0));
                EncryptedKey key = new EncryptedKey(encValue);
                PKIArchiveOptions opt = new PKIArchiveOptions(key);
                SEQUENCE seq = new SEQUENCE();
                if (foundTransport) {
                    seq.addElement(new AVA(new OBJECT_IDENTIFIER(
                            "1.3.6.1.5.5.7.5.1.4"), opt));
                }

                // Add idPOPLinkWitness control
                String secretValue = "testing";
                byte[] key1 = null;
                byte[] finalDigest = null;
                try {
                    MessageDigest SHA1Digest = MessageDigest
                            .getInstance("SHA1");
                    key1 = SHA1Digest.digest(secretValue.getBytes());
                } catch (NoSuchAlgorithmException ex) {
                }

                /* Example of adding the POP link witness control to CRMF */
                byte[] b = { 0x10, 0x53, 0x42, 0x24, 0x1a, 0x2a, 0x35, 0x3c,
                        0x7a, 0x52, 0x54, 0x56, 0x71, 0x65, 0x66, 0x4c, 0x51,
                        0x34, 0x35, 0x23, 0x3c, 0x42, 0x43, 0x45, 0x61, 0x4f,
                        0x6e, 0x43, 0x1e, 0x2a, 0x2b, 0x31, 0x32, 0x34, 0x35,
                        0x36, 0x55, 0x51, 0x48, 0x14, 0x16, 0x29, 0x41, 0x42,
                        0x43, 0x7b, 0x63, 0x44, 0x6a, 0x12, 0x6b, 0x3c, 0x4c,
                        0x3f, 0x00, 0x14, 0x51, 0x61, 0x15, 0x22, 0x23, 0x5f,
                        0x5e, 0x69 };

                try {
                    MessageDigest SHA1Digest = MessageDigest
                            .getInstance("SHA1");
                    HMACDigest hmacDigest = new HMACDigest(SHA1Digest, key1);
                    hmacDigest.update(b);
                    finalDigest = hmacDigest.digest();
                } catch (NoSuchAlgorithmException ex) {
                }

                OCTET_STRING ostr = new OCTET_STRING(finalDigest);
                seq.addElement(new AVA(
                        OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness, ostr));
                CertRequest certReq = new CertRequest(new INTEGER(1),
                        certTemplate, seq);

                System.out.println("."); // CertRequest created");

                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                certReq.encode(bo);
                byte[] toBeVerified = bo.toByteArray();

                byte popdata[] = ASN1Util.encode(certReq);
                byte signature[];

                System.out.println("."); // CertRequest encoded");

                Signature signer = token
                        .getSignatureContext(SignatureAlgorithm.RSASignatureWithMD5Digest);

                System.out.println("."); // signer created");

                signer.initSign((org.mozilla.jss.crypto.PrivateKey) pair
                        .getPrivate());

                System.out.println("."); // signer inited");

                System.out.println("."); // FAIL_OR_SUCC " + FAIL_OR_SUCC);

                if (POP_OPTION.equals("POP_SUCCESS")) {
                    System.out.println("Generating Legal POP Data.....");
                    signer.update(toBeVerified);
                } else if (POP_OPTION.equals("POP_FAIL")) {
                    System.out.println("Generating Illegal POP Data.....");
                    signer.update(iv);
                } else if (dont_do_pop == 1) {
                    System.out.println("Generating NO POP Data.....");
                }

                System.out.println("."); // signer updated");

                CertReqMsg crmfMsg = null;

                if (dont_do_pop == 0) {
                    signature = signer.sign();

                    System.out.println("Signature completed...");
                    System.out.println("");

                    AlgorithmIdentifier algID = new AlgorithmIdentifier(
                            SignatureAlgorithm.RSASignatureWithMD5Digest
                                    .toOID(),
                            null);
                    POPOSigningKey popoKey = new POPOSigningKey(null, algID,
                            new BIT_STRING(signature, 0));

                    ProofOfPossession pop = ProofOfPossession
                            .createSignature(popoKey);

                    crmfMsg = new CertReqMsg(certReq, pop, null);

                } else {
                    crmfMsg = new CertReqMsg(certReq, null, null);

                }

                // crmfMsg.verify();

                SEQUENCE s1 = new SEQUENCE();
                s1.addElement(crmfMsg);
                byte encoded[] = ASN1Util.encode(s1);

                String Req1 = com.netscape.osutil.OSUtil.BtoA(encoded);

                if (OUTPUT_CERT_REQ != null) {
                    System.out.println("Generated Cert Request: ...... ");
                    System.out.println("");

                    System.out.println(Req1);
                    System.out.println("");
                    System.out.println("End Request:");

                    if (doServerHit == 0)
                        return;
                }

                String Req = URLEncoder.encode(Req1);

                // post PKCS10

                url = new URL(
                        "http://"
                                + HOST
                                + ":"
                                + PORT
                                + "/ca/ee/ca/profileSubmit?cert_request_type=crmf&cert_request="
                                + Req + "&renewal=false&uid=" + USER_NAME
                                + "&xmlOutput=false&&profileId=" + profileName
                                + "&sn_uid=" + USER_NAME
                                + "&SubId=profile&requestor_name="
                                + REQUESTOR_NAME);
                // System.out.println("Posting " + url);

                System.out.println("");
                System.out.println("Server Response.....");
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
                        System.out.println("Enrollment Successful: ......");
                        System.out.println("");
                    }
                } /* while */
                long end_time = (new Date()).getTime();
                total_time += (end_time - start_time);
            } catch (Exception e) {
                System.out.println("WARNING: " + e.toString());
                e.printStackTrace();
            }
        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            e.printStackTrace();
        }
    }

    static Name getJssName(String dn) {

        X500Name x5Name = null;

        try {
            x5Name = new X500Name(dn);

        } catch (IOException e) {

            System.out.println("Illegal Subject Name:  " + dn + " Error: "
                    + e.toString());
            System.out.println("Filling in default Subject Name......");
            return null;
        }

        Name ret = new Name();

        netscape.security.x509.RDN[] names = null;

        names = x5Name.getNames();

        int nameLen = x5Name.getNamesLength();

        // System.out.println("x5Name len: " + nameLen);

        netscape.security.x509.RDN cur = null;

        for (int i = 0; i < nameLen; i++) {
            cur = names[i];

            String rdnStr = cur.toString();

            String[] split = rdnStr.split("=");

            if (split.length != 2)
                continue;

            try {

                if (split[0].equals("UID")) {

                    ret.addElement(new AVA(new OBJECT_IDENTIFIER(
                            "0.9.2342.19200300.100.1.1"), new PrintableString(
                            split[1])));
                    // System.out.println("UID found : " + split[1]);

                }

                if (split[0].equals("C")) {
                    ret.addCountryName(split[1]);
                    // System.out.println("C found : " + split[1]);
                    continue;

                }

                if (split[0].equals("CN")) {
                    ret.addCommonName(split[1]);
                    // System.out.println("CN found : " + split[1]);
                    continue;
                }

                if (split[0].equals("L")) {
                    ret.addLocalityName(split[1]);
                    // System.out.println("L found : " + split[1]);
                    continue;
                }

                if (split[0].equals("O")) {
                    ret.addOrganizationName(split[1]);
                    // System.out.println("O found : " + split[1]);
                    continue;
                }

                if (split[0].equals("ST")) {
                    ret.addStateOrProvinceName(split[1]);
                    // System.out.println("ST found : " + split[1]);
                    continue;
                }

                if (split[0].equals("OU")) {
                    ret.addOrganizationalUnitName(split[1]);
                    // System.out.println("OU found : " + split[1]);
                    continue;
                }
            } catch (Exception e) {
                System.out.println("Error constructing RDN: " + rdnStr
                        + " Error: " + e.toString());

                continue;
            }

        }

        return ret;

    }
}
