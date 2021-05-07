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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.POPOPrivKey;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author alee
 *
 */
public class ConfigurationTest {

    public static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("ConfigurationTest", options);
        System.exit(1);
    }

    public static void main(String args[]) throws Exception {
        String host = null;
        String port = null;
        String cstype = null;
        String token_pwd = null;
        String db_dir = "./";
        String protocol = "https";
        String pin = null;
        String extCertFile = null;
        int testnum=1;

        // parse command line arguments
        Options options = new Options();
        options.addOption("t", true, "Subsystem type");
        options.addOption("h", true, "Hostname of the CS subsystem");
        options.addOption("p", true, "Port of the CS subsystem");
        options.addOption("w", true, "Token password");
        options.addOption("d", true, "Directory for tokendb");
        options.addOption("s", true, "preop pin");
        options.addOption("e", true, "File for externally signed signing cert");
        options.addOption("x", true, "Test number");

        try {
            CommandLineParser parser = new PosixParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("t")) {
                cstype = cmd.getOptionValue("t");
            } else {
                System.err.println("Error: no subsystem type provided.");
                usage(options);
            }

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
                pin = cmd.getOptionValue("s");
            }

            if (cmd.hasOption("e")) {
                extCertFile = cmd.getOptionValue("e");
            }

            if (cmd.hasOption("x")) {
                testnum = Integer.parseInt(cmd.getOptionValue("x"));
            }
        } catch (ParseException e) {
            System.err.println("Error in parsing command line options: " + e.getMessage());
            usage(options);
        }

     // Initialize token
        try {
            CryptoManager.initialize(db_dir);
        } catch (AlreadyInitializedException e) {
            // it is ok if it is already initialized
        } catch (Exception e) {
            System.out.println("INITIALIZATION ERROR: " + e.toString());
            System.exit(1);
        }

        // log into token
        CryptoManager manager = null;
        CryptoToken token = null;
        try {
            manager = CryptoManager.getInstance();
            token = manager.getInternalKeyStorageToken();
            Password password = new Password(token_pwd.toCharArray());
            try {
                token.login(password);
            } catch (Exception e) {
                System.out.println("login Exception: " + e.toString());
                if (!token.isLoggedIn()) {
                    token.initPassword(password, password);
                }
            } finally {
                password.clear();
            }
        } catch (Exception e) {
            System.out.println("Exception in logging into token:" + e.toString());
        }

        switch (testnum) {
        case 1:
            constructCAData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 2:
            constructCloneCAData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 3:
            constructKRAData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 4:
            constructOCSPData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 5:
            constructTKSData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 6:
            constructSubCAData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 7:
            constructExternalCADataPart1(host, port, pin, db_dir, token_pwd, token);
            break;
        case 8:
            constructExternalCADataPart2(host, port, pin, db_dir, token_pwd, token, extCertFile);
            break;
        default:
            System.out.println("Invalid test");
            System.exit(1);
        }
    }

    private static void constructCAData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("signing");
        cert1.setKeySize("2048");
        cert1.setNickname("signingCert testca");
        cert1.setSubjectDN("CN=CA Signing Certificate");
        cert1.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);

        systemCerts.add(cert1);

        SystemCertData cert2 = new SystemCertData();
        cert2.setTag("ocsp_signing");
        cert2.setKeySize("2048");
        cert2.setNickname("ocspSigningCert testca");
        cert2.setSubjectDN("CN= CA OCSP Signing Certificate");
        cert2.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert2);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeySize("2048");
        cert3.setNickname("sslServerCert testca");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeySize("2048");
        cert4.setNickname("subsystemCert testca");
        cert4.setSubjectDN("CN=CA Subsystem Certificate");
        cert4.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeySize("2048");
        cert5.setNickname("auditSigningCert testca");
        cert5.setSubjectDN("CN=CA Audit Signing Certificate");
        cert5.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert5);
    }

    private static void constructSubCAData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("signing");
        cert1.setKeySize("2048");
        cert1.setNickname("signingCert testsubca");
        cert1.setSubjectDN("CN=SubCA Signing Certificate");
        cert1.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);

        systemCerts.add(cert1);

        SystemCertData cert2 = new SystemCertData();
        cert2.setTag("ocsp_signing");
        cert2.setKeySize("2048");
        cert2.setNickname("ocspSigningCert testsubca");
        cert2.setSubjectDN("CN= SubCA OCSP Signing Certificate");
        cert2.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert2);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeySize("2048");
        cert3.setNickname("sslServerCert testsubca");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeySize("2048");
        cert4.setNickname("subsystemCert testsubca");
        cert4.setSubjectDN("CN=SubCA Subsystem Certificate");
        cert4.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeySize("2048");
        cert5.setNickname("auditSigningCert testsubca");
        cert5.setSubjectDN("CN=SubCA Audit Signing Certificate");
        cert5.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert5);
    }

    private static void constructExternalCADataPart1(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("signing");
        cert1.setKeySize("2048");
        cert1.setNickname("signingCert testexternalca");
        cert1.setSubjectDN("CN=External CA Signing Certificate");
        cert1.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);

        systemCerts.add(cert1);

        SystemCertData cert2 = new SystemCertData();
        cert2.setTag("ocsp_signing");
        cert2.setKeySize("2048");
        cert2.setNickname("ocspSigningCert testexternalca");
        cert2.setSubjectDN("CN= External CA OCSP Signing Certificate");
        cert2.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert2);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeySize("2048");
        cert3.setNickname("sslServerCert testexternalca");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeySize("2048");
        cert4.setNickname("subsystemCert testexternalca");
        cert4.setSubjectDN("CN=External CA Subsystem Certificate");
        cert4.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeySize("2048");
        cert5.setNickname("auditSigningCert testexternalca");
        cert5.setSubjectDN("CN=SubCA Audit Signing Certificate");
        cert5.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert5);
    }

    private static void constructExternalCADataPart2(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token, String extCertFile)
            throws NoSuchAlgorithmException, TokenException, IOException, InvalidBERException {

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("signing");
        cert1.setKeySize("2048");
        cert1.setNickname("signingCert testexternalca");
        cert1.setSubjectDN("CN=External CA Signing Certificate");
        cert1.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);

        String extCert = "";
        BufferedReader in = new BufferedReader(new FileReader(extCertFile));
        while (in.ready()) {
            extCert += in.readLine();
        }
        in.close();
        cert1.setCert(extCert);

        systemCerts.add(cert1);

        SystemCertData cert2 = new SystemCertData();
        cert2.setTag("ocsp_signing");
        cert2.setKeySize("2048");
        cert2.setNickname("ocspSigningCert testexternalca");
        cert2.setSubjectDN("CN= External CA OCSP Signing Certificate");
        cert2.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert2);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeySize("2048");
        cert3.setNickname("sslServerCert testexternalca");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeySize("2048");
        cert4.setNickname("subsystemCert testexternalca");
        cert4.setSubjectDN("CN=External CA Subsystem Certificate");
        cert4.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeySize("2048");
        cert5.setNickname("auditSigningCert testexternalca");
        cert5.setSubjectDN("CN=SubCA Audit Signing Certificate");
        cert5.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert5);
    }

    private static void constructCloneCAData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeySize("2048");
        cert3.setNickname("sslServerCert testca");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert3);
    }

    private static void constructKRAData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("transport");
        cert1.setKeySize("2048");
        cert1.setNickname("transportCert testkra");
        cert1.setSubjectDN("CN=KRA Transport Certificate");
        cert1.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);

        systemCerts.add(cert1);

        SystemCertData cert2 = new SystemCertData();
        cert2.setTag("storage");
        cert2.setKeySize("2048");
        cert2.setNickname("storageCert testkra");
        cert2.setSubjectDN("CN= KRA Storage Certificate");
        cert2.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert2);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeySize("2048");
        cert3.setNickname("sslServerCert testkra");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeySize("2048");
        cert4.setNickname("subsystemCert testkra");
        cert4.setSubjectDN("CN=KRA Subsystem Certificate");
        cert4.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeySize("2048");
        cert5.setNickname("auditSigningCert testkra");
        cert5.setSubjectDN("CN=KRA Audit Signing Certificate");
        cert5.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert5);
    }

    private static void constructOCSPData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("signing");
        cert1.setKeySize("2048");
        cert1.setNickname("ocspSigningCert testocsp");
        cert1.setSubjectDN("CN=OCSP Signing Certificate");
        cert1.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);

        systemCerts.add(cert1);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeySize("2048");
        cert3.setNickname("sslServerCert testocsp");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeySize("2048");
        cert4.setNickname("subsystemCert testocsp");
        cert4.setSubjectDN("CN=OCSP Subsystem Certificate");
        cert4.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeySize("2048");
        cert5.setNickname("auditSigningCert testocsp");
        cert5.setSubjectDN("CN=OCSP Audit Signing Certificate");
        cert5.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert5);
    }

    private static void constructTKSData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeySize("2048");
        cert3.setNickname("sslServerCert testtks");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeySize("2048");
        cert4.setNickname("subsystemCert testtks");
        cert4.setSubjectDN("CN=TKS Subsystem Certificate");
        cert4.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeySize("2048");
        cert5.setNickname("auditSigningCert testtks");
        cert5.setSubjectDN("CN=TKS Audit Signing Certificate");
        cert5.setToken(CryptoUtil.INTERNAL_TOKEN_FULL_NAME);
        systemCerts.add(cert5);
    }

    public static String generateCRMFRequest(CryptoToken token, String keysize, String subjectdn, boolean dualkey)
            throws NoSuchAlgorithmException, TokenException, IOException, InvalidBERException {
        KeyPairGenerator kg = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);

        Integer x = Integer.valueOf(keysize);
        int key_len = x.intValue();

        kg.initialize(key_len);

        // 1st key pair
        KeyPair pair = kg.genKeyPair();

        // create CRMF
        CertTemplate certTemplate = new CertTemplate();

        certTemplate.setVersion(new INTEGER(2));

        if (subjectdn != null) {
            X500Name name = new X500Name(subjectdn);
            ByteArrayInputStream cs = new ByteArrayInputStream(name.getEncoded());
            Name n = (Name) Name.getTemplate().decode(cs);
            certTemplate.setSubject(n);
        }

        certTemplate.setPublicKey(new SubjectPublicKeyInfo(pair.getPublic()));

        SEQUENCE seq = new SEQUENCE();
        CertRequest certReq = new CertRequest(new INTEGER(1), certTemplate,
                seq);
        byte popdata[] = { 0x0, 0x3, 0x0 };

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

        // BASE64Encoder encoder = new BASE64Encoder();
        // String Req1 = encoder.encodeBuffer(encoded);
        String Req1 = Utils.base64encode(encoded, true);
        return Req1;
    }
}
