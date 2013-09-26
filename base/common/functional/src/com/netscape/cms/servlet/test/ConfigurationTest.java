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
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import netscape.security.x509.X500Name;

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
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.POPOPrivKey;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.ConfigurationResponse;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.certsrv.system.SystemConfigClient;
import com.netscape.cmsutil.util.Utils;

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

    public static void main(String args[]) throws NoSuchAlgorithmException, TokenException, IOException, InvalidBERException {
        String host = null;
        String port = null;
        String cstype = null;
        String token_pwd = null;
        String db_dir = "./";
        String protocol = "https";
        String pin = null;
        String extCertFile = null;
        String extChainFile = null;
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
        options.addOption("g", true, "File for external CA cert chain");
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

            if (cmd.hasOption("g")) {
                extChainFile = cmd.getOptionValue("g");
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
            }
        } catch (Exception e) {
            System.out.println("Exception in logging into token:" + e.toString());
        }

        SystemConfigClient client = null;
        try {
            ClientConfig config = new ClientConfig();
            config.setServerURI(protocol + "://" + host + ":" + port);

            client = new SystemConfigClient(new PKIClient(config), cstype);
        } catch (URISyntaxException e1) {
            e1.printStackTrace();
            System.exit(1);
        }

        ConfigurationRequest data = null;
        switch (testnum) {
        case 1:
            data = constructCAData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 2:
            data = constructCloneCAData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 3:
            data = constructKRAData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 4:
            data = constructOCSPData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 5:
            data = constructTKSData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 6:
            data = constructSubCAData(host, port, pin, db_dir, token_pwd, token);
            break;
        case 7:
            data = constructExternalCADataPart1(host, port, pin, db_dir, token_pwd, token);
            break;
        case 8:
            data = constructExternalCADataPart2(host, port, pin, db_dir, token_pwd, token, extCertFile, extChainFile);
            break;
        default:
            System.out.println("Invalid test");
            System.exit(1);
        }

        ConfigurationResponse response = client.configure(data);

        System.out.println("status: " + response.getStatus());
        System.out.println("adminCert: " + response.getAdminCert().getCert());
        List<SystemCertData> certs = response.getSystemCerts();
        Iterator<SystemCertData> iterator = certs.iterator();
        while (iterator.hasNext()) {
            SystemCertData cdata = iterator.next();
            System.out.println("tag: " + cdata.getTag());
            System.out.println("cert: " + cdata.getCert());
            System.out.println("request: " + cdata.getRequest());
        }

    }

    private static ConfigurationRequest constructCAData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {
        ConfigurationRequest data = new ConfigurationRequest();
        data.setPin(pin);
        data.setSecurityDomainType(ConfigurationRequest.NEW_DOMAIN);
        data.setSecurityDomainName("Testca2 security domain");
        data.setIsClone("false");
        data.setHierarchy("root");
        data.setToken(ConfigurationRequest.TOKEN_DEFAULT);
        data.setSubsystemName("test ca subsystem");

        data.setDsHost(host);
        data.setDsPort("7389");
        data.setBaseDN("o=testca2");
        data.setBindDN("cn=Directory Manager");
        data.setDatabase("o=testca2");
        data.setBindpwd("redhat123");
        data.setRemoveData("true");
        data.setSecureConn("false");

        data.setBackupKeys("true");
        data.setBackupFile("/tmp/testca.p12");
        data.setBackupPassword("redhat123");

        data.setAdminEmail("alee@redhat.com");
        data.setAdminName("admin");
        data.setAdminPassword("redhat123");
        data.setAdminProfileID("caAdminCert");
        data.setAdminUID("admin");
        String subjectdn = "CN=CA Administrator of Instance testca, UID=admin, E=alee@redhat.com, o=testca2";
        data.setAdminSubjectDN(subjectdn);

        String crmf_request = generateCRMFRequest(token, "2048", subjectdn, false);
        data.setAdminCertRequest(crmf_request);
        data.setAdminCertRequestType("crmf");

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("signing");
        cert1.setKeyAlgorithm("SHA256withRSA");
        cert1.setKeySize("2048");
        cert1.setKeyType("rsa");
        cert1.setNickname("signingCert testca");
        cert1.setSigningAlgorithm("SHA256withRSA");
        cert1.setSubjectDN("CN=CA Signing Certificate");
        cert1.setToken("Internal Key Storage Token");

        systemCerts.add(cert1);

        SystemCertData cert2 = new SystemCertData();
        cert2.setTag("ocsp_signing");
        cert2.setKeyAlgorithm("SHA256withRSA");
        cert2.setKeySize("2048");
        cert2.setKeyType("rsa");
        cert2.setNickname("ocspSigningCert testca");
        cert2.setSigningAlgorithm("SHA256withRSA");
        cert2.setSubjectDN("CN= CA OCSP Signing Certificate");
        cert2.setToken("Internal Key Storage Token");
        systemCerts.add(cert2);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeyAlgorithm("SHA256withRSA");
        cert3.setKeySize("2048");
        cert3.setKeyType("rsa");
        cert3.setNickname("sslServerCert testca");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken("Internal Key Storage Token");
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeyAlgorithm("SHA256withRSA");
        cert4.setKeySize("2048");
        cert4.setKeyType("rsa");
        cert4.setNickname("subsystemCert testca");
        cert4.setSubjectDN("CN=CA Subsystem Certificate");
        cert4.setToken("Internal Key Storage Token");
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeyAlgorithm("SHA256withRSA");
        cert5.setKeySize("2048");
        cert5.setKeyType("rsa");
        cert5.setNickname("auditSigningCert testca");
        cert5.setSigningAlgorithm("SHA256withRSA");
        cert5.setSubjectDN("CN=CA Audit Signing Certificate");
        cert5.setToken("Internal Key Storage Token");
        systemCerts.add(cert5);

        data.setSystemCerts(systemCerts);

        return data;
    }

    private static ConfigurationRequest constructSubCAData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {
        ConfigurationRequest data = new ConfigurationRequest();
        data.setPin(pin);

        data.setSecurityDomainType(ConfigurationRequest.EXISTING_DOMAIN);
        data.setSecurityDomainUri("https://" + host + ":9225");
        data.setSecurityDomainUser("admin");
        data.setSecurityDomainPassword("redhat123");

        data.setIsClone("false");
        data.setHierarchy("join");
        data.setToken(ConfigurationRequest.TOKEN_DEFAULT);
        data.setSubsystemName("test subca subsystem");

        data.setDsHost(host);
        data.setDsPort("7389");
        data.setBaseDN("o=testsubca");
        data.setBindDN("cn=Directory Manager");
        data.setDatabase("o=testsubca");
        data.setBindpwd("redhat123");
        data.setRemoveData("true");
        data.setSecureConn("false");

        data.setBackupKeys("true");
        data.setBackupFile("/tmp/testsubca.p12");
        data.setBackupPassword("redhat123");

        data.setAdminEmail("alee@redhat.com");
        data.setAdminName("admin");
        data.setAdminPassword("redhat123");
        data.setAdminProfileID("caAdminCert");
        data.setAdminUID("admin");
        String subjectdn = "CN=CA Administrator of Instance testsubca, UID=admin, E=alee@redhat.com, o=testsubca";
        data.setAdminSubjectDN(subjectdn);

        String crmf_request = generateCRMFRequest(token, "2048", subjectdn, false);
        data.setAdminCertRequest(crmf_request);
        data.setAdminCertRequestType("crmf");

        data.setIssuingCA("https://" + host + ":9224");

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("signing");
        cert1.setKeyAlgorithm("SHA256withRSA");
        cert1.setKeySize("2048");
        cert1.setKeyType("rsa");
        cert1.setNickname("signingCert testsubca");
        cert1.setSigningAlgorithm("SHA256withRSA");
        cert1.setSubjectDN("CN=SubCA Signing Certificate");
        cert1.setToken("Internal Key Storage Token");

        systemCerts.add(cert1);

        SystemCertData cert2 = new SystemCertData();
        cert2.setTag("ocsp_signing");
        cert2.setKeyAlgorithm("SHA256withRSA");
        cert2.setKeySize("2048");
        cert2.setKeyType("rsa");
        cert2.setNickname("ocspSigningCert testsubca");
        cert2.setSigningAlgorithm("SHA256withRSA");
        cert2.setSubjectDN("CN= SubCA OCSP Signing Certificate");
        cert2.setToken("Internal Key Storage Token");
        systemCerts.add(cert2);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeyAlgorithm("SHA256withRSA");
        cert3.setKeySize("2048");
        cert3.setKeyType("rsa");
        cert3.setNickname("sslServerCert testsubca");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken("Internal Key Storage Token");
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeyAlgorithm("SHA256withRSA");
        cert4.setKeySize("2048");
        cert4.setKeyType("rsa");
        cert4.setNickname("subsystemCert testsubca");
        cert4.setSubjectDN("CN=SubCA Subsystem Certificate");
        cert4.setToken("Internal Key Storage Token");
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeyAlgorithm("SHA256withRSA");
        cert5.setKeySize("2048");
        cert5.setKeyType("rsa");
        cert5.setNickname("auditSigningCert testsubca");
        cert5.setSigningAlgorithm("SHA256withRSA");
        cert5.setSubjectDN("CN=SubCA Audit Signing Certificate");
        cert5.setToken("Internal Key Storage Token");
        systemCerts.add(cert5);

        data.setSystemCerts(systemCerts);

        return data;
    }

    private static ConfigurationRequest constructExternalCADataPart1(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {
        ConfigurationRequest data = new ConfigurationRequest();
        data.setPin(pin);

        data.setSecurityDomainType(ConfigurationRequest.NEW_DOMAIN);
        data.setSecurityDomainName("External CA security domain");

        data.setIsClone("false");
        data.setHierarchy("join");
        data.setToken(ConfigurationRequest.TOKEN_DEFAULT);
        data.setSubsystemName("test external ca subsystem");

        data.setDsHost(host);
        data.setDsPort("7389");
        data.setBaseDN("o=testexternalca");
        data.setBindDN("cn=Directory Manager");
        data.setDatabase("o=testexternalca");
        data.setBindpwd("redhat123");
        data.setRemoveData("true");
        data.setSecureConn("false");

        data.setBackupKeys("true");
        data.setBackupFile("/tmp/testexternalca.p12");
        data.setBackupPassword("redhat123");

        data.setAdminEmail("alee@redhat.com");
        data.setAdminName("admin");
        data.setAdminPassword("redhat123");
        data.setAdminProfileID("caAdminCert");
        data.setAdminUID("admin");
        String subjectdn = "CN=CA Administrator of Instance testexternalca, UID=admin, E=alee@redhat.com, o=testexternalca";
        data.setAdminSubjectDN(subjectdn);

        String crmf_request = generateCRMFRequest(token, "2048", subjectdn, false);
        data.setAdminCertRequest(crmf_request);
        data.setAdminCertRequestType("crmf");

        data.setIssuingCA("External CA");

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("signing");
        cert1.setKeyAlgorithm("SHA256withRSA");
        cert1.setKeySize("2048");
        cert1.setKeyType("rsa");
        cert1.setNickname("signingCert testexternalca");
        cert1.setSigningAlgorithm("SHA256withRSA");
        cert1.setSubjectDN("CN=External CA Signing Certificate");
        cert1.setToken("Internal Key Storage Token");

        systemCerts.add(cert1);

        SystemCertData cert2 = new SystemCertData();
        cert2.setTag("ocsp_signing");
        cert2.setKeyAlgorithm("SHA256withRSA");
        cert2.setKeySize("2048");
        cert2.setKeyType("rsa");
        cert2.setNickname("ocspSigningCert testexternalca");
        cert2.setSigningAlgorithm("SHA256withRSA");
        cert2.setSubjectDN("CN= External CA OCSP Signing Certificate");
        cert2.setToken("Internal Key Storage Token");
        systemCerts.add(cert2);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeyAlgorithm("SHA256withRSA");
        cert3.setKeySize("2048");
        cert3.setKeyType("rsa");
        cert3.setNickname("sslServerCert testexternalca");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken("Internal Key Storage Token");
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeyAlgorithm("SHA256withRSA");
        cert4.setKeySize("2048");
        cert4.setKeyType("rsa");
        cert4.setNickname("subsystemCert testexternalca");
        cert4.setSubjectDN("CN=External CA Subsystem Certificate");
        cert4.setToken("Internal Key Storage Token");
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeyAlgorithm("SHA256withRSA");
        cert5.setKeySize("2048");
        cert5.setKeyType("rsa");
        cert5.setNickname("auditSigningCert testexternalca");
        cert5.setSigningAlgorithm("SHA256withRSA");
        cert5.setSubjectDN("CN=SubCA Audit Signing Certificate");
        cert5.setToken("Internal Key Storage Token");
        systemCerts.add(cert5);

        data.setSystemCerts(systemCerts);

        return data;
    }

    private static ConfigurationRequest constructExternalCADataPart2(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token, String extCertFile, String extChainFile)
            throws NoSuchAlgorithmException, TokenException, IOException, InvalidBERException {
        ConfigurationRequest data = new ConfigurationRequest();
        data.setPin(pin);

        data.setSecurityDomainType(ConfigurationRequest.NEW_DOMAIN);
        data.setSecurityDomainName("External CA security domain");

        data.setIsClone("false");
        data.setHierarchy("join");
        data.setToken(ConfigurationRequest.TOKEN_DEFAULT);
        data.setSubsystemName("test external ca subsystem");

        data.setDsHost(host);
        data.setDsPort("7389");
        data.setBaseDN("o=testexternalca");
        data.setBindDN("cn=Directory Manager");
        data.setDatabase("o=testexternalca");
        data.setBindpwd("redhat123");
        data.setRemoveData("true");
        data.setSecureConn("false");

        data.setBackupKeys("true");
        data.setBackupFile("/tmp/testexternalca.p12");
        data.setBackupPassword("redhat123");

        data.setAdminEmail("alee@redhat.com");
        data.setAdminName("admin");
        data.setAdminPassword("redhat123");
        data.setAdminProfileID("caAdminCert");
        data.setAdminUID("admin");
        String subjectdn = "CN=CA Administrator of Instance testexternalca, UID=admin, E=alee@redhat.com, o=testexternalca";
        data.setAdminSubjectDN(subjectdn);

        String crmf_request = generateCRMFRequest(token, "2048", subjectdn, false);
        data.setAdminCertRequest(crmf_request);
        data.setAdminCertRequestType("crmf");

        data.setIssuingCA("External CA");
        data.setStepTwo("true");

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("signing");
        cert1.setKeyAlgorithm("SHA256withRSA");
        cert1.setKeySize("2048");
        cert1.setKeyType("rsa");
        cert1.setNickname("signingCert testexternalca");
        cert1.setSigningAlgorithm("SHA256withRSA");
        cert1.setSubjectDN("CN=External CA Signing Certificate");
        cert1.setToken("Internal Key Storage Token");

        String extCert = "";
        BufferedReader in = new BufferedReader(new FileReader(extCertFile));
        while (in.ready()) {
            extCert += in.readLine();
        }
        in.close();
        cert1.setCert(extCert);

        String extCertChain = "";
        in = new BufferedReader(new FileReader(extChainFile));
        while (in.ready()) {
            extCertChain += in.readLine();
        }
        in.close();
        cert1.setCertChain(extCertChain);

        systemCerts.add(cert1);

        SystemCertData cert2 = new SystemCertData();
        cert2.setTag("ocsp_signing");
        cert2.setKeyAlgorithm("SHA256withRSA");
        cert2.setKeySize("2048");
        cert2.setKeyType("rsa");
        cert2.setNickname("ocspSigningCert testexternalca");
        cert2.setSigningAlgorithm("SHA256withRSA");
        cert2.setSubjectDN("CN= External CA OCSP Signing Certificate");
        cert2.setToken("Internal Key Storage Token");
        systemCerts.add(cert2);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeyAlgorithm("SHA256withRSA");
        cert3.setKeySize("2048");
        cert3.setKeyType("rsa");
        cert3.setNickname("sslServerCert testexternalca");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken("Internal Key Storage Token");
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeyAlgorithm("SHA256withRSA");
        cert4.setKeySize("2048");
        cert4.setKeyType("rsa");
        cert4.setNickname("subsystemCert testexternalca");
        cert4.setSubjectDN("CN=External CA Subsystem Certificate");
        cert4.setToken("Internal Key Storage Token");
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeyAlgorithm("SHA256withRSA");
        cert5.setKeySize("2048");
        cert5.setKeyType("rsa");
        cert5.setNickname("auditSigningCert testexternalca");
        cert5.setSigningAlgorithm("SHA256withRSA");
        cert5.setSubjectDN("CN=SubCA Audit Signing Certificate");
        cert5.setToken("Internal Key Storage Token");
        systemCerts.add(cert5);

        data.setSystemCerts(systemCerts);

        return data;
    }

    private static ConfigurationRequest constructCloneCAData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {
        ConfigurationRequest data = new ConfigurationRequest();
        data.setPin(pin);
        data.setSecurityDomainType(ConfigurationRequest.EXISTING_DOMAIN);
        data.setSecurityDomainUri("https://" + host + ":9225");
        data.setSecurityDomainUser("admin");
        data.setSecurityDomainPassword("redhat123");

        data.setIsClone("true");
        data.setCloneUri("https://" + host + ":9224" );
        data.setP12File("master.p12");
        data.setP12Password("redhat123");

        data.setHierarchy("root");
        data.setToken(ConfigurationRequest.TOKEN_DEFAULT);
        data.setSubsystemName("test clone ca subsystem");

        data.setDsHost(host);
        data.setDsPort("7494");
        data.setBaseDN("o=testca2");
        data.setBindDN("cn=Directory Manager");
        data.setDatabase("o=testca2");
        data.setBindpwd("redhat123");
        data.setRemoveData("true");
        data.setSecureConn("false");

        data.setBackupKeys("false");

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeyAlgorithm("SHA256withRSA");
        cert3.setKeySize("2048");
        cert3.setKeyType("rsa");
        cert3.setNickname("sslServerCert testca");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken("Internal Key Storage Token");
        systemCerts.add(cert3);

        data.setSystemCerts(systemCerts);

        return data;
    }

    private static ConfigurationRequest constructKRAData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {
        ConfigurationRequest data = new ConfigurationRequest();
        data.setPin(pin);

        data.setSecurityDomainType(ConfigurationRequest.EXISTING_DOMAIN);
        data.setSecurityDomainUri("https://" + host + ":9225");
        data.setSecurityDomainUser("admin");
        data.setSecurityDomainPassword("redhat123");

        data.setIsClone("false");
        data.setToken(ConfigurationRequest.TOKEN_DEFAULT);
        data.setSubsystemName("test kra subsystem");

        data.setDsHost(host);
        data.setDsPort("7389");
        data.setBaseDN("o=testkra22");
        data.setBindDN("cn=Directory Manager");
        data.setDatabase("o=testkra");
        data.setBindpwd("redhat123");
        data.setRemoveData("true");
        data.setSecureConn("false");

        data.setBackupKeys("true");
        data.setBackupFile("/tmp/testkra.p12");
        data.setBackupPassword("redhat123");

        data.setAdminEmail("alee@redhat.com");
        data.setAdminName("admin");
        data.setAdminPassword("redhat123");
        data.setAdminProfileID("caAdminCert");
        data.setAdminUID("admin");
        String subjectdn = "CN=KRA Administrator of Instance testkra, UID=admin, E=alee@redhat.com, o=testkra22";
        data.setAdminSubjectDN(subjectdn);

        String crmf_request = generateCRMFRequest(token, "2048", subjectdn, false);
        data.setAdminCertRequest(crmf_request);
        data.setAdminCertRequestType("crmf");

        data.setIssuingCA("https://" + host + ":9224");

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("transport");
        cert1.setKeyAlgorithm("SHA256withRSA");
        cert1.setKeySize("2048");
        cert1.setKeyType("rsa");
        cert1.setNickname("transportCert testkra");
        cert1.setSigningAlgorithm("SHA256withRSA");
        cert1.setSubjectDN("CN=KRA Transport Certificate");
        cert1.setToken("Internal Key Storage Token");

        systemCerts.add(cert1);

        SystemCertData cert2 = new SystemCertData();
        cert2.setTag("storage");
        cert2.setKeyAlgorithm("SHA256withRSA");
        cert2.setKeySize("2048");
        cert2.setKeyType("rsa");
        cert2.setNickname("storageCert testkra");
        cert2.setSigningAlgorithm("SHA256withRSA");
        cert2.setSubjectDN("CN= KRA Storage Certificate");
        cert2.setToken("Internal Key Storage Token");
        systemCerts.add(cert2);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeyAlgorithm("SHA256withRSA");
        cert3.setKeySize("2048");
        cert3.setKeyType("rsa");
        cert3.setNickname("sslServerCert testkra");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken("Internal Key Storage Token");
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeyAlgorithm("SHA256withRSA");
        cert4.setKeySize("2048");
        cert4.setKeyType("rsa");
        cert4.setNickname("subsystemCert testkra");
        cert4.setSubjectDN("CN=KRA Subsystem Certificate");
        cert4.setToken("Internal Key Storage Token");
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeyAlgorithm("SHA256withRSA");
        cert5.setKeySize("2048");
        cert5.setKeyType("rsa");
        cert5.setNickname("auditSigningCert testkra");
        cert5.setSigningAlgorithm("SHA256withRSA");
        cert5.setSubjectDN("CN=KRA Audit Signing Certificate");
        cert5.setToken("Internal Key Storage Token");
        systemCerts.add(cert5);

        data.setSystemCerts(systemCerts);

        return data;
    }

    private static ConfigurationRequest constructOCSPData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {
        ConfigurationRequest data = new ConfigurationRequest();
        data.setPin(pin);

        data.setSecurityDomainType(ConfigurationRequest.EXISTING_DOMAIN);
        data.setSecurityDomainUri("https://" + host + ":9225");
        data.setSecurityDomainUser("admin");
        data.setSecurityDomainPassword("redhat123");

        data.setIsClone("false");
        data.setToken(ConfigurationRequest.TOKEN_DEFAULT);
        data.setSubsystemName("test ocsp subsystem");

        data.setDsHost(host);
        data.setDsPort("7389");
        data.setBaseDN("o=testocsp22");
        data.setBindDN("cn=Directory Manager");
        data.setDatabase("o=testocsp22");
        data.setBindpwd("redhat123");
        data.setRemoveData("true");
        data.setSecureConn("false");

        data.setBackupKeys("true");
        data.setBackupFile("/tmp/testocsp.p12");
        data.setBackupPassword("redhat123");

        data.setAdminEmail("alee@redhat.com");
        data.setAdminName("admin");
        data.setAdminPassword("redhat123");
        data.setAdminProfileID("caAdminCert");
        data.setAdminUID("admin");
        String subjectdn = "CN=OCSP Administrator of Instance testocsp, UID=admin, E=alee@redhat.com, o=testocsp22";
        data.setAdminSubjectDN(subjectdn);

        String crmf_request = generateCRMFRequest(token, "2048", subjectdn, false);
        data.setAdminCertRequest(crmf_request);
        data.setAdminCertRequestType("crmf");

        data.setIssuingCA("https://" + host + ":9224");

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();
        SystemCertData cert1 = new SystemCertData();
        cert1.setTag("signing");
        cert1.setKeyAlgorithm("SHA256withRSA");
        cert1.setKeySize("2048");
        cert1.setKeyType("rsa");
        cert1.setNickname("ocspSigningCert testocsp");
        cert1.setSigningAlgorithm("SHA256withRSA");
        cert1.setSubjectDN("CN=OCSP Signing Certificate");
        cert1.setToken("Internal Key Storage Token");

        systemCerts.add(cert1);

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeyAlgorithm("SHA256withRSA");
        cert3.setKeySize("2048");
        cert3.setKeyType("rsa");
        cert3.setNickname("sslServerCert testocsp");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken("Internal Key Storage Token");
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeyAlgorithm("SHA256withRSA");
        cert4.setKeySize("2048");
        cert4.setKeyType("rsa");
        cert4.setNickname("subsystemCert testocsp");
        cert4.setSubjectDN("CN=OCSP Subsystem Certificate");
        cert4.setToken("Internal Key Storage Token");
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeyAlgorithm("SHA256withRSA");
        cert5.setKeySize("2048");
        cert5.setKeyType("rsa");
        cert5.setNickname("auditSigningCert testocsp");
        cert5.setSigningAlgorithm("SHA256withRSA");
        cert5.setSubjectDN("CN=OCSP Audit Signing Certificate");
        cert5.setToken("Internal Key Storage Token");
        systemCerts.add(cert5);

        data.setSystemCerts(systemCerts);

        return data;
    }

    private static ConfigurationRequest constructTKSData(String host, String port, String pin, String db_dir,
            String token_pwd, CryptoToken token) throws NoSuchAlgorithmException, TokenException, IOException,
            InvalidBERException {
        ConfigurationRequest data = new ConfigurationRequest();
        data.setPin(pin);

        data.setSecurityDomainType(ConfigurationRequest.EXISTING_DOMAIN);
        data.setSecurityDomainUri("https://" + host + ":9225");
        data.setSecurityDomainUser("admin");
        data.setSecurityDomainPassword("redhat123");

        data.setIsClone("false");
        data.setToken(ConfigurationRequest.TOKEN_DEFAULT);
        data.setSubsystemName("test tks subsystem");

        data.setDsHost(host);
        data.setDsPort("7389");
        data.setBaseDN("o=testtks22");
        data.setBindDN("cn=Directory Manager");
        data.setDatabase("o=testtks22");
        data.setBindpwd("redhat123");
        data.setRemoveData("true");
        data.setSecureConn("false");

        data.setBackupKeys("true");
        data.setBackupFile("/tmp/testtks.p12");
        data.setBackupPassword("redhat123");

        data.setAdminEmail("alee@redhat.com");
        data.setAdminName("admin");
        data.setAdminPassword("redhat123");
        data.setAdminProfileID("caAdminCert");
        data.setAdminUID("admin");
        String subjectdn = "CN=TKS Administrator of Instance testtks, UID=admin, E=alee@redhat.com, o=testtks22";
        data.setAdminSubjectDN(subjectdn);

        String crmf_request = generateCRMFRequest(token, "2048", subjectdn, false);
        data.setAdminCertRequest(crmf_request);
        data.setAdminCertRequestType("crmf");

        data.setIssuingCA("https://" + host + ":9224");

        // create system certs
        List<SystemCertData> systemCerts = new ArrayList<SystemCertData>();

        SystemCertData cert3 = new SystemCertData();
        cert3.setTag("sslserver");
        cert3.setKeyAlgorithm("SHA256withRSA");
        cert3.setKeySize("2048");
        cert3.setKeyType("rsa");
        cert3.setNickname("sslServerCert testtks");
        cert3.setSubjectDN("CN=" + host);
        cert3.setToken("Internal Key Storage Token");
        systemCerts.add(cert3);

        SystemCertData cert4 = new SystemCertData();
        cert4.setTag("subsystem");
        cert4.setKeyAlgorithm("SHA256withRSA");
        cert4.setKeySize("2048");
        cert4.setKeyType("rsa");
        cert4.setNickname("subsystemCert testtks");
        cert4.setSubjectDN("CN=TKS Subsystem Certificate");
        cert4.setToken("Internal Key Storage Token");
        systemCerts.add(cert4);

        SystemCertData cert5 = new SystemCertData();
        cert5.setTag("audit_signing");
        cert5.setKeyAlgorithm("SHA256withRSA");
        cert5.setKeySize("2048");
        cert5.setKeyType("rsa");
        cert5.setNickname("auditSigningCert testtks");
        cert5.setSigningAlgorithm("SHA256withRSA");
        cert5.setSubjectDN("CN=TKS Audit Signing Certificate");
        cert5.setToken("Internal Key Storage Token");
        systemCerts.add(cert5);

        data.setSystemCerts(systemCerts);

        return data;
    }

    private static String generateCRMFRequest(CryptoToken token, String keysize, String subjectdn, boolean dualkey)
            throws NoSuchAlgorithmException, TokenException, IOException, InvalidBERException {
        KeyPairGenerator kg = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);

        Integer x = new Integer(keysize);
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
        String Req1 = Utils.base64encode(encoded);
        return Req1;
    }
}
