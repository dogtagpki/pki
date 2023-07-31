//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Date;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.codec.binary.Hex;
import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.jss.tomcat.TomcatJSS;
import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CASigningUnit;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.security.SigningUnitConfig;
import com.netscape.cms.servlet.csadmin.BootstrapProfile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.Repository.IDGenerator;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.security.SecureRandomConfig;
import com.netscape.cmscore.security.SecureRandomFactory;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class CACertCreateCLI extends CommandCLI {

    public static final Logger logger = LoggerFactory.getLogger(CACertCreateCLI.class);

    public CACertCreateCLI(CLI parent) {
        super("create", "Create certificate from certificate request in CA", parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "request", true, "Request ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "profile", true, "Profile ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "type", true, "Certificate type: selfsign (default), local");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "key-id", true, "Key ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "key-token", true, "Key token");
        option.setArgName("name");
        options.addOption(option);

        option = new Option(null, "key-algorithm", true, "Key algorithm (default: SHA256withRSA)");
        option.setArgName("name");
        options.addOption(option);

        option = new Option(null, "signing-algorithm", true, "Signing algorithm (default: SHA256withRSA)");
        option.setArgName("name");
        options.addOption(option);

        option = new Option(null, "serial", true, "Certificate serial number");
        option.setArgName("serial");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "cert", true, "Certificate path");
        option.setArgName("path");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(LogLevel.INFO);
        }

        String requestID = cmd.getOptionValue("request");
        if (requestID == null) {
            throw new CLIException("Missing request ID");
        }

        String profileID = cmd.getOptionValue("profile");
        if (profileID == null) {
            throw new CLIException("Missing profile ID");
        }

        String serial = cmd.getOptionValue("serial");
        String certType = cmd.getOptionValue("type", "selfsign");

        String tokenName = cmd.getOptionValue("key-token");
        String keyAlgorithm = cmd.getOptionValue("key-algorithm", "SHA256withRSA");

        String signingAlgorithm = cmd.getOptionValue("signing-algorithm", "SHA256withRSA");

        String certFormat = cmd.getOptionValue("format", "PEM");
        String certPath = cmd.getOptionValue("cert");

        // initialize JSS in pki-server CLI
        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String instanceDir = CMS.getInstanceDir();

        String subsystem = parent.getParent().getName();
        String confDir = instanceDir + File.separator + subsystem + File.separator + "conf";
        String configFile = confDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStorage(configFile);
        CAEngineConfig cs = new CAEngineConfig(storage);
        cs.load();

        String profilePath = confDir + File.separator + profileID;

        logger.info("Loading " + profilePath);
        ConfigStorage profileStorage = new FileConfigStorage(profilePath);
        ConfigStore profileConfig = new ConfigStore(profileStorage);
        profileConfig.load();
        BootstrapProfile profile = new BootstrapProfile(cs, profileConfig);

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        LDAPConfig ldapConfig = dbConfig.getLDAPConfig();
        ldapConfig.putInteger("minConns", 1);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

        SecureRandomConfig secureRandomConfig = cs.getJssSubsystemConfig().getSecureRandomConfig();
        SecureRandom secureRandom = SecureRandomFactory.create(secureRandomConfig);

        DBSubsystem dbSubsystem = new DBSubsystem();
        dbSubsystem.setEngineConfig(cs);
        dbSubsystem.init(dbConfig, ldapConfig, socketConfig, passwordStore);

        try {
            CertRequestRepository requestRepository = new CertRequestRepository(secureRandom, dbSubsystem);
            requestRepository.init();

            Request requestRecord = requestRepository.readRequest(new RequestId(requestID));
            if (requestRecord == null) {
                throw new CLIException("Certificate request not found: " + requestID);
            }

            String certRequestType = requestRecord.getExtDataInString("cert_request_type");
            logger.info("Request type: " + certRequestType);

            String certRequest = requestRecord.getExtDataInString("cert_request");
            logger.info("Request:\n" + certRequest);

            byte[] binCertRequest = CertUtil.parseCSR(certRequest);

            X500Name subjectName;
            X509Key x509key;

            if (certRequestType.equals("crmf")) {
                SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(binCertRequest);
                subjectName = CryptoUtil.getSubjectName(crmfMsgs);
                x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);

            } else if (certRequestType.equals("pkcs10")) {
                PKCS10 pkcs10 = new PKCS10(binCertRequest);
                subjectName = pkcs10.getSubjectName();
                x509key = pkcs10.getSubjectPublicKeyInfo();

            } else {
                throw new CLIException("Certificate request type not supported: " + certRequestType);
            }

            logger.info("Subject: " + subjectName);
            logger.info("Cert type: " + certType);

            X509CertImpl signingCert = null;
            X500Name issuerName;
            PrivateKey signingPrivateKey;

            if (certType.equals("selfsign")) {

                String hexKeyID = cmd.getOptionValue("key-id");
                if (hexKeyID == null) {
                    throw new CLIException("Missing key ID");
                }

                logger.info("Key ID: " + hexKeyID);
                logger.info("Key token: " + tokenName);

                String keyID = hexKeyID;
                if (keyID.startsWith("0x")) keyID = keyID.substring(2);
                if (keyID.length() % 2 == 1) keyID = "0" + keyID;

                CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
                PK11PrivKey privateKey = (PK11PrivKey) CryptoUtil.findPrivateKey(
                        token,
                        Hex.decodeHex(keyID));

                if (privateKey == null) {
                    throw new CLIException("Private key not found: " + hexKeyID);
                }

                PK11PubKey publicKey = privateKey.getPublicKey();
                KeyPair keyPair = new KeyPair(publicKey, privateKey);

                issuerName = subjectName;
                signingPrivateKey = (PrivateKey) keyPair.getPrivate();

            } else { // certType == local

                CAConfig caConfig = cs.getCAConfig();
                SigningUnitConfig caSigningCfg = caConfig.getSigningUnitConfig();

                // create CA signing unit
                CASigningUnit signingUnit = new CASigningUnit();
                signingUnit.init(caSigningCfg, null);

                signingCert = signingUnit.getCertImpl();
                CertificateSubjectName certSubjectName = signingCert.getSubjectObj();

                // use CA's issuer object to preserve DN encoding
                issuerName = (X500Name) certSubjectName.get(CertificateIssuerName.DN_NAME);
                signingPrivateKey = signingUnit.getPrivateKey();
            }

            logger.info("Issuer: " + issuerName);

            CertificateRepository certificateRepository = new CertificateRepository(secureRandom, dbSubsystem);
            certificateRepository.init();

            BigInteger serialNumber;

            if (serial == null) {
                if (certificateRepository.getIDGenerator() != IDGenerator.RANDOM) {
                    throw new CLIException("Unable to generate random certificate ID");
                }
                serialNumber = certificateRepository.getNextSerialNumber();

            } else {
                serialNumber = new CertId(serial).toBigInteger();
            }
            logger.info("Cert ID: 0x" + Utils.HexEncode(serialNumber.toByteArray()));

            CertificateIssuerName certIssuerName = new CertificateIssuerName(issuerName);
            CertificateExtensions extensions = new CertificateExtensions();

            Date date = new Date();
            X509CertInfo certInfo = CryptoUtil.createX509CertInfo(
                    x509key,
                    serialNumber,
                    certIssuerName,
                    subjectName,
                    date,
                    date,
                    keyAlgorithm,
                    extensions);

            logger.info("Cert info:\n" + certInfo);

            profile.populate(requestRecord, certInfo);
            requestRepository.updateRequest(requestRecord);

            X509CertImpl certImpl = CryptoUtil.signCert(
                    signingPrivateKey,
                    certInfo,
                    signingAlgorithm);

            byte[] bytes;

            if ("PEM".equalsIgnoreCase(certFormat)) {
                bytes = CertUtil.toPEM(certImpl).getBytes();

            } else if ("DER".equalsIgnoreCase(certFormat)) {
                bytes = certImpl.getEncoded();

            } else {
                throw new CLIException("Unsupported certificate format: " + certFormat);
            }

            if (certPath != null) {
                try (PrintStream out = new PrintStream(new FileOutputStream(certPath))) {
                    out.write(bytes);
                }

            } else {
                System.out.write(bytes);
            }

        } finally {
            dbSubsystem.shutdown();
        }
    }
}
