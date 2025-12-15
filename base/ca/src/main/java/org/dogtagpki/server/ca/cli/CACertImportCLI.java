//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.jss.tomcat.TomcatJSS;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.security.SecureRandomConfig;
import com.netscape.cmscore.security.SecureRandomFactory;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class CACertImportCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(CACertImportCLI.class);

    public CACertImportCLI(CLI parent) {
        super("import", "Import certificate into CA", parent);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "cert", true, "Certificate path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "profile", true, "Bootstrap profile path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "request", true, "Request ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "request-type", true, "Certificate request type: pkcs10 (default), crmf");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "csr", true, "CSR path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "csr-format", true, "CSR format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "dns-names", true, "Comma-separated list of DNS names");
        option.setArgName("names");
        options.addOption(option);

        options.addOption(null, "adjust-validity", false, "Adjust validity");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        if (!cmd.hasOption("cert")) {
            throw new Exception("Missing certificate");
        }

        String certPath = cmd.getOptionValue("cert");
        String certFormat = cmd.getOptionValue("format");

        if (!cmd.hasOption("profile")) {
            throw new Exception("Missing bootstrap profile path");
        }

        String value = cmd.getOptionValue("request");
        RequestId requestID = null;
        if (value != null) {
            requestID = new RequestId(value);
        }

        String requestType = cmd.getOptionValue("request-type", "pkcs10");

        String csrPath = cmd.getOptionValue("csr");
        String csrFormat = cmd.getOptionValue("csr-format");

        value = cmd.getOptionValue("dns-names");
        String[] dnsNames = null;
        if (value != null) {
            dnsNames = value.split(",");
        }

        value = cmd.getOptionValue("adjust-validity", "false");
        boolean adjustValidity = Boolean.parseBoolean(value);

        // initialize JSS in pki-server CLI
        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        // load CSR if provided
        byte[] csrBytes = null;
        if (csrPath != null) {
            logger.info("Importing " + csrPath);
            csrBytes = Files.readAllBytes(Paths.get(csrPath));

            if (csrFormat == null || "PEM".equalsIgnoreCase(csrFormat)) {
                csrBytes = CertUtil.parseCSR(new String(csrBytes));

            } else if ("DER".equalsIgnoreCase(csrFormat)) {
                // nothing to do

            } else {
                throw new Exception("Unsupported CSR format: " + csrFormat);
            }
        }

        // load certificate
        byte[] certBytes;
        if (certPath == null) {
            // read from standard input
            certBytes = IOUtils.toByteArray(System.in);

        } else {
            // read from file
            certBytes = Files.readAllBytes(Paths.get(certPath));
        }

        if (certFormat == null || "PEM".equalsIgnoreCase(certFormat)) {
            certBytes = Cert.parseCertificate(new String(certBytes));

        } else if ("DER".equalsIgnoreCase(certFormat)) {
            // nothing to do

        } else {
            throw new Exception("Unsupported certificate format: " + certFormat);
        }

        // must be done after JSS initialization for RSA/PSS
        X509CertImpl cert = new X509CertImpl(certBytes);

        String instanceDir = CMS.getInstanceDir();

        String subsystem = parent.getParent().getName();
        String confDir = instanceDir + File.separator + subsystem + File.separator + "conf";
        String configFile = confDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStorage(configFile);
        CAEngineConfig cs = new CAEngineConfig(storage);
        cs.load();

        // If the bootstrap profile path is relative (e.g. caCert.profile),
        // convert it to /var/lib/pki/pki-tomcat/ca/conf/<profile>.
        // If the bootstrap profile path is absolute, use it as is.
        String profile = cmd.getOptionValue("profile");
        Path profilePath = Paths.get(confDir).resolve(profile);

        logger.info("Loading " + profilePath);
        ConfigStorage profileStorage = new FileConfigStorage(profilePath.toString());
        ConfigStore profileConfig = new ConfigStore(profileStorage);
        profileConfig.load();

        String profileIDMapping = profileConfig.getString("profileIDMapping");

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        LDAPConfig ldapConfig = dbConfig.getLDAPConfig();
        ldapConfig.setMinConnections(0);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = CMS.createPasswordStore(psc);

        SecureRandomConfig secureRandomConfig = cs.getJssSubsystemConfig().getSecureRandomConfig();
        SecureRandom secureRandom = SecureRandomFactory.create(secureRandomConfig);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setSecure(connConfig.isSecure());
        if (LdapAuthInfo.LDAP_SSLCLIENTAUTH_STR.equals(authConfig.getAuthType())) {
            socketFactory.setClientCertNickname(authConfig.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        DBSubsystem dbSubsystem = new DBSubsystem();
        dbSubsystem.setEngineConfig(cs);
        dbSubsystem.setSocketFactory(socketFactory);
        dbSubsystem.init(dbConfig, ldapConfig, passwordStore);

        try {
            // import CSR if provided
            if (csrBytes != null) {
                Request request = CACertCLI.importCertRequest(
                        secureRandom,
                        dbSubsystem,
                        requestID,
                        requestType,
                        csrBytes,
                        dnsNames,
                        profileConfig,
                        adjustValidity);

                requestID = request.getRequestId();
                logger.info("Created request record " + requestID.toHexString());
            }

            // import cert
            CertificateRepository certificateRepository = new CertificateRepository(secureRandom, dbSubsystem);
            certificateRepository.init();

            logger.info("Creating cert record 0x" + cert.getSerialNumber().toString(16) + ":");
            logger.info("- subject: " + cert.getSubjectName());
            logger.info("- issuer: " + cert.getIssuerName());
            logger.info("- request ID: " + requestID.toHexString());
            logger.info("- profile ID mapping: " + profileIDMapping);

            CertRecord certRecord = certificateRepository.createCertRecord(
                    requestID,
                    profileIDMapping,
                    cert);

            certificateRepository.addCertificateRecord(certRecord);

            logger.info("Updating request record " + requestID.toHexString());

            CertRequestRepository requestRepository = new CertRequestRepository(secureRandom, dbSubsystem);
            requestRepository.init();

            Request request = requestRepository.readRequest(requestID);

            requestRepository.updateRequest(request, cert);

            request.setRequestStatus(RequestStatus.COMPLETE);
            requestRepository.updateRequest(request);

        } finally {
            dbSubsystem.shutdown();
        }
    }
}
