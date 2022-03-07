//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.Level;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmsutil.password.IPasswordStore;
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

        Option option = new Option(null, "cert", true, "Certificate path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "profile", true, "Profile ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "request", true, "Request ID");
        option.setArgName("ID");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(Level.INFO);
        }

        if (!cmd.hasOption("cert")) {
            throw new Exception("Missing certificate");
        }

        String certPath = cmd.getOptionValue("cert");
        String certFormat = cmd.getOptionValue("format");

        byte[] bytes;
        if (certPath == null) {
            // read from standard input
            bytes = IOUtils.toByteArray(System.in);

        } else {
            // read from file
            bytes = Files.readAllBytes(Paths.get(certPath));
        }

        if (certFormat == null || "PEM".equalsIgnoreCase(certFormat)) {
            bytes = Cert.parseCertificate(new String(bytes));

        } else if ("DER".equalsIgnoreCase(certFormat)) {
            // nothing to do

        } else {
            throw new Exception("Unsupported format: " + certFormat);
        }

        X509CertImpl cert = new X509CertImpl(bytes);

        if (!cmd.hasOption("profile")) {
            throw new Exception("Missing profile ID");
        }

        String profileID = cmd.getOptionValue("profile");

        if (!cmd.hasOption("request")) {
            throw new Exception("Missing request ID");
        }

        RequestId requestID = new RequestId(cmd.getOptionValue("request"));

        String catalinaBase = System.getProperty("catalina.base");

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String subsystem = parent.getParent().getName();
        String confDir = catalinaBase + File.separator + subsystem + File.separator + "conf";
        String configFile = confDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStore(configFile);
        CAEngineConfig cs = new CAEngineConfig(storage);
        cs.load();

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        IPasswordStore passwordStore = IPasswordStore.create(psc);

        DBSubsystem dbSubsystem = new DBSubsystem();
        dbSubsystem.init(dbConfig, socketConfig, passwordStore);

        try {
            CertificateRepository certificateRepository = new CertificateRepository(dbSubsystem);
            certificateRepository.init();

            logger.info("Creating cert record 0x" + cert.getSerialNumber().toString(16) + ":");
            logger.info("- subject: " + cert.getSubjectDN());
            logger.info("- issuer: " + cert.getIssuerDN());
            logger.info("- profile ID: " + profileID);
            logger.info("- request ID: " + requestID.toHexString());

            CertRecord certRecord = certificateRepository.createCertRecord(
                    requestID,
                    profileID,
                    cert);

            certificateRepository.addCertificateRecord(certRecord);

            logger.info("Updating request record " + requestID.toHexString());

            CertRequestRepository requestRepository = new CertRequestRepository(dbSubsystem);
            requestRepository.init();

            Request request = requestRepository.readRequest(requestID);

            request.setExtData(EnrollProfile.REQUEST_CERTINFO, cert.getInfo());
            request.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);
            request.setRequestStatus(RequestStatus.COMPLETE);

            requestRepository.updateRequest(request);

        } finally {
            dbSubsystem.shutdown();
        }
    }
}
