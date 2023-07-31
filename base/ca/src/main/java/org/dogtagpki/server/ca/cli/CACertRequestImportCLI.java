//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.jss.tomcat.TomcatJSS;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.cert.CertRequestInfoFactory;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.Repository.IDGenerator;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.security.SecureRandomConfig;
import com.netscape.cmscore.security.SecureRandomFactory;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class CACertRequestImportCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(CACertRequestImportCLI.class);

    public CACertRequestImportCLI(CLI parent) {
        super("import", "Import certificate request into CA", parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "csr", true, "Certificate request path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate request format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "type", true, "Certificate request type: pkcs10 (default), crmf");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "profile", true, "Profile ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "dns-names", true, "Comma-separated list of DNS names");
        option.setArgName("names");
        options.addOption(option);

        options.addOption(null, "adjust-validity", false, "Adjust validity");

        option = new Option(null, "output-format", true, "Output format: text (default), json.");
        option.setArgName("format");
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

        String instanceDir = CMS.getInstanceDir();

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String[] cmdArgs = cmd.getArgs();

        RequestId requestID = null;
        if (cmdArgs.length >= 1) {
            requestID = new RequestId(cmdArgs[0]);
        }

        if (!cmd.hasOption("profile")) {
            throw new Exception("Missing profile ID");
        }

        if (!cmd.hasOption("csr")) {
            throw new Exception("Missing certificate request");
        }

        String requestPath = cmd.getOptionValue("csr");
        String requestFormat = cmd.getOptionValue("format");

        byte[] bytes;
        if (requestPath == null) {
            // read from standard input
            bytes = IOUtils.toByteArray(System.in);

        } else {
            logger.info("Importing " + requestPath);
            bytes = Files.readAllBytes(Paths.get(requestPath));
        }

        if (requestFormat == null || "PEM".equalsIgnoreCase(requestFormat)) {
            bytes = CertUtil.parseCSR(new String(bytes));

        } else if ("DER".equalsIgnoreCase(requestFormat)) {
            // nothing to do

        } else {
            throw new Exception("Unsupported format: " + requestFormat);
        }

        String subsystem = parent.getParent().getParent().getName();
        String confDir = instanceDir + File.separator + subsystem + File.separator + "conf";
        String configFile = confDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStorage(configFile);
        CAEngineConfig cs = new CAEngineConfig(storage);
        cs.load();

        String profileID = cmd.getOptionValue("profile");
        String profilePath = confDir + File.separator + profileID;

        logger.info("Loading " + profilePath);
        ConfigStorage profileStorage = new FileConfigStorage(profilePath);
        ConfigStore profileConfig = new ConfigStore(profileStorage);
        profileConfig.load();

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        LDAPConfig ldapConfig = dbConfig.getLDAPConfig();
        ldapConfig.putInteger("minConns", 1);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

        String requestType = cmd.getOptionValue("type", "pkcs10");

        String value = cmd.getOptionValue("dns-names");
        String[] dnsNames = null;
        if (value != null) {
            dnsNames = value.split(",");
        }

        value = cmd.getOptionValue("adjust-validity", "false");
        boolean adjustValidity = Boolean.parseBoolean(value);

        SecureRandomConfig secureRandomConfig = cs.getJssSubsystemConfig().getSecureRandomConfig();
        SecureRandom secureRandom = SecureRandomFactory.create(secureRandomConfig);

        DBSubsystem dbSubsystem = new DBSubsystem();
        dbSubsystem.setEngineConfig(cs);
        dbSubsystem.init(dbConfig, ldapConfig, socketConfig, passwordStore);

        try {
            CertRequestRepository requestRepository = new CertRequestRepository(secureRandom, dbSubsystem);
            requestRepository.init();

            if (requestID == null) {
                if (requestRepository.getIDGenerator() != IDGenerator.RANDOM) {
                    throw new Exception("Unable to generate random request ID");
                }
                requestID = requestRepository.createRequestID();
            }

            Request request = requestRepository.createRequest(requestID, "enrollment");

            requestRepository.updateRequest(
                    request,
                    requestType,
                    bytes,
                    dnsNames);

            requestRepository.updateRequest(
                    request,
                    profileConfig.getString("id"),
                    profileConfig.getString("profileIDMapping"),
                    profileConfig.getString("profileSetIDMapping"),
                    adjustValidity);

            requestRepository.updateRequest(request);

            CertRequestInfo info = CertRequestInfoFactory.create(request);

            String outputFormat = cmd.getOptionValue("output-format", "text");
            if (outputFormat.equalsIgnoreCase("json")) {
                System.out.println(info.toJSON());

            } else if (outputFormat.equalsIgnoreCase("text")) {
                CACertRequestCLI.printCertRequestInfo(info);

            } else {
                throw new Exception("Unsupported output format: " + outputFormat);
            }

        } finally {
            dbSubsystem.shutdown();
        }
    }
}
