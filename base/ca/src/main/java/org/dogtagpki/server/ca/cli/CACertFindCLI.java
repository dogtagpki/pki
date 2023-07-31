//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import java.io.File;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.jss.tomcat.TomcatJSS;
import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cms.servlet.cert.FilterBuilder;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertRecordList;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.security.SecureRandomConfig;
import com.netscape.cmscore.security.SecureRandomFactory;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class CACertFindCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(CACertFindCLI.class);

    public CACertFindCLI(CLI parent) {
        super("find", "Find certificates in CA", parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "status", true, "Certificate status: VALID, INVALID, REVOKED, EXPIRED, REVOKED_EXPIRED");
        option.setArgName("status");
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

        CertSearchRequest searchRequest = new CertSearchRequest();
        if (cmd.hasOption("status")) {
            searchRequest.setStatus(cmd.getOptionValue("status"));
        }

        FilterBuilder builder = new FilterBuilder(searchRequest);
        String filter = builder.buildFilter();
        logger.info("- filter: " + filter);

        int size = 20;

        String instanceDir = CMS.getInstanceDir();

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String subsystem = parent.getParent().getName();
        String confDir = instanceDir + File.separator + subsystem + File.separator + "conf";
        String configFile = confDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStorage(configFile);
        CAEngineConfig cs = new CAEngineConfig(storage);
        cs.load();

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

        CAConfig caConfig = cs.getCAConfig();

        logger.info("Initializing cert repository");

        int increment = caConfig.getInteger(CertificateRepository.PROP_INCREMENT, 5);
        logger.info("- increment: " + increment);

        try {
            CertificateRepository certificateRepository = new CertificateRepository(secureRandom, dbSubsystem);
            certificateRepository.init();

            CertRecordList list = certificateRepository.findCertRecordsInList(filter, null, "serialno", size);
            int total = list.getSize();

            for (int i = 0; i < total; i++) {

                if (i > 0) {
                    System.out.println();
                }

                CertRecord record = list.getCertRecord(i);
                CertId id = new CertId(record.getSerialNumber());
                X509Certificate cert = record.getCertificate();

                System.out.println("  Serial Number: " + id.toHexString());
                System.out.println("  Subject DN: " + cert.getSubjectDN());
                System.out.println("  Issuer DN: " + cert.getIssuerDN());

                System.out.println("  Status: " + record.getStatus());

                System.out.println("  Not Valid Before: " + cert.getNotBefore());
                System.out.println("  Not Valid After: " + cert.getNotAfter());

                System.out.println("  Issued On: " + record.getCreateTime());
                System.out.println("  Issued By: " + record.getIssuedBy());

                Date revokedOn = record.getRevokedOn();
                if (revokedOn != null) {
                    System.out.println("  Revoked On: " + revokedOn);
                }

                String revokedBy = record.getRevokedBy();
                if (revokedBy != null) {
                    System.out.println("  Revoked By: " + revokedBy);
                }
            }

        } finally {
            dbSubsystem.shutdown();
        }
    }
}
