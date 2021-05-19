//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.commons.cli.CommandLine;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.Level;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertRecordList;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmsutil.password.IPasswordStore;
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
        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String filter = "(certstatus=*)";
        int size = 20;

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(Level.INFO);
        }

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

        CAConfig caConfig = cs.getCAConfig();

        logger.info("Initializing cert repository");

        int increment = caConfig.getInteger(CertificateRepository.PROP_INCREMENT, 5);
        logger.info("- increment: " + increment);

        try {
            CertificateRepository certificateRepository = new CertificateRepository(dbSubsystem);

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
                System.out.println("  Not Valid Before: " + cert.getNotBefore());
                System.out.println("  Not Valid After: " + cert.getNotAfter());
            }

        } finally {
            dbSubsystem.shutdown();
        }
    }
}
