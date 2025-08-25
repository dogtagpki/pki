//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.acme.cli;

import java.io.File;
import java.io.FileReader;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.acme.database.ACMEDatabase;
import org.dogtagpki.acme.database.ACMEDatabaseConfig;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.server.cli.SubsystemCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.CMS;

/**
 * @author Endi S. Dewata
 */
public class ACMEDatabaseInitCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(ACMEDatabaseInitCLI.class);

    public ACMEDatabaseInitCLI(CLI parent) {
        super("init", "Initialize " + parent.getParent().getName().toUpperCase() + " database", parent);
    }

    public ACMEDatabaseInitCLI(String name, String description, CLI parent) {
        super(name, description, parent);
    }

    @Override
    public void createOptions() {
        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        initializeTomcatJSS();

        String instanceDir = CMS.getInstanceDir();
        String serverConfDir = instanceDir + File.separator + "conf";
        String acmeConfDir = serverConfDir + File.separator + "acme";
        logger.info("ACME configuration directory: " + acmeConfDir);

        File databaseConfigFile = new File(acmeConfDir + File.separator + "database.conf");
        ACMEDatabaseConfig databaseConfig;

        if (databaseConfigFile.exists()) {
            logger.info("Loading ACME database config from " + databaseConfigFile);
            Properties dbProps = new Properties();
            try (FileReader reader = new FileReader(databaseConfigFile)) {
                dbProps.load(reader);
            }
            databaseConfig = ACMEDatabaseConfig.fromProperties(dbProps);

        } else {
            logger.info("Loading default ACME database config");
            databaseConfig = new ACMEDatabaseConfig();
        }

        String className = databaseConfig.getClassName();
        Class<ACMEDatabase> databaseClass = (Class<ACMEDatabase>) Class.forName(className);

        ACMEDatabase database = databaseClass.getDeclaredConstructor().newInstance();
        database.setConfig(databaseConfig);

        try {
            database.init();

            logger.info("Initializing ACME database");
            database.initDatabase();

        } finally {
            database.close();
        }
    }
}
