//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.acme;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.acme.ACMEClient;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.Level;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ACMEDisableCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEDisableCLI.class);

    public ACMEDisableCLI(ACMECLI acmeCLI) {
        super("disable", "Disable ACME service", acmeCLI);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    public void execute(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(Level.INFO);
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        ACMEClient acmeClient = new ACMEClient(client);

        acmeClient.login();

        logger.info("Disabling ACME service");
        acmeClient.disable();

        acmeClient.logout();
    }
}
