//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class NSSCreateCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCreateCLI.class);

    public NSSCLI nssCLI;

    public NSSCreateCLI(NSSCLI nssCLI) {
        super("create", "Create NSS database", nssCLI);
        this.nssCLI = nssCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        options.addOption(null, "force", false, "Force creation.");
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified");
        }

        MainCLI mainCLI = nssCLI.mainCLI;
        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        // Make sure existing NSS database is deleted
        if (nssdb.exists()) {

            boolean force = cmd.hasOption("force");

            if (!force) {
                System.out.println("NSS database already exists in " + nssdb.getPath() + ".");
                System.out.print("Overwrite (y/N)? ");
                System.out.flush();

                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                String line = reader.readLine().trim();

                if (line.equals("") || !line.substring(0, 1).equalsIgnoreCase("Y")) {
                    return;
                }
            }

            nssdb.delete();
        }

        // Create NSS database with the provided password
        ClientConfig config = mainCLI.getConfig();
        nssdb.create(config.getNSSPassword());
    }
}
