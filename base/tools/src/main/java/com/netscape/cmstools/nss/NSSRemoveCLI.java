//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class NSSRemoveCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSRemoveCLI.class);

    public NSSCLI nssCLI;

    public NSSRemoveCLI(NSSCLI nssCLI) {
        super("remove", "Remove NSS database", nssCLI);
        this.nssCLI = nssCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        options.addOption(null, "force", false, "Force removal.");
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified");
        }

        MainCLI mainCLI = nssCLI.mainCLI;
        File certDatabase = mainCLI.getNSSDatabase();
        NSSDatabase nssdb = new NSSDatabase(certDatabase);

        if (!nssdb.exists()) {
            throw new Exception("There is no NSS database in " + certDatabase.getAbsolutePath());
        }

        boolean force = cmd.hasOption("force");

        if (!force) {
            System.out.println("Removing NSS database in " + certDatabase.getAbsolutePath() + ".");
            System.out.print("Are you sure (y/N)? ");
            System.out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine().trim();

            if (line.equals("") || !line.substring(0, 1).equalsIgnoreCase("Y")) {
                return;
            }
        }

        nssdb.delete();
    }
}
