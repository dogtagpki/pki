// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.user;

import java.io.File;
import java.util.Arrays;
import java.util.Scanner;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.user.UserCertData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class UserCertAddCLI extends CLI {

    public UserCertCLI userCertCLI;

    public UserCertAddCLI(UserCertCLI userCertCLI) {
        super("add", "Add user certificate", userCertCLI);
        this.userCertCLI = userCertCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> --input <file> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "input", true, "Input file");
        option.setArgName("file");
        option.setRequired(true);
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            System.err.println("Error: No User ID specified.");
            printHelp();
            System.exit(-1);
        }

        String userId = cmdArgs[0];
        String file = cmd.getOptionValue("input");

        // get cert from file
        if (verbose) {
            System.out.println("Reading cert from "+file+".");
        }
        String encoded = new Scanner(new File(file)).useDelimiter("\\A").next();
        if (verbose) {
            System.out.println(encoded);
        }

        UserCertData userCertData = new UserCertData();
        userCertData.setEncoded(encoded);

        if (verbose) {
            System.out.println(userCertData);
        }

        userCertData = userCertCLI.userClient.addUserCert(userId, userCertData);

        MainCLI.printMessage("Added certificate \"" + userCertData.getID() + "\"");

        UserCertCLI.printCert(userCertData, false, false);
    }
}
