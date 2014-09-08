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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.FileUtils;

import com.netscape.certsrv.cert.CertClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.dbs.certdb.CertId;
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
        formatter.printHelp(getFullName() + " <User ID> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "input", true, "Input file");
        option.setArgName("file");
        options.addOption(option);

        option = new Option(null, "serial", true, "Serial number of certificate in CA");
        option.setArgName("serial number");
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

        String userID = cmdArgs[0];
        String inputFile = cmd.getOptionValue("input");
        String serialNumber = cmd.getOptionValue("serial");

        String encoded;

        if (inputFile != null && serialNumber != null) {
            System.err.println("Error: Conflicting options: --input and --serial.");
            printHelp();
            System.exit(-1);
            return;

        } else if (inputFile != null) {
            if (verbose) {
                System.out.println("Reading certificate from " + inputFile + ".");
            }

            encoded = FileUtils.readFileToString(new File(inputFile));
            if (verbose) {
                System.out.println(encoded);
            }

        } else if (serialNumber != null) {
            if (verbose) {
                System.out.println("Downloading certificate " + serialNumber + ".");
            }

            client = parent.getClient();
            CertClient certClient = new CertClient(client, "ca");

            CertData certData = certClient.getCert(new CertId(serialNumber));
            encoded = certData.getEncoded();

        } else {
            System.err.println("Error: Missing input file or serial number.");
            printHelp();
            System.exit(-1);
            return;
        }

        UserCertData userCertData = new UserCertData();
        userCertData.setEncoded(encoded);

        if (verbose) {
            System.out.println(userCertData);
        }

        userCertData = userCertCLI.userClient.addUserCert(userID, userCertData);

        MainCLI.printMessage("Added certificate \"" + userCertData.getID() + "\"");

        UserCertCLI.printCert(userCertData, false, false);
    }
}
