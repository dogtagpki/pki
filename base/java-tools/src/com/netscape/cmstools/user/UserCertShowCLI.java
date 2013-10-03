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

import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.URLEncoder;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.user.UserCertData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class UserCertShowCLI extends CLI {

    public UserCertCLI userCertCLI;

    public UserCertShowCLI(UserCertCLI userCertCLI) {
        super("show", "Show user certificate", userCertCLI);
        this.userCertCLI = userCertCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> <Cert ID> [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        Option option = new Option(null, "output", true, "Output file");
        option.setArgName("file");
        options.addOption(option);

        options.addOption(null, "pretty", false, "Pretty print");
        options.addOption(null, "encoded", false, "Base-64 encoded");

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        boolean showPrettyPrint = cmd.hasOption("pretty");
        boolean showEncoded = cmd.hasOption("encoded");

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 2) {
            printHelp();
            System.exit(1);
        }

        String userID = cmdArgs[0];
        String certID = cmdArgs[1];
        String file = cmd.getOptionValue("output");

        UserCertData userCertData = userCertCLI.userClient.getUserCert(userID, URLEncoder.encode(certID, "UTF-8"));

        String encoded = userCertData.getEncoded();
        if (encoded != null && file != null) {
            // store cert to file
            PrintWriter out = new PrintWriter(new FileWriter(file));
            out.print(encoded);
            out.close();
        }

        MainCLI.printMessage("Certificate \"" + userCertData.getID() + "\"");

        UserCertCLI.printCert(userCertData, showPrettyPrint, showEncoded);
    }
}
