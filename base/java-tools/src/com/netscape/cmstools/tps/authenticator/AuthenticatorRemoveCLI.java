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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.tps.authenticator;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class AuthenticatorRemoveCLI extends CLI {

    public AuthenticatorCLI authenticatorCLI;

    public AuthenticatorRemoveCLI(AuthenticatorCLI authenticatorCLI) {
        super("del", "Remove authenticator", authenticatorCLI);
        this.authenticatorCLI = authenticatorCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Authenticator ID> [OPTIONS...]", options);
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
            System.err.println("Error: No Authenticator ID specified.");
            printHelp();
            System.exit(-1);
        }

        String authenticatorID = args[0];

        authenticatorCLI.authenticatorClient.removeAuthenticator(authenticatorID);

        MainCLI.printMessage("Deleted authenticator \"" + authenticatorID + "\"");
    }
}
