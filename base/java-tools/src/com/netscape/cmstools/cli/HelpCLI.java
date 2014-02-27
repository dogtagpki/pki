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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.cli;

import org.apache.commons.cli.CommandLine;

/**
 * @author Endi S. Dewata
 */
public class HelpCLI extends CLI {

    MainCLI mainCLI;

    public HelpCLI(MainCLI parent) {
        super("help", "Help messages", parent);
        mainCLI = parent;
    }

    public String getFullName() {
        return name;
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String[] cmdArgs = cmd.getArgs();

        String command;
        if (cmdArgs.length == 0) {
            command = "pki";

        } else {
            command = "pki-" + cmdArgs[0];
        }

        while (true) {
            // display man page for the command
            ProcessBuilder pb = new ProcessBuilder(
                    "/bin/man",
                    command);

            pb.inheritIO();
            Process p = pb.start();
            int rc = p.waitFor();

            if (rc == 16) {
                // man page not found, find the parent command
                int i = command.lastIndexOf('-');
                if (i >= 0) {
                    // parent command exists, try again
                    command = command.substring(0, i);
                    continue;

                } else {
                    // parent command not found, stop
                    break;
                }

            } else {
                // man page found or there's a different error, stop
                break;
            }
        }
    }
}
