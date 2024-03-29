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

import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIModule;
import org.dogtagpki.cli.CommandCLI;

/**
 * @author Endi S. Dewata
 */
public class HelpCLI extends CommandCLI {

    MainCLI mainCLI;

    public HelpCLI(MainCLI parent) {
        super("help", "Show help messages", parent);
        mainCLI = parent;
    }

    @Override
    public String getFullName() {
        return name;
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        String manPage = null;
        if (cmdArgs.length == 0) {
            // no command specified, show the pki man page
            manPage = parent.getManPage();

        } else {
            // find all modules handling the specified command
            List<CLIModule> modules = parent.findModules(cmdArgs[0]);

            // find the module that has a man page starting from the last one
            for (int i = modules.size() - 1; i >= 0; i--) {
                CLIModule module = modules.get(i);
                CLI cli = module.getCLI();
                manPage = cli.getManPage();
                if (manPage != null) break;
            }

            // if no module has a man page, show the pki man page
            if (manPage == null)
                manPage = parent.getManPage();
        }

        while (true) {
            // display man page for the command
            ProcessBuilder pb = new ProcessBuilder(
                    "/usr/bin/man",
                    manPage);

            pb.inheritIO();
            Process p = pb.start();
            int rc = p.waitFor();

            if (rc == 16) {
                // man page not found, find the parent command
                int i = manPage.lastIndexOf('-');
                if (i >= 0) {
                    // parent command exists, try again
                    manPage = manPage.substring(0, i);
                    continue;

                }
                // parent command not found, stop
                break;

            }
            // man page found or there's a different error, stop
            break;
        }
    }
}
