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

package com.netscape.cmstools.client;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientCertModifyCLI extends CLI {

    public ClientCLI clientCLI;

    public ClientCertModifyCLI(ClientCLI clientCLI) {
        super("cert-mod", "Modify certificate in client security database", clientCLI);
        this.clientCLI = clientCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <nickname> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "trust", true, "Trust attributes. Default: u,u,u.");
        option.setArgName("trust attributes");
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments specified.");
        }

        if (cmdArgs.length == 0) {
            throw new Exception("Missing certificate nickname.");
        }

        MainCLI mainCLI = (MainCLI)parent.getParent();

        String nickname = cmdArgs[0];

        String trustAttributes = cmd.getOptionValue("trust", "u,u,u");

        String[] command = {
                "/usr/bin/certutil", "-M",
                "-d", mainCLI.certDatabase.getAbsolutePath(),
                "-n", nickname,
                "-t", trustAttributes
        };

        try {
            runExternal(command);
        } catch (Exception e) {
            throw new Exception("Unable to modify certificate", e);
        }

        MainCLI.printMessage("Modified certificate \"" + nickname + "\"");
    }
}
