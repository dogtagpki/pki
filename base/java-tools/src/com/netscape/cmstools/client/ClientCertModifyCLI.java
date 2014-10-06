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

import java.io.IOException;

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

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        if (cmd.hasOption("help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length > 1) {
            System.err.println("Error: Too many arguments specified.");
            printHelp();
            System.exit(-1);
        }

        if (cmdArgs.length == 0) {
            System.err.println("Error: Missing certificate nickname.");
            printHelp();
            System.exit(-1);
        }

        MainCLI mainCLI = (MainCLI)parent.getParent();

        String nickname = cmdArgs[0];

        String trustAttributes = cmd.getOptionValue("trust", "u,u,u");

        int rc = modifyCert(
                mainCLI.certDatabase.getAbsolutePath(),
                nickname,
                trustAttributes);

        if (rc != 0) {
            MainCLI.printMessage("Modified failed");
            return;
        }

        MainCLI.printMessage("Modified certificate \"" + nickname + "\"");
    }

    public int modifyCert(
            String dbPath,
            String nickname,
            String trustAttributes) throws IOException, InterruptedException {

        String[] command = {
                "/usr/bin/certutil", "-M",
                "-d", dbPath,
                "-n", nickname,
                "-t", trustAttributes
        };

        return run(command);
    }

    public int run(String[] command) throws IOException, InterruptedException {

        Runtime rt = Runtime.getRuntime();
        Process p = rt.exec(command);
        return p.waitFor();
    }
}
