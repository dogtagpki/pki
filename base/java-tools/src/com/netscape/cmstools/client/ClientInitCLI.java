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

package com.netscape.cmstools.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.io.FileUtils;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientInitCLI extends CLI {

    public ClientInitCLI(ClientCLI clientCLI) {
        super("init", "Initialize client security database", clientCLI);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS]", options);
    }

    public void execute(String[] args) throws Exception {

        options.addOption(null, "force", false, "Force database initialization.");

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        MainCLI mainCLI = (MainCLI)parent.getParent();

        if (mainCLI.config.getCertPassword() == null) {
            System.err.println("Error: Security database password is required.");
            System.exit(1);
        }

        boolean force = cmd.hasOption("force");
        File certDatabase = mainCLI.certDatabase;

        if (certDatabase.exists()) {

            if (!force) {
                System.out.print("Security database already exists. Overwrite (y/N)? ");
                System.out.flush();

                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                String line = reader.readLine().trim();

                if (line.equals("") || !line.substring(0, 1).equalsIgnoreCase("Y")) {
                    MainCLI.printMessage("Client initialization canceled");
                    return;
                }
            }

            FileUtils.deleteDirectory(certDatabase);
        }

        certDatabase.mkdirs();

        File passwordFile = new File(certDatabase, "password.txt");

        try {
            try (PrintWriter out = new PrintWriter(new FileWriter(passwordFile))) {
                out.println(mainCLI.config.getCertPassword());
            }

            String[] commands = {
                    "/usr/bin/certutil", "-N",
                    "-d", certDatabase.getAbsolutePath(),
                    "-f", passwordFile.getAbsolutePath()
            };

            Runtime rt = Runtime.getRuntime();
            Process p = rt.exec(commands);

            int rc = p.waitFor();
            if (rc != 0) {
                MainCLI.printMessage("Client initialization failed");
                return;
            }

            MainCLI.printMessage("Client initialized");

        } finally {
            passwordFile.delete();
        }
    }
}
