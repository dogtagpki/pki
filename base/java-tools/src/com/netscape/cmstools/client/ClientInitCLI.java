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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        options.addOption(null, "force", false, "Force database initialization.");
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        MainCLI mainCLI = (MainCLI)parent.getParent();

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
            List<String> list = new ArrayList<>();
            list.add("/usr/bin/certutil");
            list.add("-N");
            list.add("-d");
            list.add(certDatabase.getAbsolutePath());

            if (mainCLI.config.getCertPassword() == null) {
                list.add("--empty-password");

            } else {
                try (PrintWriter out = new PrintWriter(new FileWriter(passwordFile))) {
                    out.println(mainCLI.config.getCertPassword());
                }

                list.add("-f");
                list.add(passwordFile.getAbsolutePath());
            }

            try {
                runExternal(list);
            } catch (Exception e) {
                throw new Exception("Client initialization failed", e);
            }

            MainCLI.printMessage("Client initialized");

        } finally {
            if (passwordFile.exists()) passwordFile.delete();
        }
    }
}
