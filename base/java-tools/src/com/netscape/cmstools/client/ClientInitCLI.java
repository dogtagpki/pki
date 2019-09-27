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
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientInitCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ClientInitCLI.class);

    public ClientCLI clientCLI;

    public ClientInitCLI(ClientCLI clientCLI) {
        super("init", "Initialize NSS database", clientCLI);
        this.clientCLI = clientCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        options.addOption(null, "force", false, "Force NSS database initialization.");
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
            throw new Exception("Too many arguments specified");
        }

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(PKILogger.Level.INFO);
        }

        MainCLI mainCLI = clientCLI.mainCLI;
        File certDatabase = mainCLI.getNSSDatabase();

        if (certDatabase.exists()) {

            boolean force = cmd.hasOption("force");

            if (!force) {
                System.out.println("NSS database already exists in " + certDatabase.getAbsolutePath() + ".");
                System.out.print("Overwrite (y/N)? ");
                System.out.flush();

                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                String line = reader.readLine().trim();

                if (line.equals("") || !line.substring(0, 1).equalsIgnoreCase("Y")) {
                    return;
                }
            }

            FileUtils.deleteDirectory(certDatabase);
        }

        File passwordFile = new File(certDatabase, "password.txt");

        try {
            certDatabase.mkdirs();

            List<String> command = new ArrayList<>();
            command.add("certutil");
            command.add("-N");
            command.add("-d");
            command.add(certDatabase.getAbsolutePath());

            ClientConfig config = mainCLI.getConfig();
            String password = config.getNSSPassword();

            if (password == null) {
                command.add("--empty-password");

            } else {
                try (PrintWriter out = new PrintWriter(new FileWriter(passwordFile))) {
                    out.println(password);
                }

                command.add("-f");
                command.add(passwordFile.getAbsolutePath());
            }

            runExternal(command);

        } catch (Exception e) {
            throw new Exception("Unable to create NSS database: " + e.getMessage(), e);

        } finally {
            if (passwordFile.exists()) passwordFile.delete();
        }
    }
}
