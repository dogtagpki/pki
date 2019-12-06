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
import java.io.InputStreamReader;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientInitCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ClientInitCLI.class);

    public ClientCLI clientCLI;

    public ClientInitCLI(ClientCLI clientCLI) {
        super("init", "Initialize NSS database", clientCLI);
        this.clientCLI = clientCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        options.addOption(null, "force", false, "Force NSS database initialization.");
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified");
        }

        MainCLI mainCLI = clientCLI.mainCLI;
        File certDatabase = mainCLI.getNSSDatabase();
        NSSDatabase nssdb = new NSSDatabase(certDatabase);

        // Make sure existing NSS database is deleted
        if (nssdb.exists()) {

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

            nssdb.delete();
        }

        // Create NSS database with the provided password
        ClientConfig config = mainCLI.getConfig();
        nssdb.create(config.getNSSPassword());
    }
}
