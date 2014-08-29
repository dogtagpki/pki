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

import java.io.File;
import java.io.FileOutputStream;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.FileUtils;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientCertImportCLI extends CLI {

    public ClientCLI clientCLI;

    public ClientCertImportCLI(ClientCLI clientCLI) {
        super("cert-import", "Import certificate into client security database", clientCLI);
        this.clientCLI = clientCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "cert", true, "Import certificate file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "ca-cert", true, "Import CA certificate file");
        option.setArgName("path");
        options.addOption(option);

        options.addOption(null, "ca-server", false, "Import CA certificate from CA server");
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

        if (cmdArgs.length != 0) {
            System.err.println("Error: Too many arguments specified.");
            printHelp();
            System.exit(-1);
        }

        byte[] bytes = null;

        String certPath = cmd.getOptionValue("cert");
        String caCertPath = cmd.getOptionValue("ca-cert");
        boolean importFromCAServer = cmd.hasOption("ca-server");

        boolean isCACert = false;

        // load the certificate
        if (certPath != null) {
            if (verbose) System.out.println("Loading certificate from " + certPath + ".");
            bytes = FileUtils.readFileToByteArray(new File(certPath));


        } else if (caCertPath != null) {
            if (verbose) System.out.println("Loading CA certificate from " + caCertPath + ".");
            bytes = FileUtils.readFileToByteArray(new File(caCertPath));

            isCACert = true;

        } else if (importFromCAServer) {

            // late initialization
            MainCLI mainCLI = (MainCLI)parent.parent;
            mainCLI.init();

            client = mainCLI.getClient();
            ClientConfig config = client.getConfig();

            String caServerURI = "http://" + config.getServerURI().getHost() + ":8080/ca";

            if (verbose) System.out.println("Downloading CA certificate from " + caServerURI + ".");
            bytes = client.downloadCACertChain(caServerURI);

            isCACert = true;

        } else {
            System.err.println("Error: Missing certificate to import");
            printHelp();
            System.exit(-1);
        }

        MainCLI mainCLI = (MainCLI)parent.getParent();

        if (mainCLI.config.getCertNickname() == null) {
            System.err.println("Error: Certificate nickname is required.");
            System.exit(-1);
        }

        File certDatabase = mainCLI.certDatabase;
        File certFile = new File(certDatabase, "import.crt");

        try {
            try (FileOutputStream out = new FileOutputStream(certFile)) {
                out.write(bytes);
            }

            String flag;
            if (isCACert) {
                if (verbose) System.out.println("Importing CA certificate.");
                flag = "CT,c,";

            } else {
                if (verbose) System.out.println("Importing certificate.");
                flag = "u,u,u";
            }

            String[] commands = {
                    "/usr/bin/certutil", "-A",
                    "-d", certDatabase.getAbsolutePath(),
                    "-i", certFile.getAbsolutePath(),
                    "-n", mainCLI.config.getCertNickname(),
                    "-t", flag
            };

            Runtime rt = Runtime.getRuntime();
            Process p = rt.exec(commands);

            int rc = p.waitFor();
            if (rc != 0) {
                MainCLI.printMessage("Import failed");
                return;
            }

            MainCLI.printMessage("Imported certificate \"" + mainCLI.config.getCertNickname() + "\"");

        } finally {
            certFile.delete();
        }
    }
}
