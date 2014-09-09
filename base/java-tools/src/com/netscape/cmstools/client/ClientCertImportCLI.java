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
import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.cert.CertClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
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
        formatter.printHelp(getFullName() + " <nickname> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "cert", true, "Import certificate file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "ca-cert", true, "Import CA certificate file");
        option.setArgName("path");
        options.addOption(option);

        options.addOption(null, "ca-server", false, "Import CA certificate from CA server");

        option = new Option(null, "serial", true, "Serial number of certificate in CA");
        option.setArgName("serial number");
        options.addOption(option);

        option = new Option(null, "trust", true, "Trust attributes. Default: u,u,u.");
        option.setArgName("trust attributes");
        options.addOption(option);
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

        if (cmdArgs.length > 1) {
            System.err.println("Error: Too many arguments specified.");
            printHelp();
            System.exit(-1);
        }

        MainCLI mainCLI = (MainCLI)parent.getParent();

        String nickname = null;

        // Get nickname from command argument if specified.
        if (cmdArgs.length > 0) {
            nickname = cmdArgs[0];
        }

        // Otherwise, get nickname from authentication option -n.
        // This code is used to provide backward compatibility.
        // TODO: deprecate/remove this code in 10.3.
        if (nickname == null) {
            nickname = mainCLI.config.getCertNickname();
        }

        if (nickname == null) {
            System.err.println("Error: Missing certificate nickname.");
            System.exit(-1);
        }

        String certPath = cmd.getOptionValue("cert");
        String caCertPath = cmd.getOptionValue("ca-cert");
        boolean importFromCAServer = cmd.hasOption("ca-server");
        String serialNumber = cmd.getOptionValue("serial");
        String trustAttributes = cmd.getOptionValue("trust", "u,u,u");

        File certFile;

        // load the certificate
        if (certPath != null) {
            if (verbose) System.out.println("Loading certificate from " + certPath + ".");
            certFile = new File(certPath);

        } else if (caCertPath != null) {
            if (verbose) System.out.println("Loading CA certificate from " + caCertPath + ".");
            certFile = new File(caCertPath);

            trustAttributes = "CT,c,";

        } else if (importFromCAServer) {

            // late initialization
            mainCLI.init();

            client = mainCLI.getClient();
            URI serverURI = mainCLI.config.getServerURI();

            String caServerURI = serverURI.getScheme() + "://" +
                serverURI.getHost() + ":" + serverURI.getPort() + "/ca";

            if (verbose) System.out.println("Downloading CA certificate from " + caServerURI + ".");
            byte[] bytes = client.downloadCACertChain(caServerURI);

            certFile = File.createTempFile("pki-client-cert-import-", ".crt", mainCLI.certDatabase);
            certFile.deleteOnExit();

            try (FileOutputStream out = new FileOutputStream(certFile)) {
                out.write(bytes);
            }

            trustAttributes = "CT,c,";

        } else if (serialNumber != null) {

            // connect to CA anonymously
            ClientConfig config = new ClientConfig(mainCLI.config);
            config.setCertDatabase(null);
            config.setCertPassword(null);
            config.setCertNickname(null);

            PKIClient client = new PKIClient(config, null);
            CertClient certClient = new CertClient(client, "ca");

            CertData certData = certClient.getCert(new CertId(serialNumber));

            certFile = File.createTempFile("pki-client-cert-import-", ".crt", mainCLI.certDatabase);
            certFile.deleteOnExit();

            String encoded = certData.getEncoded();
            try (PrintWriter out = new PrintWriter(new FileWriter(certFile))) {
                out.write(encoded);
            }

        } else {
            System.err.println("Error: Missing certificate to import");
            printHelp();
            System.exit(-1);
            return;
        }

        String[] commands = {
                "/usr/bin/certutil", "-A",
                "-d", mainCLI.certDatabase.getAbsolutePath(),
                "-i", certFile.getAbsolutePath(),
                "-n", nickname,
                "-t", trustAttributes
        };

        Runtime rt = Runtime.getRuntime();
        Process p = rt.exec(commands);

        int rc = p.waitFor();
        if (rc != 0) {
            MainCLI.printMessage("Import failed");
            return;
        }

        MainCLI.printMessage("Imported certificate \"" + nickname + "\"");
    }
}
