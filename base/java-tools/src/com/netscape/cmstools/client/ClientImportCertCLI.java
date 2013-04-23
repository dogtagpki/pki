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
import java.net.URI;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.FileUtils;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientImportCertCLI extends CLI {

    public ClientCLI parent;

    public ClientImportCertCLI(ClientCLI parent) {
        super("import-cert", "Import certificate into client security database");
        this.parent = parent;
    }

    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " [OPTIONS]", options);
    }

    public void execute(String[] args) throws Exception {

        Option option = new Option(null, "cert", true, "Import certificate file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "ca-cert", true, "Import CA certificate file");
        option.setArgName("path");
        options.addOption(option);

        options.addOption(null, "ca-server", false, "Import CA certificate from CA server");

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        byte[] bytes = null;
        X509Certificate cert = null;

        String certPath = cmd.getOptionValue("cert");
        String caCertPath = cmd.getOptionValue("ca-cert");
        boolean importCACert = cmd.hasOption("ca-server");

        if (certPath != null) {
            if (verbose) System.out.println("Loading certificate from " + certPath + ".");
            bytes = FileUtils.readFileToByteArray(new File(certPath));

            if (verbose) System.out.println("Importing certificate.");
            cert = parent.parent.client.importCertPackage(bytes, parent.parent.client.config.getCertNickname());

        } else if (caCertPath != null) {
            if (verbose) System.out.println("Loading CA certificate from " + caCertPath + ".");
            bytes = FileUtils.readFileToByteArray(new File(caCertPath));

            if (verbose) System.out.println("Importing CA certificate.");
            cert = parent.parent.client.importCACertPackage(bytes);

        } else if (importCACert) {
            ClientConfig config = parent.parent.config;
            String caServerURI = "http://" + config.getServerURI().getHost() + ":8080/ca";

            if (verbose) System.out.println("Downloading CA certificate from " + caServerURI + ".");
            bytes = parent.parent.client.downloadCACertChain(new URI(caServerURI));

            if (verbose) System.out.println("Importing CA certificate.");
            cert = parent.parent.client.importCACertPackage(bytes);

        } else {
            System.err.println("Error: Missing certificate to import");
            printHelp();
            System.exit(1);
        }

        MainCLI.printMessage("Imported certificate \"" + cert.getNickname() + "\"");
        ClientCLI.printCertInfo(cert);
    }
}
