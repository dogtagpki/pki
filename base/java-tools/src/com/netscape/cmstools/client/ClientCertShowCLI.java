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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.certsrv.cert.CertData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.util.Utils;

/**
 * @author Endi S. Dewata
 */
public class ClientCertShowCLI extends CLI {

    public ClientCLI clientCLI;

    public ClientCertShowCLI(ClientCLI clientCLI) {
        super("cert-show", "Show certificate in client security database", clientCLI);
        this.clientCLI = clientCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <nickname> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "cert", true, "PEM file to store the certificate.");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "client-cert", true, "PEM file to store the certificate and the private key.");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "pkcs12", true, "PKCS #12 file to store the certificate chain and the private key.");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "pkcs12-password", true, "PKCS #12 file password.");
        option.setArgName("password");
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
        String certPath = cmd.getOptionValue("cert");
        String pkcs12Path = cmd.getOptionValue("pkcs12");
        String pkcs12Password = cmd.getOptionValue("pkcs12-password");
        String clientCertPath = cmd.getOptionValue("client-cert");

        if (certPath != null) {

            if (verbose) System.out.println("Exporting certificate to " + clientCertPath + ".");

            // late initialization
            mainCLI.init();

            client = mainCLI.getClient();
            X509Certificate cert = client.getCert(nickname);

            try (PrintWriter out = new PrintWriter(new FileWriter(certPath))) {
                out.println(CertData.HEADER);
                out.println(Utils.base64encode(cert.getEncoded()));
                out.println(CertData.FOOTER);
            }

        } else if (pkcs12Path != null) {

            if (verbose) System.out.println("Exporting certificate chain and private key to " + pkcs12Path + ".");

            if (pkcs12Password == null) {
                throw new Exception("Missing PKCS #12 password");
            }

            // store password into a temporary file
            File pkcs12PasswordFile = File.createTempFile("pki-client-cert-show-", ".pwd");
            pkcs12PasswordFile.deleteOnExit();

            try (PrintWriter out = new PrintWriter(new FileWriter(pkcs12PasswordFile))) {
                out.print(pkcs12Password);
            }

            // export certificate chain and private key into PKCS #12 file
            exportPKCS12(
                    mainCLI.certDatabase.getAbsolutePath(),
                    mainCLI.config.getCertPassword(),
                    pkcs12Path,
                    pkcs12PasswordFile.getAbsolutePath(),
                    nickname);

        } else if (clientCertPath != null) {

            if (verbose) System.out.println("Exporting client certificate and private key to " + clientCertPath + ".");

            // generate random PKCS #12 password
            pkcs12Password = RandomStringUtils.randomAlphanumeric(16);

            // store password into a temporary file
            File pkcs12PasswordFile = File.createTempFile("pki-client-cert-show-", ".pwd");
            pkcs12PasswordFile.deleteOnExit();

            try (PrintWriter out = new PrintWriter(new FileWriter(pkcs12PasswordFile))) {
                out.print(pkcs12Password);
            }

            // export certificate chain and private key into a temporary PKCS #12 file
            File pkcs12File = File.createTempFile("pki-client-cert-show-", ".p12");
            pkcs12File.deleteOnExit();

            exportPKCS12(
                    mainCLI.certDatabase.getAbsolutePath(),
                    mainCLI.config.getCertPassword(),
                    pkcs12File.getAbsolutePath(),
                    pkcs12PasswordFile.getAbsolutePath(),
                    nickname);

            // export client certificate and private key into a PEM file
            exportClientCertificate(
                    pkcs12File.getAbsolutePath(),
                    pkcs12PasswordFile.getAbsolutePath(),
                    clientCertPath);

        } else {
            // late initialization
            mainCLI.init();

            client = mainCLI.getClient();
            X509Certificate cert = client.getCert(nickname);

            ClientCLI.printCertInfo(cert);
        }
    }

    public void exportPKCS12(
            String dbPath,
            String dbPassword,
            String pkcs12Path,
            String pkcs12PasswordPath,
            String nickname) throws Exception {

        String[] command = {
                "/bin/pk12util",
                "-d", dbPath,
                "-K", dbPassword,
                "-o", pkcs12Path,
                "-w", pkcs12PasswordPath,
                "-n", nickname
        };

        try {
            run(command);

        } catch (Exception e) {
            throw new Exception("Unable to export PKCS #12 file", e);
        }
    }

    public void exportClientCertificate(
            String pkcs12Path,
            String pkcs12PasswordPath,
            String clientCertPath) throws Exception {

        String[] command = {
                "/bin/openssl",
                "pkcs12",
                "-clcerts", // client certificate only
                "-nodes",   // no encryption
                "-in",      pkcs12Path,
                "-passin",  "file:" + pkcs12PasswordPath,
                "-out",     clientCertPath
        };

        try {
            run(command);

        } catch (Exception e) {
            throw new Exception("Unable to export client certificate", e);
        }
    }

    public void run(String[] command) throws IOException, InterruptedException {

        if (verbose) System.out.println("Command: " + StringUtils.join(command, " "));

        Runtime rt = Runtime.getRuntime();
        Process p = rt.exec(command);
        int rc = p.waitFor();

        if (rc != 0) {
            throw new IOException("Command failed. RC: " + rc);
        }
    }
}
