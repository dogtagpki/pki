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
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang.StringUtils;

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
        formatter.printHelp(getFullName() + " [nickname] [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "cert", true, "Certificate file to import.");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "ca-cert", true, "CA certificate file to import.");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "pkcs12", true, "PKCS #12 file to import.");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "pkcs12-password", true, "PKCS #12 password.");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "pkcs12-password-file", true, "PKCS #12 password file.");
        option.setArgName("path");
        options.addOption(option);

        options.addOption(null, "ca-server", false, "Import CA certificate from CA server");

        option = new Option(null, "serial", true, "Serial number of certificate to import from CA server");
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

        // nickname is not required to import PKCS #12 file

        String certPath = cmd.getOptionValue("cert");
        String caCertPath = cmd.getOptionValue("ca-cert");
        String pkcs12Path = cmd.getOptionValue("pkcs12");
        String pkcs12Password = cmd.getOptionValue("pkcs12-password");
        String pkcs12PasswordPath = cmd.getOptionValue("pkcs12-password-file");
        boolean importFromCAServer = cmd.hasOption("ca-server");
        String serialNumber = cmd.getOptionValue("serial");
        String trustAttributes = cmd.getOptionValue("trust", "u,u,u");

        // load the certificate
        if (certPath != null) {

            if (verbose) System.out.println("Importing certificate from " + certPath + ".");

            importCert(
                    mainCLI.certDatabase.getAbsolutePath(),
                    certPath,
                    nickname,
                    trustAttributes);

        } else if (caCertPath != null) {

            if (verbose) System.out.println("Importing CA certificate from " + caCertPath + ".");

            trustAttributes = "CT,c,";

            importCert(
                    mainCLI.certDatabase.getAbsolutePath(),
                    caCertPath,
                    nickname,
                    trustAttributes);

        } else if (pkcs12Path != null) {

            if (verbose) System.out.println("Importing certificates from " + pkcs12Path + ".");

            if (pkcs12Password != null && pkcs12PasswordPath != null) {
                throw new Exception("PKCS #12 password and password file are mutually exclusive");

            } else if (pkcs12Password != null) {
                // store password into a temporary file
                File pkcs12PasswordFile = File.createTempFile("pki-client-cert-import-", ".pwd");
                pkcs12PasswordFile.deleteOnExit();

                try (PrintWriter out = new PrintWriter(new FileWriter(pkcs12PasswordFile))) {
                    out.print(pkcs12Password);
                }

                pkcs12PasswordPath = pkcs12PasswordFile.getAbsolutePath();

            } else if (pkcs12PasswordPath != null) {
                // nothing to do

            } else {
                throw new Exception("Missing PKCS #12 password");
            }

            // import certificates and private key into PKCS #12 file
            importPKCS12(
                    mainCLI.certDatabase.getAbsolutePath(),
                    mainCLI.config.getCertPassword(),
                    pkcs12Path,
                    pkcs12PasswordPath);

        } else if (importFromCAServer) {

            // late initialization
            mainCLI.init();

            client = mainCLI.getClient();
            URI serverURI = mainCLI.config.getServerURI();

            String caServerURI = serverURI.getScheme() + "://" +
                serverURI.getHost() + ":" + serverURI.getPort() + "/ca";

            if (verbose) System.out.println("Importing CA certificate from " + caServerURI + ".");
            byte[] bytes = client.downloadCACertChain(caServerURI);

            File certFile = File.createTempFile("pki-client-cert-import-", ".crt");
            certFile.deleteOnExit();

            try (FileOutputStream out = new FileOutputStream(certFile)) {
                out.write(bytes);
            }

            trustAttributes = "CT,c,";

            importCert(
                    mainCLI.certDatabase.getAbsolutePath(),
                    certFile.getAbsolutePath(),
                    nickname,
                    trustAttributes);

        } else if (serialNumber != null) {

            // connect to CA anonymously
            ClientConfig config = new ClientConfig(mainCLI.config);
            config.setCertDatabase(null);
            config.setCertPassword(null);
            config.setCertNickname(null);

            URI serverURI = config.getServerURI();
            if (verbose) System.out.println("Importing certificate " + serialNumber + " from " + serverURI + ".");

            PKIClient client = new PKIClient(config, null);
            CertClient certClient = new CertClient(client, "ca");

            CertData certData = certClient.getCert(new CertId(serialNumber));

            File certFile = File.createTempFile("pki-client-cert-import-", ".crt");
            certFile.deleteOnExit();

            String encoded = certData.getEncoded();
            try (PrintWriter out = new PrintWriter(new FileWriter(certFile))) {
                out.write(encoded);
            }

            importCert(
                    mainCLI.certDatabase.getAbsolutePath(),
                    certFile.getAbsolutePath(),
                    nickname,
                    trustAttributes);

        } else {
            System.err.println("Error: Missing certificate to import");
            printHelp();
            System.exit(-1);
            return;
        }

        if (nickname == null) {
            MainCLI.printMessage("Imported certificates from PKCS #12 file");

        } else {
            MainCLI.printMessage("Imported certificate \"" + nickname + "\"");
        }
    }

    public void importCert(
            String dbPath,
            String certPath,
            String nickname,
            String trustAttributes) throws Exception {

        if (nickname == null) {
            System.err.println("Error: Missing certificate nickname.");
            System.exit(-1);
        }

        String[] command = {
                "/bin/certutil", "-A",
                "-d", dbPath,
                "-i", certPath,
                "-n", nickname,
                "-t", trustAttributes
        };

        try {
            run(command);

        } catch (Exception e) {
            throw new Exception("Unable to import certificate file", e);
        }
    }

    public void importPKCS12(
            String dbPath,
            String dbPassword,
            String pkcs12Path,
            String pkcs12PasswordPath) throws Exception {

        String[] command = {
                "/bin/pk12util",
                "-d", dbPath,
                "-K", dbPassword,
                "-i", pkcs12Path,
                "-w", pkcs12PasswordPath
        };

        try {
            run(command);

        } catch (Exception e) {
            throw new Exception("Unable to import PKCS #12 file", e);
        }
    }

    public void run(String[] command) throws IOException, InterruptedException {

        if (verbose) {
           System.out.println("Command: " + StringUtils.join(command));
        }

        Runtime rt = Runtime.getRuntime();
        Process p = rt.exec(command);
        int rc = p.waitFor();

        if (rc != 0) {
            throw new IOException("Command failed. RC: " + rc);
        }
    }
}
