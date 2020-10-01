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
import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang3.RandomStringUtils;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientCertShowCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ClientCertShowCLI.class);

    public ClientCLI clientCLI;

    public ClientCertShowCLI(ClientCLI clientCLI) {
        super("cert-show", "Show certificate in NSS database", clientCLI);
        this.clientCLI = clientCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <nickname> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "cert", true, "PEM file to store the certificate.");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "private-key", true, "PEM file to store the private key.");
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

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments specified.");
        }

        if (cmdArgs.length == 0) {
            throw new Exception("Missing certificate nickname.");
        }

        MainCLI mainCLI = (MainCLI) getRoot();

        String nickname = cmdArgs[0];
        String certPath = cmd.getOptionValue("cert");
        String privateKeyPath = cmd.getOptionValue("private-key");
        String clientCertPath = cmd.getOptionValue("client-cert");
        String pkcs12Path = cmd.getOptionValue("pkcs12");
        String pkcs12Password = cmd.getOptionValue("pkcs12-password");

        File pkcs12File;

        if (pkcs12Path != null) {
            // exporting certificate to PKCS #12 file

            pkcs12File = new File(pkcs12Path);

            if (pkcs12Password == null) {
                throw new Exception("Missing PKCS #12 password");
            }

        } else if (clientCertPath != null || privateKeyPath != null) {
            // exporting private key to PEM file using temporary PKCS #12 file

            // prepare temporary PKCS #12 file
            pkcs12File = File.createTempFile("pki-client-cert-show-", ".p12");
            pkcs12File.deleteOnExit();

            // generate random password
            pkcs12Password = RandomStringUtils.randomAlphanumeric(16);

        } else {
            // displaying certificate info

            mainCLI.init();

            CryptoManager manager = CryptoManager.getInstance();
            X509Certificate cert = manager.findCertByNickname(nickname);

            if (certPath != null) {
                try (PrintWriter out = new PrintWriter(new FileWriter(certPath))) {
                    out.println(Cert.HEADER);
                    out.print(Utils.base64encode(cert.getEncoded(), true));
                    out.println(Cert.FOOTER);
                }

            } else {
                ClientCLI.printCertInfo(cert);

            }
            return;
        }

        // store password into a temporary file
        File pkcs12PasswordFile = File.createTempFile("pki-client-cert-show-", ".pwd");
        pkcs12PasswordFile.deleteOnExit();

        try (PrintWriter out = new PrintWriter(new FileWriter(pkcs12PasswordFile))) {
            out.print(pkcs12Password);
        }

        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        logger.info("Exporting certificate chain and private key to " + pkcs12File);
        exportPKCS12(
                nssdb.getPath().toString(),
                mainCLI.config.getNSSPassword(),
                pkcs12File.getAbsolutePath(),
                pkcs12PasswordFile.getAbsolutePath(),
                nickname);

        if (certPath != null) {
            logger.info("Exporting certificate to " + certPath);
            exportCertificate(
                    pkcs12File.getAbsolutePath(),
                    pkcs12PasswordFile.getAbsolutePath(),
                    certPath);
        }

        if (privateKeyPath != null) {
            logger.info("Exporting private key to " + privateKeyPath);
            exportPrivateKey(
                    pkcs12File.getAbsolutePath(),
                    pkcs12PasswordFile.getAbsolutePath(),
                    privateKeyPath);
        }

        if (clientCertPath != null) {
            logger.info("Exporting client certificate and private key to " + clientCertPath);
            exportClientCertificateAndPrivateKey(
                    pkcs12File.getAbsolutePath(),
                    pkcs12PasswordFile.getAbsolutePath(),
                    clientCertPath);
        }
    }

    public void exportPKCS12(
            String dbPath,
            String dbPassword,
            String pkcs12Path,
            String pkcs12PasswordPath,
            String nickname) throws Exception {

        String[] command = {
                "/usr/bin/pk12util",
                "-d", dbPath,
                "-K", dbPassword,
                "-o", pkcs12Path,
                "-w", pkcs12PasswordPath,
                "-n", nickname
        };

        try {
            runExternal(command);
        } catch (Exception e) {
            throw new Exception("Unable to export PKCS #12 file", e);
        }
    }

    public void exportCertificate(
            String pkcs12Path,
            String pkcs12PasswordPath,
            String certPath) throws Exception {

        String[] command = {
                "/usr/bin/openssl",
                "pkcs12",
                "-clcerts", // certificate only
                "-nokeys",
                "-in",      pkcs12Path,
                "-passin",  "file:" + pkcs12PasswordPath,
                "-out",     certPath
        };

        try {
            runExternal(command);
        } catch (Exception e) {
            throw new Exception("Unable to export certificate", e);
        }
    }

    public void exportPrivateKey(
            String pkcs12Path,
            String pkcs12PasswordPath,
            String privateKeyPath) throws Exception {

        String[] command = {
                "/usr/bin/openssl",
                "pkcs12",
                "-nocerts", // private key only
                "-nodes",   // no encryption
                "-in",      pkcs12Path,
                "-passin",  "file:" + pkcs12PasswordPath,
                "-out",     privateKeyPath
        };

        try {
            runExternal(command);
        } catch (Exception e) {
            throw new Exception("Unable to export private key", e);
        }
    }

    public void exportClientCertificateAndPrivateKey(
            String pkcs12Path,
            String pkcs12PasswordPath,
            String clientCertPath) throws Exception {

        String[] command = {
                "/usr/bin/openssl",
                "pkcs12",
                "-clcerts", // client certificate and private key
                "-nodes",   // no encryption
                "-in",      pkcs12Path,
                "-passin",  "file:" + pkcs12PasswordPath,
                "-out",     clientCertPath
        };

        try {
            runExternal(command);
        } catch (Exception e) {
            throw new Exception("Unable to export client certificate and private key", e);
        }
    }
}
