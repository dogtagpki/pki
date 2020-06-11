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
import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class ClientCertImportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ClientCertImportCLI.class);

    public ClientCLI clientCLI;

    public ClientCertImportCLI(ClientCLI clientCLI) {
        super("cert-import", "Import certificate into NSS database", clientCLI);
        this.clientCLI = clientCLI;
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

        option = new Option(null, "pkcs7", true, "DEPRECATED: PKCS #7 file to import.");
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

        option = new Option(null, "trust", true, "Trust attributes.");
        option.setArgName("trust attributes");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments specified");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ClientConfig clientConfig = mainCLI.getConfig();
        String nickname = null;

        // Get nickname from command argument if specified.
        if (cmdArgs.length > 0) {
            nickname = cmdArgs[0];
        }

        // Otherwise, get nickname from authentication option -n.
        // This code is used to provide backward compatibility.
        // TODO: deprecate/remove this code in 10.3.
        if (nickname == null) {
            nickname = clientConfig.getCertNickname();
        }

        // nickname is not required to import PKCS #12 file

        String certPath = cmd.getOptionValue("cert");
        String caCertPath = cmd.getOptionValue("ca-cert");
        String pkcs7Path = cmd.getOptionValue("pkcs7");
        String pkcs12Path = cmd.getOptionValue("pkcs12");
        String pkcs12Password = cmd.getOptionValue("pkcs12-password");
        String pkcs12PasswordPath = cmd.getOptionValue("pkcs12-password-file");
        boolean importFromCAServer = cmd.hasOption("ca-server");
        String serialNumber = cmd.getOptionValue("serial");
        String trustAttributes = cmd.getOptionValue("trust");

        NSSDatabase nssdb = mainCLI.getNSSDatabase();
        File nssdbPasswordFile = null;

        String password = clientConfig.getNSSPassword();
        if (password != null) {

            // store NSS database password in a temporary file

            nssdbPasswordFile = File.createTempFile("pki-client-cert-import-", ".nssdb-pwd");
            nssdbPasswordFile.deleteOnExit();

            try (PrintWriter out = new PrintWriter(new FileWriter(nssdbPasswordFile))) {
                out.print(password);
            }
        }

        // load the certificate
        if (certPath != null) {

            logger.info("Importing certificate from " + certPath);

            if (nickname == null) {
                throw new Exception("Missing certificate nickname");
            }

            if (trustAttributes == null)
                trustAttributes = "u,u,u";

            importCert(
                    nssdb.getDirectory(),
                    nssdbPasswordFile,
                    certPath,
                    nickname,
                    trustAttributes);

        } else if (caCertPath != null) {

            logger.info("Importing CA certificate from " + caCertPath);

            if (trustAttributes == null)
                trustAttributes = "CT,C,C";

            if (nickname != null) {
                // import a single CA certificate with the provided nickname
                importCert(nssdb.getDirectory(), nssdbPasswordFile, caCertPath, nickname, trustAttributes);
                return;
            }

            org.mozilla.jss.crypto.X509Certificate cert = nssdb.addCertificate(caCertPath, trustAttributes);
            System.out.println("Imported certificate \"" + cert.getNickname() + "\"");

        } else if (pkcs7Path != null) {

            logger.warn("The --pkcs7 option has been deprecated. Use the following command instead:");
            logger.warn("  $ pki pkcs7-import --input-file <filename>");

            logger.info("Importing certificates from " + pkcs7Path);

            importPKCS7(pkcs7Path, nickname, trustAttributes);

        } else if (pkcs12Path != null) {

            logger.info("Importing certificates from " + pkcs12Path);

            if (pkcs12Password != null && pkcs12PasswordPath != null) {
                throw new Exception("PKCS #12 password and password file are mutually exclusive");

            } else if (pkcs12Password != null) {
                // store password into a temporary file
                File pkcs12PasswordFile = File.createTempFile("pki-client-cert-import-", ".pkcs12-pwd");
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
                    nssdb.getDirectory(),
                    nssdbPasswordFile,
                    pkcs12Path,
                    pkcs12PasswordPath);

        } else if (importFromCAServer) {

            logger.info("Importing CA certificate from " + clientConfig.getServerURL());

            PKIClient client = getClient();
            CAClient caClient = new CAClient(client);
            PKCS7 chain = caClient.getCertChain();

            if (trustAttributes == null)
                trustAttributes = "CT,C,C";

            CryptoUtil.importPKCS7(chain, nickname, trustAttributes);

        } else if (serialNumber != null) {

            // connect to CA anonymously
            ClientConfig config = new ClientConfig(clientConfig);
            config.setNSSDatabase(null);
            config.setNSSPassword(null);
            config.setCertNickname(null);

            URL serverURL = config.getServerURL();
            logger.info("Importing certificate " + serialNumber + " from " + serverURL);

            PKIClient client = new PKIClient(config);
            CAClient caClient = new CAClient(client);
            CACertClient certClient = new CACertClient(caClient);

            CertData certData = certClient.getCert(new CertId(serialNumber));

            File certFile = File.createTempFile("pki-client-cert-import-", ".crt");
            certFile.deleteOnExit();

            String encoded = certData.getEncoded();
            try (PrintWriter out = new PrintWriter(new FileWriter(certFile))) {
                out.write(encoded);
            }

            if (nickname == null) {
                throw new Exception("Missing certificate nickname");
            }

            if (trustAttributes == null)
                trustAttributes = "u,u,u";

            importCert(
                    nssdb.getDirectory(),
                    nssdbPasswordFile,
                    certFile.getAbsolutePath(),
                    nickname,
                    trustAttributes);

        } else {
            throw new Exception("Missing certificate to import");
        }
    }

    public void importCert(
            File dbPath,
            File dbPasswordFile,
            String certFile,
            String nickname,
            String trustAttributes) throws Exception {

        List<String> command = new ArrayList<>();
        command.add("/usr/bin/certutil");
        command.add("-A");
        command.add("-d");
        command.add(dbPath.getAbsolutePath());

        if (dbPasswordFile != null) {
            command.add("-f");
            command.add(dbPasswordFile.getAbsolutePath());
        }

        // accept PEM or PKCS #7 certificate
        command.add("-a");

        command.add("-i");
        command.add(certFile);
        command.add("-n");
        command.add(nickname);
        command.add("-t");
        command.add(trustAttributes);

        try {
            runExternal(command);
        } catch (Exception e) {
            throw new Exception("Unable to import certificate file", e);
        }

        System.out.println("Imported certificate \"" + nickname + "\"");
    }

    public void importPKCS7(
            String pkcs7Path,
            String nickname,
            String trustAttributes) throws Exception {

        logger.info("Loading PKCS #7 data from " + pkcs7Path);
        String str = new String(Files.readAllBytes(Paths.get(pkcs7Path))).trim();

        PKCS7 pkcs7 = new PKCS7(str);
        CryptoUtil.importPKCS7(pkcs7, nickname, trustAttributes);
    }

    public void importPKCS12(
            File dbPath,
            File dbPasswordFile,
            String pkcs12File,
            String pkcs12PasswordFile) throws Exception {

        List<String> command = new ArrayList<>();
        command.add("/usr/bin/pk12util");
        command.add("-d");
        command.add(dbPath.getAbsolutePath());

        if (dbPasswordFile != null) {
            command.add("-k");
            command.add(dbPasswordFile.getAbsolutePath());
        }

        command.add("-i");
        command.add(pkcs12File);
        command.add("-w");
        command.add(pkcs12PasswordFile);

        try {
            runExternal(command);
        } catch (Exception e) {
            throw new Exception("Unable to import PKCS #12 file", e);
        }

        System.out.println("Imported certificates from PKCS #12 file");
    }
}
