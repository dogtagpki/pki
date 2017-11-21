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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

import netscape.security.pkcs.PKCS12;
import netscape.security.pkcs.PKCS7;

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

        option = new Option(null, "pkcs7", true, "PKCS #7 file to import.");
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

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments specified.");
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
        String pkcs7Path = cmd.getOptionValue("pkcs7");
        String pkcs12Path = cmd.getOptionValue("pkcs12");
        String pkcs12Password = cmd.getOptionValue("pkcs12-password");
        String pkcs12PasswordPath = cmd.getOptionValue("pkcs12-password-file");
        boolean importFromCAServer = cmd.hasOption("ca-server");
        String serialNumber = cmd.getOptionValue("serial");
        String trustAttributes = cmd.getOptionValue("trust");

        File nssdbPasswordFile = null;

        if (mainCLI.config.getCertPassword() != null) {

            // store NSS database password in a temporary file

            nssdbPasswordFile = File.createTempFile("pki-client-cert-import-", ".nssdb-pwd");
            nssdbPasswordFile.deleteOnExit();

            try (PrintWriter out = new PrintWriter(new FileWriter(nssdbPasswordFile))) {
                out.print(mainCLI.config.getCertPassword());
            }
        }

        // load the certificate
        if (certPath != null) {

            if (verbose) System.out.println("Importing certificate from " + certPath + ".");

            if (trustAttributes == null)
                trustAttributes = "u,u,u";

            importCert(
                    mainCLI.certDatabase,
                    nssdbPasswordFile,
                    certPath,
                    nickname,
                    trustAttributes);

        } else if (caCertPath != null) {

            if (verbose) System.out.println("Importing CA certificate from " + caCertPath + ".");

            if (trustAttributes == null)
                trustAttributes = "CT,C,C";

            importCert(
                    mainCLI.certDatabase,
                    nssdbPasswordFile,
                    caCertPath,
                    nickname,
                    trustAttributes);

        } else if (pkcs7Path != null) {

            if (verbose) System.out.println("Importing certificates from " + pkcs7Path + ".");

            // initialize JSS
            mainCLI.init();

            importPKCS7(pkcs7Path, nickname, trustAttributes);

        } else if (pkcs12Path != null) {

            if (verbose) System.out.println("Importing certificates from " + pkcs12Path + ".");

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
                    mainCLI.certDatabase,
                    nssdbPasswordFile,
                    pkcs12Path,
                    pkcs12PasswordPath);

        } else if (importFromCAServer) {

            // late initialization
            mainCLI.init();

            PKIClient client = getClient();
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

            if (trustAttributes == null)
                trustAttributes = "CT,C,C";

            importCert(
                    mainCLI.certDatabase,
                    nssdbPasswordFile,
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
            CAClient caClient = new CAClient(client);
            CACertClient certClient = new CACertClient(caClient);

            CertData certData = certClient.getCert(new CertId(serialNumber));

            File certFile = File.createTempFile("pki-client-cert-import-", ".crt");
            certFile.deleteOnExit();

            String encoded = certData.getEncoded();
            try (PrintWriter out = new PrintWriter(new FileWriter(certFile))) {
                out.write(encoded);
            }

            if (trustAttributes == null)
                trustAttributes = "u,u,u";

            importCert(
                    mainCLI.certDatabase,
                    nssdbPasswordFile,
                    certFile.getAbsolutePath(),
                    nickname,
                    trustAttributes);

        } else {
            throw new Exception("Missing certificate to import");
        }

        if (nickname == null) {
            MainCLI.printMessage("Imported certificates from PKCS #12 file");

        } else {
            MainCLI.printMessage("Imported certificate \"" + nickname + "\"");
        }
    }

    public void setTrustAttributes(X509Certificate cert, String trustAttributes)
            throws Exception {

        String[] flags = trustAttributes.split(",", -1); // don't remove empty string
        if (flags.length < 3) throw new Exception("Invalid trust attributes: " + trustAttributes);

        InternalCertificate internalCert = (InternalCertificate) cert;
        internalCert.setSSLTrust(PKCS12.decodeFlags(flags[0]));
        internalCert.setEmailTrust(PKCS12.decodeFlags(flags[1]));
        internalCert.setObjectSigningTrust(PKCS12.decodeFlags(flags[2]));
    }

    public void importCert(
            File dbPath,
            File dbPasswordFile,
            String certFile,
            String nickname,
            String trustAttributes) throws Exception {

        if (nickname == null) {
            throw new Exception("Missing certificate nickname.");
        }

        List<String> command = new ArrayList<>();
        command.add("/usr/bin/certutil");
        command.add("-A");
        command.add("-d");
        command.add(dbPath.getAbsolutePath());

        if (dbPasswordFile != null) {
            command.add("-f");
            command.add(dbPasswordFile.getAbsolutePath());
        }

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
    }

    /**
     * Sorts certificate chain from leaf to root.
     *
     * This method sorts an array of certificates (e.g. from a PKCS #7
     * data) that represents a certificate chain from leaf to root
     * according to the subject DNs and issuer DNs.
     *
     * The array must contain exactly one unbranched certificate chain
     * with one leaf and one root. The subject DNs must be unique.
     *
     * The result is returned in a new array. The input array is unchanged.
     *
     * @param certs array of certificates
     * @return new array containing sorted certificates
     */
    public java.security.cert.X509Certificate[] sort(java.security.cert.X509Certificate[] certs) throws Exception {

        // lookup map: subject DN -> cert
        Map<String, java.security.cert.X509Certificate> certMap = new LinkedHashMap<>();

        // hierarchy map: subject DN -> issuer DN
        Map<String, String> parentMap = new HashMap<>();

        // reverse hierarchy map: issuer DN -> subject DN
        Map<String, String> childMap = new HashMap<>();

        // build maps
        for (java.security.cert.X509Certificate cert : certs) {

            String subjectDN = cert.getSubjectDN().toString();
            String issuerDN = cert.getIssuerDN().toString();

            if (certMap.containsKey(subjectDN)) {
                throw new Exception("Duplicate certificate: " + subjectDN);
            }

            certMap.put(subjectDN, cert);

            // ignore self-signed certificate when building hierarchy maps
            if (subjectDN.equals(issuerDN)) continue;

            if (childMap.containsKey(issuerDN)) {
                throw new Exception("Branched chain: " + issuerDN);
            }

            parentMap.put(subjectDN, issuerDN);
            childMap.put(issuerDN, subjectDN);
        }

        if (verbose) {
            System.out.println("Certificates:");
            for (String subjectDN : certMap.keySet()) {
                System.out.println(" - " + subjectDN);

                String parent = parentMap.get(subjectDN);
                if (parent != null) System.out.println("   parent: " + parent);

                String child = childMap.get(subjectDN);
                if (child != null) System.out.println("   child: " + child);
            }
        }

        // find leaf cert
        List<String> leafCerts = new ArrayList<>();

        for (String subjectDN : certMap.keySet()) {

            // if cert has a child, skip
            if (childMap.containsKey(subjectDN)) continue;

            // found leaf cert
            leafCerts.add(subjectDN);
        }

        if (leafCerts.isEmpty()) {
            throw new Exception("Unable to find leaf certificate");

        } else if (leafCerts.size() > 1) {
            StringBuilder sb = new StringBuilder();
            for (String subjectDN : leafCerts) {
                if (sb.length() > 0) sb.append(", ");
                sb.append("[" + subjectDN + "]");
            }
            throw new Exception("Multiple leaf certificates: " + sb);
        }

        // build cert chain from leaf cert
        List<java.security.cert.X509Certificate> chain = new ArrayList<>();
        String current = leafCerts.get(0);

        while (current != null) {

            java.security.cert.X509Certificate cert = certMap.get(current);
            chain.add(cert);

            current = parentMap.get(current);
        }

        return chain.toArray(new java.security.cert.X509Certificate[chain.size()]);
    }

    public void importPKCS7(
            String pkcs7Path,
            String nickname,
            String trustAttributes) throws Exception {

        if (nickname == null) {
            throw new Exception("Missing certificate nickname.");
        }

        if (verbose) System.out.println("Loading PKCS #7 data from " + pkcs7Path);
        String str = new String(Files.readAllBytes(Paths.get(pkcs7Path))).trim();
        PKCS7 pkcs7 = new PKCS7(str);

        java.security.cert.X509Certificate[] certs = pkcs7.getCertificates();
        if (certs == null || certs.length == 0) {
            if (verbose) System.out.println("No certificates to import");
            return;
        }

        // sort certs from leaf to root
        certs = sort(certs);

        CryptoManager manager = CryptoManager.getInstance();

        // Import certs with preferred nicknames.
        // NOTE: JSS/NSS may assign different nickname.

        List<X509Certificate> importedCerts = new ArrayList<>();
        int i = 0;

        for (java.security.cert.X509Certificate cert : certs) {

            String preferredNickname = nickname + (i == 0 ? "" : " #" + (i + 1));
            if (verbose) System.out.println("Importing certificate " + preferredNickname + ": " + cert.getSubjectDN());

            X509Certificate importedCert = manager.importCertPackage(cert.getEncoded(), preferredNickname);
            importedCerts.add(importedCert);

            String importedNickname = importedCert.getNickname();
            if (verbose) System.out.println("Certificate imported as " + importedNickname);

            if (importedNickname.equals(preferredNickname)) {
                // Cert was imported with preferred nickname, increment counter.
                i++;
            }
        }

        X509Certificate cert = importedCerts.get(0);
        if (verbose) {
            System.out.println("Leaf cert: " + cert.getNickname());
        }

        if (trustAttributes != null) {
            if (verbose) {
                System.out.println(
                        "Setting trust attributes to " + trustAttributes);
            }
            setTrustAttributes(cert, trustAttributes);
        }

        X509Certificate[] chain = manager.buildCertificateChain(cert);
        if (chain.length == 1 && trustAttributes != null) {
            // Cert has no parent cert and is already trusted.
            return;
        }

        // Trust root cert.
        X509Certificate root = chain[chain.length - 1];
        if (verbose) {
            System.out.println("Root cert: " + root.getNickname());
            System.out.println(
                    "Setting trust attributes to CT,C,C");
        }
        setTrustAttributes(root, "CT,C,C");
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
    }
}
