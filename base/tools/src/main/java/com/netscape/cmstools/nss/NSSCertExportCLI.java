//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.FileOutputStream;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;

import com.netscape.cmstools.cli.MainCLI;

public class NSSCertExportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertExportCLI.class);

    public NSSCertExportCLI(NSSCertCLI nssCertCLI) {
        super("export", "Export certificate", nssCertCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <nickname> [path]", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "output-file", true, "Output file path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER, RAW");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "with-chain", false, "Export with certificate chain from NSS DB");
        option.setArgName("with-chain");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        String nickname = null;
        String path = null;

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing required positional argument: nickname");
        }
        nickname = cmdArgs[0];

        if (cmdArgs.length >= 2) {
            logger.warn("The optional positional path argument has been deprecated. Use the --output-file option instead.");
            path = cmdArgs[1];
        }

        String outputFile = cmd.getOptionValue("output-file");
        if (outputFile != null) {
            path = outputFile;
        }

        String format = cmd.getOptionValue("format", "PEM").toUpperCase();
        boolean chain = cmd.hasOption("with-chain");

        if (!format.equals("PEM") && !format.equals("DER") && !format.equals("RAW")) {
            throw new CLIException("Unknown type of output format: " + format);
        }

        if (chain && format.equals("DER")) {
            throw new CLIException("Unable to write chain of DER-encoded certificates; use PEM instead.");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        X509Certificate[] certs;

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509", "Mozilla-JSS");
        JSSKeyManager km = (JSSKeyManager) kmf.getKeyManagers()[0];

        if (chain) {
            certs = km.getCertificateChain(nickname);
            if (certs == null) {
                throw new CLIException("Certificate chain not found: " + nickname);
            }
        } else {
            PK11Cert cert = (PK11Cert) km.getCertificate(nickname);
            if (cert == null) {
                throw new CLIException("Certificate not found: " + nickname);
            }
            certs = new X509Certificate[] { cert };
        }

        byte[] output = null;

        if (format.equals("RAW")) {
            StringBuffer buffer = new StringBuffer();
            for (X509Certificate cert : certs) {
                buffer.append(cert.toString());
            }

            output = buffer.toString().getBytes();

        } else if (format.equals("PEM")) {
            StringBuffer buffer = new StringBuffer();

            for (X509Certificate cert : certs) {
                byte[] encoded = cert.getEncoded();
                buffer.append(Cert.HEADER);
                buffer.append("\r\n");
                buffer.append(Utils.base64encodeMultiLine(encoded));
                buffer.append(Cert.FOOTER);
                buffer.append("\r\n");
            }

            output = buffer.toString().getBytes();

        } else if (format.equals("DER")) {
            for (X509Certificate cert : certs) {
                output = cert.getEncoded();
            }

        } else {
            throw new CLIException("Unsupported format: " + format);
        }

        if (path == null) {
            System.out.write(output);

        } else {
            try (FileOutputStream fos = new FileOutputStream(path)) {
                fos.write(output);
            }
        }
    }
}
