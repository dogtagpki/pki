//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.MainCLI;

public class NSSCertImportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertImportCLI.class);

    public NSSCertImportCLI(NSSCertCLI nssCertCLI) {
        super("import", "Import certificate", nssCertCLI);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nickname]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "cert", true, "Certificate to import");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "trust", true, "Trust attributes");
        option.setArgName("attributes");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        String nickname = null;

        if (cmdArgs.length >= 1) {
            nickname = cmdArgs[0];
        }

        String filename = cmd.getOptionValue("cert");
        String format = cmd.getOptionValue("format");
        String trustAttributes = cmd.getOptionValue("trust");

        if (trustAttributes == null)
            trustAttributes = ",,";

        byte[] bytes;
        if (filename == null) {
            // read from standard input
            bytes = IOUtils.toByteArray(System.in);

        } else {
            // read from file
            bytes = Files.readAllBytes(Paths.get(filename));
        }

        if (format == null || "PEM".equalsIgnoreCase(format)) {
            bytes = Cert.parseCertificate(new String(bytes));

        } else if ("DER".equalsIgnoreCase(format)) {
            // nothing to do

        } else {
            throw new Exception("Unsupported format: " + format);
        }

        X509CertImpl cert = new X509CertImpl(bytes);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ClientConfig clientConfig = mainCLI.getConfig();
        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        if (nickname == null) {
            nssdb.addCertificate(cert, trustAttributes);

        } else {
            nssdb.addCertificate(nickname, cert, trustAttributes);
        }
    }
}
