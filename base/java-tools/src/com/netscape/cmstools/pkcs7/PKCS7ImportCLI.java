//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.pkcs7;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;

import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class PKCS7ImportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKCS7ImportCLI.class);

    public PKCS7CLI pkcs7CLI;

    public PKCS7ImportCLI(PKCS7CLI pkcs7CLI) {
        super("import", "Import PKCS #7 file into NSS database", pkcs7CLI);
        this.pkcs7CLI = pkcs7CLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "input-file", true, "Input file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "trust-flags", true, "Root certificate trust flags");
        option.setArgName("flags");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String filename = cmd.getOptionValue("input-file");

        if (filename == null) {
            throw new Exception("Missing input file");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        logger.info("Loading PKCS #7 data from " + filename);
        String str = new String(Files.readAllBytes(Paths.get(filename))).trim();

        PKCS7 pkcs7 = new PKCS7(str);
        X509Certificate[] certs = pkcs7.getCertificates();

        org.mozilla.jss.crypto.X509Certificate[] nssCerts = CryptoUtil.importPKCS7(pkcs7);
        org.mozilla.jss.crypto.X509Certificate rootCert = nssCerts[0];

        String trustFlags = cmd.getOptionValue("trust-flags");
        if (trustFlags != null) {
            CryptoUtil.setTrustFlags(rootCert, trustFlags);
        }
    }
}
