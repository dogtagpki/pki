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
import org.apache.commons.io.IOUtils;
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

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nickname]", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "pkcs7", true, "PKCS #7 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "input-file", true, "DEPRECATED: PKCS #7 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "trust", true, "Trust flags");
        option.setArgName("flags");
        options.addOption(option);

        option = new Option(null, "trust-flags", true, "DEPRECATED: Trust flags");
        option.setArgName("flags");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        String nickname;
        if (cmdArgs.length > 0) {
            nickname = cmdArgs[0];
        } else {
            nickname = null;
        }

        String filename = cmd.getOptionValue("pkcs7");
        if (filename == null) {
            filename = cmd.getOptionValue("input-file");
            if (filename != null) {
                logger.warn("The --input-file has been deprecated. Use --pkcs7 instead.");
            }
        }

        String trustFlags = cmd.getOptionValue("trust");
        if (trustFlags == null) {
            trustFlags = cmd.getOptionValue("trust-flags");
            if (trustFlags != null) {
                logger.warn("The --trust-flags has been deprecated. Use --trust instead.");
            }
        }

        String input;
        if (filename == null) {
            logger.info("Loading PKCS #7 data from standard input");
            input = IOUtils.toString(System.in, "UTF-8").trim();

        } else {
            logger.info("Loading PKCS #7 data from " + filename);
            input = new String(Files.readAllBytes(Paths.get(filename))).trim();
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKCS7 pkcs7 = new PKCS7(input);
        for (X509Certificate cert : pkcs7.getCertificates()) {
            logger.info("- " + cert.getSubjectDN());
        }

        CryptoUtil.importPKCS7(pkcs7, nickname, trustFlags);
    }
}
