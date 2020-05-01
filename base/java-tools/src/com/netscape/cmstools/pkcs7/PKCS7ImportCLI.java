//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.pkcs7;

import java.nio.file.Files;
import java.nio.file.Paths;

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

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nickname]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "input-file", true, "Input file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "trust-flags", true, "Trust flags");
        option.setArgName("flags");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        String nickname;
        if (cmdArgs.length > 0) {
            nickname = cmdArgs[0];
        } else {
            nickname = null;
        }

        String filename = cmd.getOptionValue("input-file");
        String trustFlags = cmd.getOptionValue("trust-flags");

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
        CryptoUtil.importPKCS7(pkcs7, nickname, trustFlags);
    }
}
