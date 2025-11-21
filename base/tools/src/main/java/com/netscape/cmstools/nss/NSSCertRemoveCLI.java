//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class NSSCertRemoveCLI extends CommandCLI {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertRemoveCLI.class);

    public NSSCertRemoveCLI(NSSCertCLI nssCertCLI) {
        super("del", "Remove certificate", nssCertCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <nickname>", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        options.addOption(null, "remove-key", false, "Remove key");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing certificate nickname");
        }

        String nickname = cmdArgs[0];

        boolean removeKey = cmd.hasOption("remove-key");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        CryptoUtil.deleteCertificates(nickname, removeKey);
    }
}
