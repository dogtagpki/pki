//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.cmstools.cli.MainCLI;

public class NSSCertShowCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertShowCLI.class);

    public NSSCertShowCLI(NSSCertCLI nssCertCLI) {
        super("show", "Show certificate", nssCertCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <nickname>", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        String nickname = null;

        if (cmdArgs.length < 1) {
            throw new Exception("Missing certificate nickname");
        }

        nickname = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate cert = cm.findCertByNickname(nickname);

        NSSCertCLI.printCertInfo(cert);
    }
}
