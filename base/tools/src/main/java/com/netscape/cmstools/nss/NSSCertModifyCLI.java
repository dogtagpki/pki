//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Cert;

import com.netscape.cmstools.cli.MainCLI;

public class NSSCertModifyCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertModifyCLI.class);

    public NSSCertModifyCLI(NSSCertCLI nssCertCLI) {
        super("mod", "Modify certificate", nssCertCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <nickname>", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "trust-flags", true, "Certificate trust flags");
        option.setArgName("flags");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing certificate nickname");
        }

        String nickname = cmdArgs[0];

        String trustFlags = cmd.getOptionValue("trust-flags");
        if (trustFlags == null) {
            throw new CLIException("Missing trust flags");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        CryptoManager cm = CryptoManager.getInstance();

        X509Certificate cert;
        try {
            cert = cm.findCertByNickname(nickname);
        } catch (ObjectNotFoundException e) {
            throw new CLIException("Certificate not found: " + nickname);
        }

        if (trustFlags != null) {
            try (PK11Cert pk11Cert = (PK11Cert) cert) {
                pk11Cert.setTrustFlags(trustFlags);
            }
        }
    }
}
