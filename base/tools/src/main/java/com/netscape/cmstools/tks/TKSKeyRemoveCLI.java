//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.tks;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.TPSConnectorClient;

public class TKSKeyRemoveCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TKSKeyRemoveCLI.class);

    public TKSKeyCLI tksKeyCLI;

    public TKSKeyRemoveCLI(TKSKeyCLI tksKeyCLI) {
        super("del", "Remove key from TKS", tksKeyCLI);
        this.tksKeyCLI = tksKeyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <Key ID>", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing key ID");
        }

        String keyID = cmdArgs[0];

        PKIClient client = getClient();
        TPSConnectorClient tpsConnectorClient = tksKeyCLI.getTPSConnectorClient();
        tpsConnectorClient.deleteSharedSecret(keyID);
    }
}
