//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.tks;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.system.TPSConnectorClient;

public class TKSKeyCreateCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TKSKeyCreateCLI.class);

    public TKSKeyCLI tksKeyCLI;

    public TKSKeyCreateCLI(TKSKeyCLI tksKeyCLI) {
        super("create", "Create key in TKS", tksKeyCLI);
        this.tksKeyCLI = tksKeyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <Key ID>", options);
    }

    public void createOptions() {
        Option option = new Option(null, "output-format", true, "Output format: text (default), json");
        option.setArgName("format");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing key ID");
        }

        String keyID = cmdArgs[0];
        String outputFormat = cmd.getOptionValue("output-format", "text");

        PKIClient client = getClient();
        TPSConnectorClient tpsConnectorClient = tksKeyCLI.getTPSConnectorClient();
        KeyData keyData = tpsConnectorClient.createSharedSecret(keyID);

        if ("json".equalsIgnoreCase(outputFormat)) {
            System.out.println(keyData.toJSON());

        } else {
            TKSKeyCLI.printKeyInfo(keyID, keyData);
        }
    }
}
