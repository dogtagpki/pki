//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.tks;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.system.TPSConnectorClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class TKSKeyReplaceCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TKSKeyReplaceCLI.class);

    public TKSKeyCLI tksKeyCLI;

    public TKSKeyReplaceCLI(TKSKeyCLI tksKeyCLI) {
        super("replace", "Replace key in TKS", tksKeyCLI);
        this.tksKeyCLI = tksKeyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <Key ID>", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "output-format", true, "Output format: text (default), json");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing key ID");
        }

        String keyID = cmdArgs[0];
        String outputFormat = cmd.getOptionValue("output-format", "text");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = tksKeyCLI.tksCLI.getSubsystemClient(client);
        TPSConnectorClient tpsConnectorClient = new TPSConnectorClient(subsystemClient);
        KeyData keyData = tpsConnectorClient.replaceSharedSecret(keyID);

        if ("json".equalsIgnoreCase(outputFormat)) {
            System.out.println(keyData.toJSON());

        } else {
            TKSKeyCLI.printKeyInfo(keyID, keyData);
        }
    }
}
