//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.tks;

import java.io.FileWriter;
import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.system.TPSConnectorClient;

public class TKSKeyExportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TKSKeyExportCLI.class);

    public TKSKeyCLI tksKeyCLI;

    public TKSKeyExportCLI(TKSKeyCLI tksKeyCLI) {
        super("export", "Export key from TKS", tksKeyCLI);
        this.tksKeyCLI = tksKeyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <Key ID>", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "output", true, "File to store the exported key");
        option.setArgName("path");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing key ID");
        }

        String keyID = cmdArgs[0];
        String outputFile = cmd.getOptionValue("output");

        PKIClient client = getClient();
        TPSConnectorClient tpsConnectorClient = tksKeyCLI.getTPSConnectorClient();
        KeyData keyData = tpsConnectorClient.getSharedSecret(keyID);

        logger.info("Wrapped session key: " + keyData.getWrappedPrivateData());
        logger.info("Wrapped secret key: " + keyData.getAdditionalWrappedPrivateData());

        if (outputFile != null) {
            try (FileWriter fw = new FileWriter(outputFile);
                    PrintWriter out = new PrintWriter(fw)) {
                out.println(keyData.toJSON());
            }

        } else {
            System.out.println(keyData.toJSON());
        }
    }
}
