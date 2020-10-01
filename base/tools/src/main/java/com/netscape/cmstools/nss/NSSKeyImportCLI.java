//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.key.KeyData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class NSSKeyImportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSKeyImportCLI.class);

    public NSSKeyCLI nssKeyCLI;

    public NSSKeyImportCLI(NSSKeyCLI nssKeyCLI) {
        super("import", "Import key into NSS database", nssKeyCLI);
        this.nssKeyCLI = nssKeyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <key nickname>", options);
    }

    public void createOptions() {
        Option option = new Option(null, "input", true, "File that contains the key to be imported");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "wrapper", true, "Nickname of the wrapper certificate");
        option.setArgName("nickname");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing key nickname");
        }

        String nickname = cmdArgs[0];
        String inputFile = cmd.getOptionValue("input");
        String wrapperNickname = cmd.getOptionValue("wrapper");

        if (wrapperNickname == null) {
            throw new Exception("Missing wrapper certificate nickname");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        byte[] bytes;
        if (inputFile == null) {
            // read from standard input
            bytes = IOUtils.toByteArray(System.in);
        } else {
            // read from file
            bytes = Files.readAllBytes(Paths.get(inputFile));
        }

        KeyData keyData = KeyData.fromJSON(new String(bytes));

        logger.info("Wrapped session key: " + keyData.getWrappedPrivateData());
        logger.info("Wrapped secret key: " + keyData.getAdditionalWrappedPrivateData());

        byte[] wrappedSessionKey = Utils.base64decode(keyData.getWrappedPrivateData());
        byte[] wrappedSecretKey = Utils.base64decode(keyData.getAdditionalWrappedPrivateData());

        CryptoUtil.importSharedSecret(wrappedSessionKey, wrappedSecretKey, wrapperNickname, nickname);
    }
}
