//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.key.KeyData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class NSSKeyExportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSKeyExportCLI.class);

    public NSSKeyCLI nssKeyCLI;

    public NSSKeyExportCLI(NSSKeyCLI nssKeyCLI) {
        super("export", "Export key from NSS database", nssKeyCLI);
        this.nssKeyCLI = nssKeyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <key nickname>", options);
    }

    public void createOptions() {
        Option option = new Option(null, "output", true, "File to store the exported key");
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
        String outputFile = cmd.getOptionValue("output");
        String wrapperNickname = cmd.getOptionValue("wrapper");

        if (wrapperNickname == null) {
            throw new Exception("Missing wrapper certificate nickname");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate cert = cm.findCertByNickname(wrapperNickname);
        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());

        SymmetricKey tempKey = CryptoUtil.createDes3SessionKeyOnInternal();

        List<byte[]> listWrappedKeys = CryptoUtil.exportSharedSecret(nickname, certImpl, tempKey);
        byte[] wrappedSessionKey = listWrappedKeys.get(0);
        byte[] wrappedKey = listWrappedKeys.get(1);

        KeyData keyData = new KeyData();
        keyData.setWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSessionKey));
        keyData.setAdditionalWrappedPrivateData(Utils.base64encodeSingleLine(wrappedKey));

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
