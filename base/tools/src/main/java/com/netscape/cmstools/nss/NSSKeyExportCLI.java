//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
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

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <key nickname>", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "output", true, "File to store the exported key");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "session-key-size", true, "Session key size (default: 128)");
        option.setArgName("size");
        options.addOption(option);

        option = new Option(null, "wrapper", true, "Nickname of the wrapper certificate");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "wrapper-cert", true, "Wrapper certificate file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null,"useOAEPKeyWrap", false, "Use OAEP Key Wrap to wrap exported key");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            printHelp();
            throw new Exception("Missing key nickname");
        }

        String nickname = cmdArgs[0];
        String outputFile = cmd.getOptionValue("output");
        String sessionKeySize = cmd.getOptionValue("session-key-size", "128");
        String wrapperNickname = cmd.getOptionValue("wrapper");
        String wrapperCert = cmd.getOptionValue("wrapper-cert");

        if (wrapperNickname == null && wrapperCert == null) {
            throw new CLIException("Missing wrapper certificate nickname or file");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();
        CryptoManager cm = CryptoManager.getInstance();

        byte[] bytes;
        if (wrapperNickname != null) {
            // get cert from NSS database
            X509Certificate cert = cm.findCertByNickname(wrapperNickname);
            bytes = cert.getEncoded();
        } else {
            // get cert from file
            bytes = Files.readAllBytes(Paths.get(wrapperCert));
            bytes = Cert.parseCertificate(new String(bytes));
        }

        X509CertImpl certImpl = new X509CertImpl(bytes);

	SymmetricKey tempKey = CryptoUtil.createAESSessionKeyOnInternal(Integer.parseInt(sessionKeySize));

        boolean useOAEPKeyWrap = cmd.hasOption("useOAEPKeyWrap");

        List<byte[]> listWrappedKeys = CryptoUtil.exportSharedSecret(nickname, certImpl, tempKey,useOAEPKeyWrap);

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
