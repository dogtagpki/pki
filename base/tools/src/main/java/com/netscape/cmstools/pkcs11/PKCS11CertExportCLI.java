//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.pkcs11;

import java.io.FileOutputStream;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.cert.Certificate;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.provider.java.security.JSSLoadStoreParameter;

import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class PKCS11CertExportCLI extends CommandCLI {

    public PKCS11CertCLI certCLI;

    public PKCS11CertExportCLI(PKCS11CertCLI certCLI) {
        super("export", "Export PKCS #11 certificate", certCLI);
        this.certCLI = certCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <Cert ID>", options);
    }

    public void createOptions() {
        Option option = new Option(null, "output-format", true, "Output format: pem (default), der");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "output-file", true, "Output file");
        option.setArgName("file");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing cert ID.");
        }

        String outputFormat = cmd.getOptionValue("output-format", "pem");
        String outputFile = cmd.getOptionValue("output-file");

        String alias = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        KeyStore ks = KeyStore.getInstance("pkcs11");
        ks.load(new JSSLoadStoreParameter(token));

        Certificate cert = ks.getCertificate(alias);

        if (cert == null) {
            throw new Exception("Certificate not found: " + alias);
        }

        byte[] bytes;

        if ("pem".equalsIgnoreCase(outputFormat)) {
            String b64 = Cert.HEADER + "\n" + Utils.base64encodeMultiLine(cert.getEncoded()) + Cert.FOOTER + "\n";
            bytes = b64.getBytes();

        } else if ("der".equalsIgnoreCase(outputFormat)) {
            bytes = cert.getEncoded();

        } else {
            throw new Exception("Unsupported format: " + outputFormat);
        }

        if (outputFile != null) {
            try (PrintStream out = new PrintStream(new FileOutputStream(outputFile))) {
                out.write(bytes);
            }

        } else {
            System.out.write(bytes);
        }
    }
}
