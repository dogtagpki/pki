//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.pkcs7;

import java.io.FileOutputStream;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class PKCS7ExportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKCS7ExportCLI.class);

    public PKCS7CLI pkcs7CLI;

    public PKCS7ExportCLI(PKCS7CLI pkcs7CLI) {
        super("export", "Export PKCS #7 file from NSS database", pkcs7CLI);
        this.pkcs7CLI = pkcs7CLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <nickname>", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "pkcs7", true, "PKCS #7 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "PKCS #7 format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        if (cmdArgs.length == 0) {
            throw new Exception("Missing certificate nickname");
        }

        String nickname = cmdArgs[0];

        String filename = cmd.getOptionValue("pkcs7");
        String format = cmd.getOptionValue("format", "PEM").toUpperCase();

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        logger.info("Loading certificate chain from NSS database");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509", "Mozilla-JSS");
        JSSKeyManager km = (JSSKeyManager) kmf.getKeyManagers()[0];

        X509Certificate[] certs = km.getCertificateChain(nickname);
        if (certs == null || certs.length == 0) {
            throw new Exception("Certificate not found: " + nickname);
        }

        CertificateChain certChain = new CertificateChain(certs);
        certChain.sort();

        for (X509Certificate cert : certChain.getCertificates()) {
            logger.info("- " + cert.getSubjectDN());
        }

        PKCS7 pkcs7 = certChain.toPKCS7();
        byte[] bytes;

        if (format.equals("PEM")) {
            bytes = pkcs7.toPEMString().getBytes();

        } else if (format.equals("DER")) {
            bytes = pkcs7.getBytes();

        } else {
            throw new Exception("Unsupported format: " + format);
        }

        if (filename == null) {
            System.out.write(bytes);

        } else {
            try (FileOutputStream fos = new FileOutputStream(filename)) {
                fos.write(bytes);
            }
        }
    }
}
