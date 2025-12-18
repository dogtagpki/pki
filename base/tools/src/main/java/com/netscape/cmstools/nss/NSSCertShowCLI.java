//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;

import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class NSSCertShowCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertShowCLI.class);

    public NSSCertShowCLI(NSSCertCLI nssCertCLI) {
        super("show", "Show certificate", nssCertCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nickname]", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "cert-file", true, "Certificate to show");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "cert-format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "output-file", true, "Output file path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json");
        option.setArgName("format");
        options.addOption(option);
    }

    public X509Certificate findCertByNickname(String nickname) throws Exception {

        logger.info("Searching for cert " + nickname);

        try {
            CryptoManager cm = CryptoManager.getInstance();
            return cm.findCertByNickname(nickname);

        } catch (ObjectNotFoundException e) {
            throw new CLIException("Certificate not found: " + nickname);
        }
    }

    public X509Certificate findCertByCertFile(
            CryptoStore cryptoStore,
            String certFile,
            String certFormat) throws Exception {

        logger.info("Searching for cert in " + certFile);

        byte[] bytes = Files.readAllBytes(Paths.get(certFile));

        if ("PEM".equalsIgnoreCase(certFormat)) {
            bytes = Cert.parseCertificate(new String(bytes));

        } else if ("DER".equalsIgnoreCase(certFormat)) {
            // nothing to do

        } else {
            throw new CLIException("Unsupported certificate format: " + certFormat);
        }

        X509Certificate cert = cryptoStore.findCert(bytes);

        if (cert == null) {
            throw new CLIException("Certificate not found: " + certFile);
        }

        return cert;
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String certFile = cmd.getOptionValue("cert-file");
        String certFormat = cmd.getOptionValue("cert-format", "PEM");
        String outputFormat = cmd.getOptionValue("output-format", "text");

        String[] cmdArgs = cmd.getArgs();
        String nickname = null;

        if (cmdArgs.length >= 1) {
            nickname = cmdArgs[0];
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        CryptoStore cryptoStore = token.getCryptoStore();

        X509Certificate cert;

        if (certFile != null) {
            cert = findCertByCertFile(cryptoStore, certFile, certFormat);

        } else if (nickname != null) {
            cert = findCertByNickname(nickname);

        } else {
            throw new CLIException("Missing certificate nickname or certificate file");
        }

        NSSCertInfo certInfo = NSSCertCLI.createCertInfo(cert);
        byte[] output;

        if ("json".equalsIgnoreCase(outputFormat)) {
            output = certInfo.toJSON().getBytes();

        } else if ("text".equalsIgnoreCase(outputFormat)) {
            try (StringWriter sb = new StringWriter();
                    PrintWriter out = new PrintWriter(sb)) {
                NSSCertCLI.printCertInfo(certInfo, out);
                output = sb.toString().getBytes();
            }

        } else {
            throw new CLIException("Unsupported output format: " + outputFormat);
        }

        String outputFile = cmd.getOptionValue("output-file");

        if (outputFile == null) {
            System.out.write(output);

        } else {
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(output);
            }
        }
    }
}
