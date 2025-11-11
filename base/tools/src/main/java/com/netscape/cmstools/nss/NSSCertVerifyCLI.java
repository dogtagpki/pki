//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.dogtagpki.cert.PKITrustManager;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CertificateUsage;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.cmstools.cli.MainCLI;

public class NSSCertVerifyCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertVerifyCLI.class);

    public NSSCertVerifyCLI(NSSCertCLI nssCertCLI) {
        super("verify", "Verify certificate", nssCertCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nickname]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "cert", true, "Certificate to verify");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        StringBuilder usages = new StringBuilder();
        Iterator<CertificateUsage> usage = CertificateUsage.getCertificateUsages();
        while (usage.hasNext()) {
            if (!usages.isEmpty()) usages.append(", ");
            usages.append(usage.next());
        }

        option = new Option(null, "cert-usage", true, "Certificate usage: " + usages);
        option.setArgName("usage");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String certFile = cmd.getOptionValue("cert");
        String certFormat = cmd.getOptionValue("format", "PEM");

        String[] cmdArgs = cmd.getArgs();
        String nickname = null;

        if (cmdArgs.length >= 1) {
            nickname = cmdArgs[0];
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        X509Certificate cert;

        if (nickname != null) {
            // get cert from NSS database
            CryptoManager cm = CryptoManager.getInstance();
            cert = cm.findCertByNickname(nickname);

        } else {
            byte[] bytes;
            if (certFile != null) {
                // get cert from file
                bytes = Files.readAllBytes(Paths.get(certFile));

            } else {
                // get cert from standard input
                bytes = IOUtils.toByteArray(System.in);
            }

            if ("PEM".equalsIgnoreCase(certFormat)) {
                bytes = Cert.parseCertificate(new String(bytes));

            } else if ("DER".equalsIgnoreCase(certFormat)) {
                // nothing to do

            } else {
                throw new CLIException("Unsupported certificate format: " + certFormat);
            }

            cert = new X509CertImpl(bytes);
        }

        PKITrustManager tm = new PKITrustManager();

        try {
            tm.checkCert(cert);

        } catch (Exception e) {
            throw new CLIException("Invalid certificate: " + e.getMessage());
        }

        String certUsage = cmd.getOptionValue("cert-usage");

        if (nickname != null && certUsage != null) {
            try {
                // validate specified cert usage
                CertUtil.verifyCertificateUsage(nickname, certUsage);

            } catch (Exception e) {
                throw new CLIException("Invalid certificate: " + e.getMessage());
            }
        }
    }
}
