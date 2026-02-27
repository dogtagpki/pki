//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.MainCLI;

public class NSSCertImportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertImportCLI.class);

    public NSSCertImportCLI(NSSCertCLI nssCertCLI) {
        super("import", "Import certificate", nssCertCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nickname]", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "cert", true, "Certificate to import");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "trust", true, "Trust flags");
        option.setArgName("flags");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        String nickname = null;

        if (cmdArgs.length >= 1) {
            nickname = cmdArgs[0];
        }

        String filename = cmd.getOptionValue("cert");
        String format = cmd.getOptionValue("format");
        String trustFlags = cmd.getOptionValue("trust");

        if (trustFlags == null)
            trustFlags = ",,";

        // initialize CLI in pki CLI
        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        // load input data
        byte[] bytes;
        if (filename == null) {
            // read from standard input
            bytes = IOUtils.toByteArray(System.in);

        } else {
            // read from file
            bytes = Files.readAllBytes(Paths.get(filename));
        }

        // load cert chain
        CertificateChain chain;
        if (format == null || "PEM".equalsIgnoreCase(format)) {
            // load a single PEM cert or multiple PEM certs
            chain = CertificateChain.fromPEMString(new String(bytes));

        } else if ("DER".equalsIgnoreCase(format)) {
            // load a single DER cert
            X509CertImpl cert = new X509CertImpl(bytes);
            chain = new CertificateChain(cert);

        } else {
            throw new Exception("Unsupported format: " + format);
        }

        // sort cert chain from root to leaf
        chain.sort();
        List<X509Certificate> certs = chain.getCertificates();
        int size = certs.size();
        logger.info("Loaded " + size + " certs");

        // use token name specified in --token option
        ClientConfig clientConfig = mainCLI.getConfig();
        String tokenName = clientConfig.getTokenName();
        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        if (nickname == null) {
            // import all certs without nickname
            for (int i = 0; i < size; i++) {
                X509Certificate cert = certs.get(i);
                nssdb.addCertificate(cert, trustFlags);
            }
            return;
        }

        // import non-leaf certs without nickname
        for (int i = 0; i < size - 1; i++) {
            X509Certificate cert = certs.get(i);
            nssdb.addCertificate(cert, trustFlags);
        }

        int i = nickname.indexOf(':');

        if (i >= 0) {
            // use token name specified in nickname
            tokenName = nickname.substring(0, i);
            nickname = nickname.substring(i + 1);
        }

        // import leaf cert with nickname
        X509Certificate cert = certs.get(size - 1);
        nssdb.addCertificate(tokenName, nickname, cert, trustFlags);
    }
}
