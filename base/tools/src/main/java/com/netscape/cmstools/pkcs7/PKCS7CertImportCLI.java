//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.pkcs7;

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class PKCS7CertImportCLI extends CommandCLI {

    private static Logger logger = LoggerFactory.getLogger(PKCS7CertImportCLI.class);

    public PKCS7CertCLI certCLI;

    public PKCS7CertImportCLI(PKCS7CertCLI certCLI) {
        super("import", "Import a certificate into a PKCS #7 file", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "pkcs7", true, "PKCS #7 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "input-file", true, "Path to certificate file to import");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "input-format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        options.addOption(null, "append", false, "Import into an existing PKCS #7 file");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String filename = cmd.getOptionValue("pkcs7");
        if (filename == null) {
            throw new Exception("Missing PKCS #7 file");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        CertificateChain certChain = new CertificateChain();

        Path path = Paths.get(filename);
        boolean append = cmd.hasOption("append");

        if (Files.exists(path) && append) {

            logger.info("Loading certificates from " + path);
            byte[] bytes = Files.readAllBytes(path);

            PKCS7 pkcs7 = new PKCS7(new String(bytes));
            for (X509Certificate cert : pkcs7.getCertificates()) {
                logger.info(" - " + cert.getSubjectDN());
            }

            certChain.addPKCS7(pkcs7);
        }

        String inputFilename = cmd.getOptionValue("input-file");
        byte[] bytes;
        if (inputFilename == null) {
            logger.info("Loading certificate from standard input");
            bytes = IOUtils.toByteArray(System.in);

        } else {
            logger.info("Loading certificate from " + inputFilename);
            bytes = Files.readAllBytes(Paths.get(inputFilename));
        }

        String inputFormat = cmd.getOptionValue("input-format", "PEM");
        if ("PEM".equalsIgnoreCase(inputFormat)) {

            CertificateChain inputChain = CertificateChain.fromPEMString(new String(bytes));
            for (X509Certificate cert : inputChain.getCertificates()) {
                logger.info(" - " + cert.getSubjectDN());
            }

            certChain.addCertificateChain(inputChain);

        } else if ("DER".equalsIgnoreCase(inputFormat)) {

            X509CertImpl cert = new X509CertImpl(bytes);
            logger.info(" - " + cert.getSubjectDN());

            certChain.addCertificate(cert);

        } else {
            throw new Exception("Unsupported format: " + inputFormat);
        }

        logger.info("Storing certificates into " + path);
        PKCS7 pkcs7 = certChain.toPKCS7();

        for (X509Certificate cert : pkcs7.getCertificates()) {
            logger.info("- " + cert.getSubjectDN());
        }

        try (PrintWriter os = new PrintWriter(path.toFile())) {
            os.print(pkcs7.toPEMString());
        }
    }
}
