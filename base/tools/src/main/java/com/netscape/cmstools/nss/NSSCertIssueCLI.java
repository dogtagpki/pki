//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.nss.NSSExtensionGenerator;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.MainCLI;

public class NSSCertIssueCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertIssueCLI.class);

    public NSSCertIssueCLI(NSSCertCLI nssCertCLI) {
        super("issue", "Issue certificate", nssCertCLI);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "issuer", true, "Issuer nickname (default is self-signed)");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "csr", true, "Certificate signing request");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "ext", true, "Certificate extensions configuration");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "serial", true, "Serial number (default is random)");
        option.setArgName("number");
        options.addOption(option);

        option = new Option(null, "months-valid", true, "Months valid (default is 3)");
        option.setArgName("months");
        options.addOption(option);

        option = new Option(null, "cert", true, "Certificate");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String issuerNickname = cmd.getOptionValue("issuer");
        String csrFile = cmd.getOptionValue("csr");
        String extConf = cmd.getOptionValue("ext");
        String serialNumber = cmd.getOptionValue("serial");
        String monthsValid = cmd.getOptionValue("months-valid");

        if (csrFile == null) {
            throw new Exception("Missing certificate signing request");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ClientConfig clientConfig = mainCLI.getConfig();
        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        org.mozilla.jss.crypto.X509Certificate issuer;
        if (issuerNickname == null) {
            issuer = null;

        } else {
            CryptoManager cm = CryptoManager.getInstance();
            issuer = cm.findCertByNickname(issuerNickname);
        }

        String csrPEM = new String(Files.readAllBytes(Paths.get(csrFile)));
        byte[] csrBytes = CertUtil.parseCSR(csrPEM);
        PKCS10 pkcs10 = new PKCS10(csrBytes);

        CertificateExtensions extensions = null;
        if (extConf != null) {
            NSSExtensionGenerator generator = new NSSExtensionGenerator();
            generator.init(extConf);
            extensions = generator.createExtensions(issuer, pkcs10);
        }

        X509Certificate cert = nssdb.createCertificate(
                issuer,
                pkcs10,
                serialNumber,
                monthsValid == null ? null : new Integer(monthsValid),
                extensions);

        String format = cmd.getOptionValue("format");
        byte[] bytes;

        if (format == null || "PEM".equalsIgnoreCase(format)) {
            bytes = CertUtil.toPEM(cert).getBytes();

        } else if ("DER".equalsIgnoreCase(format)) {
            bytes = cert.getEncoded();

        } else {
            throw new Exception("Unsupported format: " + format);
        }

        String filename = cmd.getOptionValue("cert");

        if (filename != null) {
            Files.write(Paths.get(filename) , bytes);

        } else {
            System.out.write(bytes);
        }
    }
}
