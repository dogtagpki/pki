//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.nss.NSSExtensionGenerator;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.MainCLI;

public class NSSCertIssueCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertIssueCLI.class);

    public NSSCertIssueCLI(NSSCertCLI nssCertCLI) {
        super("issue", "Issue certificate", nssCertCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "issuer", true, "Issuer nickname (default is self-signed)");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "csr", true, "Certificate signing request");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "ext", true, "Certificate extensions configuration");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "subjectAltName", true, "Subject alternative name");
        option.setArgName("value");
        options.addOption(option);

        option = new Option(null, "serial", true, "Serial number (default is 128-bit random number)");
        option.setArgName("number");
        options.addOption(option);

        option = new Option(null, "months-valid", true, "DEPRECATED: Months valid");
        option.setArgName("months");
        options.addOption(option);

        option = new Option(null, "validity-length", true, "Validity length (default: 3)");
        option.setArgName("length");
        options.addOption(option);

        option = new Option(null, "validity-unit", true, "Validity unit: minute, hour, day, month (default), year");
        option.setArgName("unit");
        options.addOption(option);

        option = new Option(null, "hash", true, "Hash algorithm (default is SHA256)");
        option.setArgName("hash");
        options.addOption(option);

        option = new Option(null, "cert", true, "Certificate");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String issuerNickname = cmd.getOptionValue("issuer");
        String csrFile = cmd.getOptionValue("csr");
        String extConf = cmd.getOptionValue("ext");
        String subjectAltName = cmd.getOptionValue("subjectAltName");
        String serialNumber = cmd.getOptionValue("serial");
        String monthsValid = cmd.getOptionValue("months-valid");
        String validityLengthStr = cmd.getOptionValue("validity-length", "3");
        String validityUnitStr = cmd.getOptionValue("validity-unit", "month");
        String hash = cmd.getOptionValue("hash", "SHA256");

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
        X509Key x509Key = pkcs10.getSubjectPublicKeyInfo();
        X500Name subjectName = pkcs10.getSubjectName();

        NSSExtensionGenerator generator = new NSSExtensionGenerator();
        Extensions extensions = null;

        if (extConf != null) {
            generator.init(extConf);
        }

        if (subjectAltName != null) {
            generator.setParameter("subjectAltName", subjectAltName);
        }

        extensions = generator.createExtensions(issuer, pkcs10);

        int validityLength;
        int validityUnit;

        if (monthsValid != null) {
            logger.warn("The --months-valid option has been deprecated. Use --validity-length and --validity-unit instead.");
            validityLength = Integer.valueOf(monthsValid);
            validityUnit = Calendar.MONTH;

        } else {
            validityLength = Integer.valueOf(validityLengthStr);
            validityUnit = NSSDatabase.validityUnitFromString(validityUnitStr);
        }

        String tokenName = clientConfig.getTokenName();

        X509Certificate cert = nssdb.createCertificate(
                tokenName,
                x509Key,
                subjectName,
                issuer,
                serialNumber,
                validityLength,
                validityUnit,
                hash,
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
