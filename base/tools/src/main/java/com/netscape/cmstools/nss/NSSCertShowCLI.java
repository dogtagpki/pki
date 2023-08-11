//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cert.CertificateInfo;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.MainCLI;

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
        Option option = new Option(null, "cert-file", true, "Certificate to show");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "cert-format", true, "Certificate format: PEM (default), DER");
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

    public X509Certificate findCertByCertFile(String certFile, String certFormat) throws Exception {

        logger.info("Loading cert from " + certFile);

        byte[] bytes = Files.readAllBytes(Paths.get(certFile));

        if ("PEM".equalsIgnoreCase(certFormat)) {
            bytes = Cert.parseCertificate(new String(bytes));

        } else if ("DER".equalsIgnoreCase(certFormat)) {
            // nothing to do

        } else {
            throw new CLIException("Unsupported certificate format: " + certFormat);
        }

        Certificate pkixCert;
        try (ByteArrayInputStream is = new ByteArrayInputStream(bytes)) {
            pkixCert = (Certificate) Certificate.getTemplate().decode(is);
        }

        CertificateInfo certInfo = pkixCert.getInfo();
        Name issuer = certInfo.getIssuer();
        INTEGER serialNumber = certInfo.getSerialNumber();

        logger.info("Searching for cert with:");
        logger.info("- issuer: " + issuer.getRFC1485());
        logger.info("- serial number: " + new CertId(serialNumber).toHexString());

        // CryptoManager doesn't have a method that calls CERT_FindCertByDERCert()
        // in NSS so for now just use findCertByIssuerAndSerialNumber().
        // TODO: Add CryptoManager.findCertByDERCert() to call CERT_FindCertByDERCert().

        try {
            CryptoManager cm = CryptoManager.getInstance();
            return cm.findCertByIssuerAndSerialNumber(
                    ASN1Util.encode(issuer),
                    serialNumber);

        } catch (ObjectNotFoundException e) {
            throw new CLIException("Certificate not found");
        }
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String certFile = cmd.getOptionValue("cert-file");
        String certFormat = cmd.getOptionValue("cert-format", "PEM");

        String[] cmdArgs = cmd.getArgs();
        String nickname = null;

        if (cmdArgs.length >= 1) {
            nickname = cmdArgs[0];
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        X509Certificate cert;

        if (certFile != null) {
            cert = findCertByCertFile(certFile, certFormat);

        } else if (nickname != null) {
            cert = findCertByNickname(nickname);

        } else {
            throw new CLIException("Missing certificate nickname or certificate file");
        }

        NSSCertCLI.printCertInfo(cert);
    }
}
