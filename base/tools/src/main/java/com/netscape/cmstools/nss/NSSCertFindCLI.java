//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cert.CertificateInfo;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class NSSCertFindCLI extends CommandCLI {

    public NSSCertFindCLI(NSSCertCLI certCLI) {
        super("find", "Find certificates", certCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "cert", true, "Certificate to find");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);
    }

    public X509Certificate findCertByDERCert(byte[] derCert) throws Exception {

        Certificate pkixCert;
        try (ByteArrayInputStream is = new ByteArrayInputStream(derCert)) {
            pkixCert = (Certificate) Certificate.getTemplate().decode(is);
        }

        CertificateInfo certInfo = pkixCert.getInfo();
        Name issuer = certInfo.getIssuer();
        INTEGER serialNumber = certInfo.getSerialNumber();

        logger.info("Searching for cert with:");
        logger.info("- issuer: " + issuer.getRFC1485());
        logger.info("- serial number: " + new CertId(serialNumber).toHexString());

        CryptoManager cm = CryptoManager.getInstance();

        // CryptoManager doesn't have a method that calls CERT_FindCertByDERCert()
        // in NSS so for now just use findCertByIssuerAndSerialNumber().
        // TODO: Add CryptoManager.findCertByDERCert() to call CERT_FindCertByDERCert().

        return cm.findCertByIssuerAndSerialNumber(
                ASN1Util.encode(issuer),
                serialNumber);
    }

    public Collection<X509Certificate> findAllCerts() throws Exception {

        logger.info("Searching for all certs");
        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        CryptoStore store = token.getCryptoStore();

        return Arrays.asList(store.getCertificates());
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String filename = cmd.getOptionValue("cert");
        String format = cmd.getOptionValue("format");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        Collection<X509Certificate> certs;

        if (filename != null) {

            // load cert from file
            byte[] bytes = Files.readAllBytes(Paths.get(filename));

            if (format == null || "PEM".equalsIgnoreCase(format)) {
                bytes = Cert.parseCertificate(new String(bytes));

            } else if ("DER".equalsIgnoreCase(format)) {
                // nothing to do

            } else {
                throw new Exception("Unsupported format: " + format);
            }

            certs = new ArrayList<>();
            try {
                X509Certificate x509cert = findCertByDERCert(bytes);
                certs.add(x509cert);

            } catch (ObjectNotFoundException e) {
                logger.info("Cert not found");
            }

        } else {
            certs = findAllCerts();
        }

        boolean first = true;

        for (X509Certificate cert : certs) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            NSSCertCLI.printCertInfo(cert);
        }
    }
}
