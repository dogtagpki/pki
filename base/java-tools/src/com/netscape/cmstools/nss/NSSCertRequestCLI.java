//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.MainCLI;

public class NSSCertRequestCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertRequestCLI.class);

    public NSSCertRequestCLI(NSSCertCLI nssCertCLI) {
        super("request", "Generate certificate signing request", nssCertCLI);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "subject", true, "Subject name");
        option.setArgName("name");
        options.addOption(option);

        option = new Option(null, "key-id", true, "Key ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "key-type", true, "Key type: RSA (default), EC, DSA");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "key-size", true, "RSA key size (default is 2048)");
        option.setArgName("size");
        options.addOption(option);

        option = new Option(null, "curve", true, "Elliptic curve name");
        option.setArgName("name");
        options.addOption(option);

        option = new Option(null, "hash", true, "Hash algorithm");
        option.setArgName("name");
        options.addOption(option);

        option = new Option(null, "csr", true, "Certificate signing request");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate signing request format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String subject = cmd.getOptionValue("subject");
        String keyID = cmd.getOptionValue("key-id");
        String keyType = cmd.getOptionValue("key-type");
        String keySize = cmd.getOptionValue("key-size");
        String curve = cmd.getOptionValue("curve");
        String hash = cmd.getOptionValue("hash");

        if (subject == null) {
            throw new Exception("Missing subject name");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ClientConfig clientConfig = mainCLI.getConfig();
        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        PKCS10 pkcs10 = nssdb.createRequest(
                subject,
                keyID,
                keyType,
                keySize,
                curve,
                hash);

        String format = cmd.getOptionValue("format");
        byte[] bytes;

        if (format == null || "PEM".equalsIgnoreCase(format)) {
            bytes = CertUtil.toPEM(pkcs10).getBytes();

        } else if ("DER".equalsIgnoreCase(format)) {
            bytes = pkcs10.toByteArray();

        } else {
            throw new Exception("Unsupported format: " + format);
        }

        String filename = cmd.getOptionValue("csr");

        if (filename != null) {
            Files.write(Paths.get(filename) , bytes);

        } else {
            System.out.write(bytes);
        }
    }
}
