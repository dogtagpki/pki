//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.codec.binary.Hex;
import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.nss.NSSExtensionGenerator;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs11.PK11PrivKey;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class NSSCertRequestCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertRequestCLI.class);

    public NSSCertRequestCLI(NSSCertCLI nssCertCLI) {
        super("request", "Generate certificate signing request", nssCertCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "subject", true, "Subject name");
        option.setArgName("name");
        options.addOption(option);

        option = new Option(null, "key-id", true, "Key ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "key-type", true, "Key type: RSA (default), EC");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "key-size", true, "RSA key size (default: 2048)");
        option.setArgName("size");
        options.addOption(option);

        options.addOption(null, "key-wrap", false, "Generate RSA key for wrapping/unwrapping.");

        option = new Option(null, "curve", true, "Elliptic curve name (default: nistp256)");
        option.setArgName("name");
        options.addOption(option);

        options.addOption(null, "ssl-ecdh", false, "Generate EC key for SSL with ECDH ECDSA.");

        option = new Option(null, "hash", true, "Hash algorithm (default: SHA256)");
        option.setArgName("name");
        options.addOption(option);

        option = new Option(null, "ext", true, "Certificate extensions configuration");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "subjectAltName", true, "Subject alternative name");
        option.setArgName("value");
        options.addOption(option);

        option = new Option(null, "csr", true, "Certificate signing request");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate signing request format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String subject = cmd.getOptionValue("subject");
        if (subject == null) {
            throw new Exception("Missing subject name");
        }

        String keyID = cmd.getOptionValue("key-id");
        String keyType = cmd.getOptionValue("key-type", "RSA");
        String keySize = cmd.getOptionValue("key-size", "2048");
        boolean keyWrap = cmd.hasOption("key-wrap");
        String curve = cmd.getOptionValue("curve", "nistp256");
        boolean sslECDH = cmd.hasOption("ssl-ecdh");
        String hash = cmd.getOptionValue("hash", "SHA256");
        String extConf = cmd.getOptionValue("ext");
        String subjectAltName = cmd.getOptionValue("subjectAltName");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ClientConfig clientConfig = mainCLI.getConfig();
        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        String tokenName = clientConfig.getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        KeyPair keyPair;

        if (keyID != null) {

            if (keyID.startsWith("0x")) keyID = keyID.substring(2);
            if (keyID.length() % 2 == 1) keyID = "0" + keyID;

            keyPair = nssdb.loadKeyPair(token, Hex.decodeHex(keyID));

        } else if ("RSA".equalsIgnoreCase(keyType)) {

            Usage[] usages = keyWrap ? CryptoUtil.RSA_KEYPAIR_USAGES : null;
            Usage[] usagesMask = keyWrap ? CryptoUtil.RSA_KEYPAIR_USAGES_MASK : null;

            keyPair = nssdb.createRSAKeyPair(
                    token,
                    Integer.parseInt(keySize),
                    usages,
                    usagesMask);

        } else if ("EC".equalsIgnoreCase(keyType)) {

            Usage[] usages = null;
            Usage[] usagesMask = sslECDH ? CryptoUtil.ECDH_USAGES_MASK : CryptoUtil.ECDHE_USAGES_MASK;

            keyPair = nssdb.createECKeyPair(
                    token,
                    curve,
                    usages,
                    usagesMask);

        } else {
            throw new Exception("Unsupported key type: " + keyType);
        }

        NSSExtensionGenerator generator = new NSSExtensionGenerator();
        Extensions extensions = null;

        if (extConf != null) {
            generator.init(extConf);
        }

        if (subjectAltName != null) {
            generator.setParameter("subjectAltName", subjectAltName);
        }

        X509Key subjectKey = CryptoUtil.createX509Key(keyPair.getPublic());
        extensions = generator.createExtensions(subjectKey);

        PK11PrivKey privateKey = (PK11PrivKey) keyPair.getPrivate();
        String keyAlgorithm = hash + "with" + privateKey.getType();

        PKCS10 pkcs10 = nssdb.createPKCS10Request(
                keyPair,
                subject,
                keyAlgorithm,
                extensions);

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
