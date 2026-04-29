//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.codec.binary.Hex;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.nss.NSSExtensionGenerator;
import org.dogtagpki.util.cert.CRMFUtil;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.pkix.primitive.Name;

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

        super.createOptions();

        Option option = new Option(null, "type", true, "Request type: pkcs10 (default), crmf");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "subject", true, "Subject name");
        option.setArgName("name");
        options.addOption(option);

        options.addOption(null, "subject-encoding", false, "Enable attribute encoding in subject name");

        option = new Option(null, "token", true, "Security token name");
        option.setArgName("token");
        options.addOption(option);

        option = new Option(null, "key-id", true, "Key ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "key-id-file", true, "File containing key ID");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "key-type", true, "Key type: RSA (default), EC, MLDSA, MLKEM");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "key-size", true, "DEPRECATED: Key size");
        option.setArgName("size");
        options.addOption(option);

        option = new Option(null, "key-strength", true, "Key strength (RSA default: 2048, MLDSA default: 65, MLKEM default: 768)");
        option.setArgName("strength");
        options.addOption(option);

        options.addOption(null, "key-wrap", false, "Generate RSA key for wrapping/unwrapping.");

        option = new Option(null, "key-wrap-alg", true, "Key wrapping algorithm (default: " + KeyWrapAlgorithm.AES_KEY_WRAP_PAD + ")");
        option.setArgName("alg");
        options.addOption(option);

        option = new Option(null, "key-wrap-oaep", false, "Use OAEP key wrap algorithm.");
        options.addOption(option);

        option = new Option(null, "curve", true, "Elliptic curve name (default: nistp256)");
        option.setArgName("name");
        options.addOption(option);

        options.addOption(null, "ssl-ecdh", false, "Generate EC key for SSL with ECDH ECDSA.");

        options.addOption(null, "temporary", false, "Generate temporary key");

        option = new Option(null, "sensitive", true, "Generate sensitive key");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option(null, "extractable", true, "Generate extractable key");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option(null, "hash", true, "Hash function (default is SHA256 for RSA and EC key)");
        option.setArgName("name");
        options.addOption(option);

        option = new Option(null, "ext", true, "Certificate extensions configuration");
        option.setArgName("path");
        options.addOption(option);

        options.addOption(null, "skid", false, "Include SubjectKeyIdentifier extension");

        option = new Option(null, "subjectAltName", true, "Subject alternative name");
        option.setArgName("value");
        options.addOption(option);

        options.addOption(null, "pop", false, "Include Proof-of-Possession in CRMF request");

        option = new Option(null, "transport", true, "Transport certificate nickname");
        option.setArgName("nickname");
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

        String requestType = cmd.getOptionValue("type", "pkcs10");
        String requestFormat = cmd.getOptionValue("format");

        String subject = cmd.getOptionValue("subject");
        boolean subjectEncoding = cmd.hasOption("subject-encoding");

        String keyID = cmd.getOptionValue("key-id");
        String keyIDFile = cmd.getOptionValue("key-id-file");

        if (keyID == null && keyIDFile != null) {
            Path keyIDPath = Paths.get(keyIDFile);
            if (Files.exists(keyIDPath)) {
                // load key ID from file
                keyID = Files.readString(keyIDPath).strip();
            }
        }

        String keyType = cmd.getOptionValue("key-type", "RSA");

        String keyStrength = cmd.getOptionValue("key-strength");
        String keySize = cmd.getOptionValue("key-size");

        if (keyStrength == null && keySize != null) {
            logger.warn("The --key-size option has been deprecated. Use --key-strength instead.");
            keyStrength = keySize;
        }

        boolean keyWrap = cmd.hasOption("key-wrap");
        String keyWrapAlg = cmd.getOptionValue(
                "key-wrap-alg",
                KeyWrapAlgorithm.AES_KEY_WRAP_PAD.toString());
        boolean keyWrapOAEP = cmd.hasOption("key-wrap-oaep");
        String curve = cmd.getOptionValue("curve", "nistp256");
        boolean sslECDH = cmd.hasOption("ssl-ecdh");

        Boolean temporary = cmd.hasOption("temporary");

        String s = cmd.getOptionValue("sensitive");
        Boolean sensitive = null;
        if (s != null) {
            sensitive = Boolean.parseBoolean(s);
        }

        s = cmd.getOptionValue("extractable");
        Boolean extractable = null;
        if (s != null) {
            extractable = Boolean.parseBoolean(s);
        }

        String hash = cmd.getOptionValue("hash");
        String extConf = cmd.getOptionValue("ext");
        boolean skid = cmd.hasOption("skid");
        String subjectAltName = cmd.getOptionValue("subjectAltName");
        Boolean pop = cmd.hasOption("pop") ? true : null;

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ClientConfig clientConfig = mainCLI.getConfig();
        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        String tokenName = cmd.getOptionValue("token");
        if (tokenName == null) {
            tokenName = clientConfig.getTokenName();
        }
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        KeyPair keyPair;

        if (keyID != null) {

            if (keyID.startsWith("0x")) keyID = keyID.substring(2);
            if (keyID.length() % 2 == 1) keyID = "0" + keyID;

            keyPair = nssdb.loadKeyPair(token, Hex.decodeHex(keyID));
            keyType = keyPair.getPublic().getAlgorithm();

        } else if ("RSA".equalsIgnoreCase(keyType)) {

            if (keyStrength == null) keyStrength = "2048";

            keyPair = nssdb.createRSAKeyPair(
                    token,
                    Integer.parseInt(keyStrength),
                    keyWrap,
                    temporary,
                    sensitive,
                    extractable);

        } else if ("EC".equalsIgnoreCase(keyType)) {

            keyPair = nssdb.createECKeyPair(
                    token,
                    curve,
                    sslECDH,
                    temporary,
                    sensitive,
                    extractable);

        } else if ("MLDSA".equalsIgnoreCase(keyType)) {

            if (keyStrength == null) keyStrength = "65";

            keyPair = nssdb.createMLDSAKeyPair(
                    token,
                    Integer.parseInt(keyStrength),
                    temporary,
                    sensitive,
                    extractable);

        } else if ("MLKEM".equalsIgnoreCase(keyType)) {

            if (keyStrength == null) keyStrength = "768";

            keyPair = nssdb.createMLKEMKeyPair(
                    token,
                    Integer.parseInt(keyStrength),
                    temporary,
                    sensitive,
                    extractable);

        } else {
            throw new Exception("Unsupported key type: " + keyType);
        }

        if (keyID == null) {
            PK11PrivKey privateKey = (PK11PrivKey) keyPair.getPrivate();
            keyID = "0x" + Utils.HexEncode(privateKey.getUniqueID());
        }

        if (keyIDFile != null) {
            Path keyIDPath = Paths.get(keyIDFile);
            if (Files.notExists(keyIDPath)) {
                // store new key ID to file
                try (FileWriter out = new FileWriter(keyIDFile)) {
                    out.write(keyID);
                }
            }
        }

        NSSExtensionGenerator generator = new NSSExtensionGenerator();
        Extensions extensions = null;

        if (extConf != null) {
            generator.init(extConf);
        }

        if (skid && generator.getParameter("subjectKeyIdentifier") == null) {
            generator.setParameter("subjectKeyIdentifier", "hash");
        }

        if (subjectAltName != null) {
            generator.setParameter("subjectAltName", subjectAltName);
        }

        X509Key subjectKey = CryptoUtil.createX509Key(keyPair.getPublic());
        extensions = generator.createExtensions(subjectKey);
        String keyAlgorithm = subjectKey.getAlgorithm();

        if (("RSA".equals(keyAlgorithm) || "EC".equals(keyAlgorithm))) {
            if (hash == null) {
                // by default use SHA256 for RSA and EC keys
                hash = "SHA256";
            }

        } else { // ML-DSA and ML-KEM
            if (hash != null) {
                throw new CLIException("Hash function not supported for " + keyAlgorithm + " keys");
            }
        }

        byte[] bytes;

        if ("pkcs10".equalsIgnoreCase(requestType)) {

            PKCS10 pkcs10 = nssdb.createPKCS10Request(
                    keyPair,
                    subject,
                    false,
                    hash,
                    extensions);

            if (requestFormat == null || "PEM".equalsIgnoreCase(requestFormat)) {
                bytes = CertUtil.toPEM(pkcs10).getBytes();

            } else if ("DER".equalsIgnoreCase(requestFormat)) {
                bytes = pkcs10.toByteArray();

            } else {
                throw new Exception("Unsupported format: " + requestFormat);
            }

        } else if ("crmf".equalsIgnoreCase(requestType)) {

            CryptoManager cm = CryptoManager.getInstance();

            String transportCertNickname = cmd.getOptionValue("transport");

            X509Certificate transportCert = null;
            if (transportCertNickname != null) {
                transportCert = cm.findCertByNickname(transportCertNickname);
            }

            Name subjectName = CryptoUtil.createName(subject, subjectEncoding);

            SignatureAlgorithm signatureAlgorithm;
            if ("RSA".equalsIgnoreCase(keyType)) {
                signatureAlgorithm = SignatureAlgorithm.RSASignatureWithSHA256Digest;

            } else if ("EC".equalsIgnoreCase(keyType)) {
                signatureAlgorithm = SignatureAlgorithm.ECSignatureWithSHA256Digest;

            } else if ("MLDSA".equalsIgnoreCase(keyType) || "ML-DSA".equalsIgnoreCase(keyType) || keyType.startsWith("ML-DSA-")) {
                if ("44".equals(keyStrength)) {
                    signatureAlgorithm = SignatureAlgorithm.MLDSA44;
                } else if ("65".equals(keyStrength)) {
                    signatureAlgorithm = SignatureAlgorithm.MLDSA65;
                } else if ("87".equals(keyStrength)) {
                    signatureAlgorithm = SignatureAlgorithm.MLDSA87;
                } else {
                    throw new CLIException("Unsupported ML-DSA key strength: " + keyStrength);
                }

            } else if ("MLKEM".equalsIgnoreCase(keyType) || "ML-KEM".equalsIgnoreCase(keyType) || keyType.startsWith("ML-KEM-")) {
                if (pop != null) {
                    throw new CLIException("ML-KEM does not support signature-based POP");
                }

                signatureAlgorithm = null;

            } else {
                throw new Exception("Unknown algorithm: " + keyType);
            }

            KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.fromString(keyWrapAlg);

            SEQUENCE crmfMsgs = nssdb.createCRMFRequest(
                    token,
                    keyPair,
                    subjectName,
                    transportCert,
                    signatureAlgorithm,
                    pop,
                    keyWrapAlgorithm,
                    keyWrapOAEP,
                    extensions);

            if (requestFormat == null || "PEM".equalsIgnoreCase(requestFormat)) {
                bytes = CRMFUtil.encodeCRMF(crmfMsgs).getBytes();

            } else if ("DER".equalsIgnoreCase(requestFormat)) {
                bytes = ASN1Util.encode(crmfMsgs);

            } else {
                throw new Exception("Unsupported format: " + requestFormat);
            }

        } else {
            throw new Exception("Unsupported request type: " + requestType);
        }

        String filename = cmd.getOptionValue("csr");

        if (filename != null) {
            Files.write(Paths.get(filename) , bytes);

        } else {
            System.out.write(bytes);
        }
    }
}
