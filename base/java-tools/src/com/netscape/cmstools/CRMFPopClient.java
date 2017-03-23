// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.io.FileUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.PrintableString;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.TeletexString;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.asn1.UniversalString;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.crmf.POPOSigningKey;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.HMACDigest;
import com.netscape.cmsutil.util.Utils;

import netscape.security.util.WrappingParams;
import netscape.security.x509.X500Name;

/**
 * A command-line utility used to generate a Certificate Request Message
 * Format (CRMF) request with proof of possesion (POP).
 *
 * <pre>
 * IMPORTANT:  The transport certificate file needs to be created to contain the
 *             transport certificate in its base64 encoded format.
 * </pre>
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class CRMFPopClient {

    public boolean verbose;

    // From https://www.rfc-editor.org/rfc/rfc7468.txt
    public static final String RFC7468_HEADER = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String RFC7468_TRAILER = "-----END CERTIFICATE REQUEST-----";

    public static Options createOptions() {

        Options options = new Options();

        Option option = new Option("d", true, "Security database location");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("p", true, "Security token password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option("h", true, "Security token name");
        option.setArgName("token");
        options.addOption(option);

        option = new Option("o", true, "Output file to store base-64 CRMF request");
        option.setArgName("output");
        options.addOption(option);

        option = new Option("n", true, "Subject DN");
        option.setArgName("subject DN");
        options.addOption(option);

        option = new Option("a", true, "Key algorithm");
        option.setArgName("algorithm");
        options.addOption(option);

        option = new Option("l", true, "Key length");
        option.setArgName("length");
        options.addOption(option);

        option = new Option("c", true, "ECC curve name");
        option.setArgName("curve");
        options.addOption(option);

        option = new Option("m", true, "CA server hostname and port");
        option.setArgName("hostname:port");
        options.addOption(option);

        option = new Option("f", true, "Certificate profile");
        option.setArgName("profile");
        options.addOption(option);

        option = new Option("u", true, "Username");
        option.setArgName("username");
        options.addOption(option);

        option = new Option("r", true, "Requestor");
        option.setArgName("requestor");
        options.addOption(option);

        option = new Option("q", true, "POP option");
        option.setArgName("POP option");
        options.addOption(option);

        option = new Option("b", true, "PEM transport certificate");
        option.setArgName("transport cert");
        options.addOption(option);

        option = new Option("k", true, "Attribute encoding");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option("x", true, "SSL certificate with ECDH ECDSA");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option("t", true, "Temporary");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option("s", true, "Sensitive");
        option.setArgName("sensitive");
        options.addOption(option);

        option = new Option("e", true, "Extractable");
        option.setArgName("extractable");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "help", false, "Show help message.");

        return options;
    }

    public static void printHelp() {

        System.out.println("Usage: CRMFPopClient [OPTIONS]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -d <database>                Security database location (default: current directory)");
        System.out.println("  -h <token>                   Security token name (default: internal)");
        System.out.println("  -p <password>                Security token password");
        System.out.println("  -n <subject DN>              Certificate subject DN");
        System.out.println("  -k <true|false>              Attribute value encoding in subject DN (default: false)");
        System.out.println("                               - true: enabled");
        System.out.println("                               - false: disabled");
        System.out.println("  -a <rsa|ec>                  Key algorithm (default: rsa)");
        System.out.println("                               - rsa: RSA");
        System.out.println("                               - ec: ECC");
        System.out.println("  -f <profile>                 Certificate profile");
        System.out.println("                               - RSA default: caEncUserCert");
        System.out.println("                               - ECC default: caEncECUserCert");
        System.out.println("  -q <POP option>              POP option (default: POP_SUCCESS)");
        System.out.println("                               - POP_NONE: without POP");
        System.out.println("                               - POP_SUCCESS: with valid POP");
        System.out.println("                               - POP_FAIL: with invalid POP (for testing)");
        System.out.println("  -b <transport cert>          PEM transport certificate (default: transport.txt)");
        System.out.println("  -v, --verbose                Run in verbose mode.");
        System.out.println("      --help                   Show help message.");
        System.out.println();
        System.out.println("With RSA algorithm the following options can be specified:");
        System.out.println("  -l <length>                  Key length (default: 2048)");
        System.out.println();
        System.out.println("With ECC algorithm the following options can be specified:");
        System.out.println("  -c <curve>                   ECC curve name (default: nistp256)");
        System.out.println("  -t <true|false>              Temporary (default: true)");
        System.out.println("                               - true: temporary (session)");
        System.out.println("                               - false: permanent (token)");
        System.out.println("  -s <-1|0|1>                  Sensitive (default: -1)");
        System.out.println("                               - -1: temporaryPairMode dependent");
        System.out.println("                               - 0: non-sensitive");
        System.out.println("                               - 1: sensitive");
        System.out.println("  -e <-1|0|1>                  Extractable (default: -1)");
        System.out.println("                               - -1: token dependent");
        System.out.println("                               - 0: non-extractable");
        System.out.println("                               - 1: extractable");
        System.out.println("  -x <true|false>              Certificate type (default: false)");
        System.out.println("                               - true: SSL certificate with ECDH ECDSA (reqires POP_NONE)");
        System.out.println("                               - false: otherwise");
        System.out.println();
        System.out.println("To store the CRMF request the following options are required:");
        System.out.println("  -o <output>                  Output file to store base-64 CRMF request");
        System.out.println();
        System.out.println("To submit the CRMF request the following options are required:");
        System.out.println("  -m <hostname:port>           CA server hostname and port");
        System.out.println("  -u <username>                Username");
        System.out.println("  -r <requestor>               Requestor");
        System.out.println();
        System.out.println("Available ECC curve names:");
        System.out.println("  nistp256 (secp256r1), nistp384 (secp384r1), nistp521 (secp521r1), nistk163 (sect163k1),");
        System.out.println("  sect163r1, nistb163 (sect163r2), sect193r1, sect193r2, nistk233 (sect233k1),");
        System.out.println("  nistb233 (sect233r1), sect239k1, nistk283 (sect283k1), nistb283 (sect283r1),");
        System.out.println("  nistk409 (sect409k1), nistb409 (sect409r1),nistk571 (sect571k1), nistb571 (sect571r1),");
        System.out.println("  secp160k1, secp160r1, secp160r2, secp192k1, nistp192 (secp192r1, prime192v1),");
        System.out.println("  secp224k1, nistp224 (secp224r1), secp256k1, prime192v2, prime192v3, prime239v1,");
        System.out.println("  prime239v2, prime239v3, c2pnb163v1, c2pnb163v2, c2pnb163v3, c2pnb176v1, c2tnb191v1,");
        System.out.println("  c2tnb191v2, c2tnb191v3, c2pnb208w1, c2tnb239v1, c2tnb239v2, c2tnb239v3, c2pnb272w1,");
        System.out.println("  c2pnb304w1, c2tnb359w1, c2pnb368w1, c2tnb431r1, secp112r1, secp112r2, secp128r1,");
        System.out.println("  secp128r2, sect113r1, sect113r2, sect131r1, sect131r2");
    }

    public static void printError(String message) {
        System.err.println("ERROR: " + message);
        System.err.println("Try 'CRMFPopClient --help' for more information.");
    }

    public static void main(String args[]) throws Exception {

        Options options = createOptions();
        CommandLine cmd = null;

        try {
            CommandLineParser parser = new PosixParser();
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            printError(e.getMessage());
            System.exit(1);
        }

        if (cmd.hasOption("help")) {
            printHelp();
            System.exit(0);
        }

        boolean verbose = cmd.hasOption("v");

        String databaseDir = cmd.getOptionValue("d", ".");
        String tokenPassword = cmd.getOptionValue("p");
        String tokenName = cmd.getOptionValue("h");

        String algorithm = cmd.getOptionValue("a", "rsa");
        int keySize = Integer.parseInt(cmd.getOptionValue("l", "2048"));

        String profileID = cmd.getOptionValue("f");
        String subjectDN = cmd.getOptionValue("n");
        boolean encodingEnabled = Boolean.parseBoolean(cmd.getOptionValue("k", "false"));

        String transportCertFilename = cmd.getOptionValue("b", "transport.txt");

        String popOption = cmd.getOptionValue("q", "POP_SUCCESS");

        String curve = cmd.getOptionValue("c", "nistp256");
        boolean sslECDH = Boolean.parseBoolean(cmd.getOptionValue("x", "false"));
        boolean temporary = Boolean.parseBoolean(cmd.getOptionValue("t", "true"));
        int sensitive = Integer.parseInt(cmd.getOptionValue("s", "-1"));
        int extractable = Integer.parseInt(cmd.getOptionValue("e", "-1"));

        String output = cmd.getOptionValue("o");

        String hostPort = cmd.getOptionValue("m");
        String username = cmd.getOptionValue("u");
        String requestor = cmd.getOptionValue("r");

        if (subjectDN == null) {
            printError("Missing subject DN");
            System.exit(1);
         }

        if (tokenPassword == null) {
            printError("Missing token password");
            System.exit(1);
         }

        if (algorithm.equals("rsa")) {
            if (cmd.hasOption("c")) {
                printError("Illegal parameter for RSA: -c");
                System.exit(1);
            }

            if (cmd.hasOption("t")) {
                printError("Illegal parameter for RSA: -t");
                System.exit(1);
            }

            if (cmd.hasOption("s")) {
                printError("Illegal parameter for RSA: -s");
                System.exit(1);
            }

            if (cmd.hasOption("e")) {
                printError("Illegal parameter for RSA: -e");
                System.exit(1);
            }

            if (cmd.hasOption("x")) {
                printError("Illegal parameter for RSA: -x");
                System.exit(1);
            }

        } else if (algorithm.equals("ec")) {
            if (cmd.hasOption("l")) {
                printError("Illegal parameter for ECC: -l");
                System.exit(1);
            }

            if (sensitive != 0 && sensitive != 1 && sensitive != -1) {
                printError("Illegal input parameters for -s: " + sensitive);
                System.exit(1);
            }

            if (extractable != 0 && extractable != 1 && extractable != -1) {
                printError("Illegal input parameters for -e: " + extractable);
                System.exit(1);
            }

        } else {
            printError("Invalid algorithm: " + algorithm);
            System.exit(1);
        }

        if (!popOption.equals("POP_SUCCESS") &&
                !popOption.equals("POP_FAIL") &&
                !popOption.equals("POP_NONE")) {
            printError("Invalid POP option: "+ popOption);
            System.exit(1);
        }

        if (profileID == null) {
            if (algorithm.equals("rsa")) {
                profileID = "caEncUserCert";

            } else if (algorithm.equals("ec")) {
                profileID = "caEncECUserCert";

            } else {
                throw new Exception("Unknown algorithm: " + algorithm);
            }
        }

        try {
            if (verbose) System.out.println("Initializing security database: " + databaseDir);
            CryptoManager.initialize(databaseDir);

            CryptoManager manager = CryptoManager.getInstance();

            CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
            tokenName = token.getName();
            manager.setThreadToken(token);

            Password password = new Password(tokenPassword.toCharArray());
            try {
                token.login(password);
            } catch (Exception e) {
                throw new Exception("Unable to login: " + e, e);
            }

            CRMFPopClient client = new CRMFPopClient();
            client.setVerbose(verbose);

            if (verbose) System.out.println("Loading transport certificate");
            String encoded = FileUtils.readFileToString(new File(transportCertFilename));
            encoded = Cert.normalizeCertStrAndReq(encoded);
            encoded = Cert.stripBrackets(encoded);
            byte[] transportCertData = Utils.base64decode(encoded);

            X509Certificate transportCert = manager.importCACertPackage(transportCertData);

            if (verbose) System.out.println("Parsing subject DN");
            Name subject = client.createName(subjectDN, encodingEnabled);

            if (subject == null) {
                subject = new Name();
                subject.addCommonName("Me");
                subject.addCountryName("US");
                subject.addElement(new AVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"),  new PrintableString("MyUid")));
            }

            if (verbose) System.out.println("Generating key pair");
            KeyPair keyPair;
            if (algorithm.equals("rsa")) {
                keyPair = CryptoUtil.generateRSAKeyPair(token, keySize);
            } else if (algorithm.equals("ec")) {
                keyPair = client.generateECCKeyPair(token, curve, sslECDH, temporary, sensitive, extractable);

            } else {
                throw new Exception("Unknown algorithm: " + algorithm);
            }

            if (verbose) System.out.println("Creating certificate request");
            CertRequest certRequest = client.createCertRequest(token, transportCert, algorithm, keyPair, subject);

            ProofOfPossession pop = null;

            if (!popOption.equals("POP_NONE")) {

                if (verbose) System.out.println("Creating signer");
                Signature signer = client.createSigner(token, algorithm, keyPair);

                if (popOption.equals("POP_SUCCESS")) {

                    ByteArrayOutputStream bo = new ByteArrayOutputStream();
                    certRequest.encode(bo);
                    signer.update(bo.toByteArray());

                } else if (popOption.equals("POP_FAIL")) {

                    byte[] data = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };

                    signer.update(data);
                }

                byte[] signature = signer.sign();

                if (verbose) System.out.println("Creating POP");
                pop = client.createPop(algorithm, signature);
            }

            if (verbose) System.out.println("Creating CRMF requrest");
            String request = client.createCRMFRequest(certRequest, pop);

            StringWriter sw = new StringWriter();
            try (PrintWriter out = new PrintWriter(sw)) {
                out.println(RFC7468_HEADER);
                out.println(request);
                out.println(RFC7468_TRAILER);
            }
            String csr = sw.toString();

            if (hostPort != null) {
                System.out.println("Submitting CRMF request to " + hostPort);
                client.submitRequest(
                        request,
                        hostPort,
                        username,
                        profileID,
                        requestor);

            } else if (output != null) {
                System.out.println("Storing CRMF requrest into " + output);
                try (FileWriter out = new FileWriter(output)) {
                    out.write(csr);
                }

            } else {
                System.out.println(csr);
            }

        } catch (Exception e) {
            if (verbose) e.printStackTrace();
            printError(e.getMessage());
            System.exit(1);
        }
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public KeyPair generateECCKeyPair(
            CryptoToken token,
            String curve,
            boolean sslECDH,
            boolean temporary,
            int sensitive,
            int extractable) throws Exception {
        /*
         * used with SSL server cert that does ECDH ECDSA
         *  ** can only be used with POP_NONE **
         */
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usagesMaskECDH = {
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN_RECOVER
        };

        /* used for other certs including SSL server cert that does ECDHE ECDSA */
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usagesMask = {
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DERIVE
        };

        return CryptoUtil.generateECCKeyPair(
                token.getName(),
                curve,
                null,
                sslECDH ? usagesMaskECDH : usagesMask,
                temporary,
                sensitive,
                extractable);
    }

    public CertRequest createCertRequest(
            CryptoToken token,
            X509Certificate transportCert,
            String algorithm,
            KeyPair keyPair,
            Name subject) throws Exception {
        EncryptionAlgorithm encryptAlg = EncryptionAlgorithm.AES_128_CBC_PAD;
        byte[] iv = CryptoUtil.getNonceData(encryptAlg.getIVLength());

        AlgorithmIdentifier aid;
        if (algorithm.equals("rsa")) {
            aid = new AlgorithmIdentifier(EncryptionAlgorithm.AES_128_CBC.toOID(), new OCTET_STRING(iv));
        } else if (algorithm.equals("ec")) {
            // TODO(alee) figure out what this should be for ECC
            aid = new AlgorithmIdentifier(new OBJECT_IDENTIFIER("1.2.840.10045.2.1"), new OCTET_STRING(iv));
        } else {
            throw new Exception("Unknown algorithm: " + algorithm);
        }

        WrappingParams params = new WrappingParams(
                SymmetricKey.AES, KeyGenAlgorithm.AES, 128,
                KeyWrapAlgorithm.RSA, encryptAlg,
                KeyWrapAlgorithm.AES_KEY_WRAP_PAD, null, null);

        PKIArchiveOptions opts = CryptoUtil.createPKIArchiveOptions(
                token,
                transportCert.getPublicKey(),
                (PrivateKey) keyPair.getPrivate(),
                params,
                aid);

        CertTemplate certTemplate = createCertTemplate(subject, keyPair.getPublic());

        SEQUENCE seq = new SEQUENCE();
        seq.addElement(new AVA(new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.5.1.4"), opts));

        OCTET_STRING ostr = createIDPOPLinkWitness();
        seq.addElement(new AVA(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness, ostr));

        return new CertRequest(new INTEGER(1), certTemplate, seq);
    }

    public OCTET_STRING createIDPOPLinkWitness() throws Exception {

        String secretValue = "testing";
        MessageDigest digest1 = MessageDigest.getInstance("SHA1");
        byte[] key1 = digest1.digest(secretValue.getBytes());

        /* Example of adding the POP link witness control to CRMF */
        byte[] b = {
            0x10, 0x53, 0x42, 0x24, 0x1a, 0x2a, 0x35, 0x3c,
            0x7a, 0x52, 0x54, 0x56, 0x71, 0x65, 0x66, 0x4c,
            0x51, 0x34, 0x35, 0x23, 0x3c, 0x42, 0x43, 0x45,
            0x61, 0x4f, 0x6e, 0x43, 0x1e, 0x2a, 0x2b, 0x31,
            0x32, 0x34, 0x35, 0x36, 0x55, 0x51, 0x48, 0x14,
            0x16, 0x29, 0x41, 0x42, 0x43, 0x7b, 0x63, 0x44,
            0x6a, 0x12, 0x6b, 0x3c, 0x4c, 0x3f, 0x00, 0x14,
            0x51, 0x61, 0x15, 0x22, 0x23, 0x5f, 0x5e, 0x69
        };

        MessageDigest digest2 = MessageDigest.getInstance("SHA1");
        HMACDigest hmacDigest = new HMACDigest(digest2, key1);
        hmacDigest.update(b);
        byte[] finalDigest = hmacDigest.digest();

        return new OCTET_STRING(finalDigest);
    }

    public CertTemplate createCertTemplate(Name subject, PublicKey publicKey) throws Exception {

        CertTemplate template = new CertTemplate();
        template.setVersion(new INTEGER(2));
        template.setSubject(subject);
        template.setPublicKey(new SubjectPublicKeyInfo(publicKey));

        return template;
    }

    public Signature createSigner(
            CryptoToken token,
            String algorithm,
            KeyPair keyPair) throws Exception {

        Signature signer;
        if (algorithm.equals("rsa")) {
            signer =  token.getSignatureContext(SignatureAlgorithm.RSASignatureWithMD5Digest);

        } else if (algorithm.equals("ec")) {
            signer =  token.getSignatureContext(SignatureAlgorithm.ECSignatureWithSHA1Digest);

        } else {
            throw new Exception("Unknown algorithm: " + algorithm);
        }

        signer.initSign((org.mozilla.jss.crypto.PrivateKey) keyPair.getPrivate());

        return signer;
    }

    public ProofOfPossession createPop(String algorithm, byte[] signature) throws Exception {

        AlgorithmIdentifier algorithmID;
        if (algorithm.equals("rsa")) {
            algorithmID = new AlgorithmIdentifier(SignatureAlgorithm.RSASignatureWithMD5Digest.toOID(), null);

        } else if (algorithm.equals("ec")) {
            algorithmID = new AlgorithmIdentifier(SignatureAlgorithm.ECSignatureWithSHA1Digest.toOID(), null);

        } else {
            throw new Exception("Unknown algorithm: " + algorithm);
        }

        POPOSigningKey popoKey = new POPOSigningKey(null, algorithmID, new BIT_STRING(signature, 0));
        return ProofOfPossession.createSignature(popoKey);
    }

    public String createCRMFRequest(
            CertRequest certRequest,
            ProofOfPossession pop) throws Exception {

        CertReqMsg crmfMessage = new CertReqMsg(certRequest, pop, null);
        //crmfMessage.verify();

        SEQUENCE seq = new SEQUENCE();
        seq.addElement(crmfMessage);

        byte[] encodedCrmfMessage = ASN1Util.encode(seq);
        return Utils.base64encode(encodedCrmfMessage);
    }

    public void submitRequest(
            String request,
            String hostPort,
            String username,
            String profileID,
            String requestor) throws Exception {

        String url = "http://" + hostPort + "/ca/ee/ca/profileSubmit"
                + "?cert_request_type=crmf"
                + "&cert_request=" + URLEncoder.encode(request, "UTF-8")
                + "&renewal=false"
                + "&xmlOutput=false"
                + "&profileId=" + URLEncoder.encode(profileID, "UTF-8")
                + "&SubId=profile";

        if (username != null) {
            url += "&uid=" + URLEncoder.encode(username, "UTF-8");
            url += "&sn_uid=" + URLEncoder.encode(username, "UTF-8");
        }

        if (requestor != null) {
            url += "&requestor_name=" + URLEncoder.encode(requestor, "UTF-8");
        }

        if (verbose) System.out.println("Opening " + url);

        DefaultHttpClient client = new DefaultHttpClient();
        HttpGet method = new HttpGet(url);
        try {
            HttpResponse response = client.execute(method);

            if (response.getStatusLine().getStatusCode() != 200) {
                throw new Exception("Error: " + response.getStatusLine());
            }

            processResponse(response);

        } finally {
            method.releaseConnection();
        }
    }

    public void processResponse(HttpResponse response) throws Exception {

        HttpEntity entity = response.getEntity();

        BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent()));

        if (verbose) System.out.println("--------------------");
        String line = null;
        String requestID = null;
        String status = null;
        String reason = null;
        while ((line = reader.readLine()) != null) {
            if (verbose) System.out.println(line);

            if (line.startsWith("requestList.requestId=")) {
                int i = line.indexOf("\"");
                int j = line.indexOf("\";", i+1);
                requestID = line.substring(i+1, j);

            } else if (line.startsWith("errorCode=")) {
                int i = line.indexOf("\"");
                int j = line.indexOf("\";", i+1);
                String errorCode = line.substring(i+1, j);

                if ("0".equals(errorCode)) {
                    status = "completed";

                } else if ("1".equals(errorCode)) {
                    status = "failed";

                } else if ("2".equals(errorCode)) {
                    status = "pending";

                } else if ("3".equals(errorCode)) {
                    status = "rejected";

                } else {
                    status = "unknown";
                }

            } else if (line.startsWith("errorReason=")) {
                int i = line.indexOf("\"");
                int j = line.indexOf("\";", i+1);
                reason = line.substring(i+1, j);
            }
        }
        if (verbose) System.out.println("--------------------");

        if (requestID != null) {
            System.out.println("Request ID: " + requestID);
        }

        if (status != null) {
            System.out.println("Request Status: " + status);
        }

        if (reason != null) {
            System.out.println("Reason: " + reason);
        }

        EntityUtils.consume(entity);
    }

    public boolean isEncoded(String elementValue) {

        if (elementValue == null) return false;

        return elementValue.startsWith("UTF8String:")
                || elementValue.startsWith("PrintableString:")
                || elementValue.startsWith("BMPString:")
                || elementValue.startsWith("TeletexString:")
                || elementValue.startsWith("UniversalString:");
    }

    public AVA createAVA(OBJECT_IDENTIFIER oid, int n, String elementValue) throws Exception {

        String encodingType = n > 0 ? elementValue.substring(0, n) : null;
        String nameValue = n > 0 ? elementValue.substring(n+1) : null;

        if (encodingType != null && encodingType.length() > 0
                && nameValue != null && nameValue.length() > 0) {

            if (encodingType.equals("UTF8String")) {
                return new AVA(oid, new UTF8String(nameValue));

            } else if (encodingType.equals("PrintableString")) {
                return new AVA(oid, new PrintableString(nameValue));

            } else if (encodingType.equals("BMPString")) {
                return new AVA(oid, new BMPString(nameValue));

            } else if (encodingType.equals("TeletexString")) {
                return new AVA(oid, new TeletexString(nameValue));

            } else if (encodingType.equals("UniversalString")) {
                return new AVA(oid, new UniversalString(nameValue));

            } else {
                throw new Exception("Unsupported encoding: " + encodingType);
            }
        }

        return null;
    }

    public Name createName(String dn, boolean encodingEnabled) throws Exception {

        X500Name x500Name = new X500Name(dn);
        Name jssName = new Name();

        for (netscape.security.x509.RDN rdn : x500Name.getNames()) {

            String rdnStr = rdn.toString();
            if (verbose) System.out.println("RDN: " + rdnStr);

            String[] split = rdnStr.split("=");
            if (split.length != 2) continue;

            String attribute = split[0];
            String value = split[1];

            int n = value.indexOf(':');

            if (attribute.equalsIgnoreCase("UID")) {
                AVA ava;
                if (encodingEnabled && isEncoded(value)) {
                    ava = createAVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"), n, value);
                } else {
                    ava = new AVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"), new PrintableString(value));
                }
                jssName.addElement(ava);

            } else if (attribute.equalsIgnoreCase("C")) {
                jssName.addCountryName(value);

            } else if (attribute.equalsIgnoreCase("CN")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.commonName, n, value));
                } else {
                    jssName.addCommonName(value);
                }

            } else if (attribute.equalsIgnoreCase("L")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.localityName, n, value));
                } else {
                    jssName.addLocalityName(value);
                }

            } else if (attribute.equalsIgnoreCase("O")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.organizationName, n, value));
                } else {
                    jssName.addOrganizationName(value);
                }

            } else if (attribute.equalsIgnoreCase("ST")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.stateOrProvinceName, n, value));
                } else {
                    jssName.addStateOrProvinceName(value);
                }

            } else if (attribute.equalsIgnoreCase("OU")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.organizationalUnitName, n, value));
                } else {
                    jssName.addOrganizationalUnitName(value);
                }

            } else {
                throw new Exception("Unsupported attribute: " + attribute);
            }
        }

        return jssName;
    }
}
