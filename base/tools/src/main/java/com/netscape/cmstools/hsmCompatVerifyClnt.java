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
// Copyright (C) 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.netscape.security.util.WrappingParams;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * hsmCompatVerifyClnt - Client-side tool for PKI token compatibility verification
 *
 * This tool simulates the client-side operations for key archival:
 * - Generates a key pair
 * - Wraps the private key with a session key
 * - Wraps the session key with KRA transport public key
 *
 * It outputs the wrapped keys to files for verification with hsmCompatVerifyServ.
 *
 * Adopted from: CRMFPopClient (client operations)
 *
 * @author Christina Fu (cfu)
 */
public class hsmCompatVerifyClnt {

    private static final String DEFAULT_ALGORITHM = "RSA";
    private static final int DEFAULT_KEY_LENGTH = 2048;
    private static final String DEFAULT_KEYWRAP_ALG = "AES KeyWrap/Wrapped";
    private static final String DEFAULT_RSA_KEYWRAP = "RSA-OAEP";
    private static final String DEFAULT_CLIENT_DB = System.getProperty("user.home") + "/.dogtag-kra-compat/client-nssdb";
    private static final String DEFAULT_PKISERV_DB = System.getProperty("user.home") + "/.dogtag-kra-compat/pkiserv-nssdb";

    private boolean autoYes = false;

    public static void main(String[] args) {
        try {
            Options options = createOptions();
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("help")) {
                printHelp(options);
                System.exit(0);
            }

            // Parameters with defaults
            String clientDB = cmd.getOptionValue("client-db-path", DEFAULT_CLIENT_DB);

            // Determine transport cert location:
            // 1. If --transport-cert is specified, use that
            // 2. Otherwise, if --client-db-path is specified, use <client-db-path>/kra_transport.pem
            // 3. Otherwise, use default pkiserv-nssdb location
            String transportCertFile;
            if (cmd.hasOption("transport-cert")) {
                transportCertFile = cmd.getOptionValue("transport-cert");
            } else if (cmd.hasOption("client-db-path")) {
                transportCertFile = clientDB + "/kra_transport.pem";
            } else {
                transportCertFile = DEFAULT_PKISERV_DB + "/kra_transport.pem";
            }

            String clientPasswd = cmd.getOptionValue("client-passwd");
            String clientPasswdFile = cmd.getOptionValue("client-passwd-file");

            // Read password from file if specified
            if (clientPasswd == null && clientPasswdFile != null) {
                try {
                    clientPasswd = new String(java.nio.file.Files.readAllBytes(
                        java.nio.file.Paths.get(clientPasswdFile))).trim();
                } catch (Exception e) {
                    System.err.println("ERROR: Failed to read password from file: " + clientPasswdFile);
                    System.err.println("       " + e.getMessage());
                    System.exit(1);
                }
            }

            String rsaKeywrap = cmd.getOptionValue("rsa-keywrap", DEFAULT_RSA_KEYWRAP);
            boolean useOAEP = rsaKeywrap.equals("RSA-OAEP");

            // Validate required parameter (only password is truly required)
            if (clientPasswd == null) {
                System.err.println("ERROR: Missing required parameter: --client-passwd or --client-passwd-file");
                printHelp(options);
                System.exit(1);
            }

            // Validate rsa-keywrap value
            if (!rsaKeywrap.equals("RSA") && !rsaKeywrap.equals("RSA-OAEP")) {
                System.err.println("ERROR: Invalid --rsa-keywrap value: " + rsaKeywrap);
                System.err.println("       Valid values: RSA, RSA-OAEP");
                System.exit(1);
            }

            // Check if transport cert file exists
            if (!new java.io.File(transportCertFile).exists()) {
                System.err.println("ERROR: Transport certificate not found: " + transportCertFile);
                System.err.println("       Please specify --transport-cert <path to kra_transport.pem>");
                System.exit(1);
            }

            // Default output prefix is based on client DB directory
            String defaultOutput = clientDB + "/kra-test";
            String outputPrefix = cmd.getOptionValue("output", defaultOutput);

            // Optional parameters
            String algorithm = cmd.getOptionValue("algorithm", DEFAULT_ALGORITHM);
            int keyLength = Integer.parseInt(cmd.getOptionValue("l", String.valueOf(DEFAULT_KEY_LENGTH)));
            String curve = cmd.getOptionValue("c", "nistp256");
            boolean sslECDH = Boolean.parseBoolean(cmd.getOptionValue("x", "false"));
            boolean temporary = Boolean.parseBoolean(cmd.getOptionValue("t", algorithm.equalsIgnoreCase("rsa") ? "false" : "true"));
            int sensitive = Integer.parseInt(cmd.getOptionValue("s", "-1"));
            int extractable = Integer.parseInt(cmd.getOptionValue("e", "-1"));
            String keywrapAlg = cmd.getOptionValue("w", DEFAULT_KEYWRAP_ALG);
            boolean verbose = cmd.hasOption("verbose");
            boolean autoYes = cmd.hasOption("yes");

            // Print all parameters being used (including defaults)
            System.out.println("=== hsmCompatVerifyClnt Configuration ===");
            System.out.println("Parameters (including defaults):");
            System.out.println("  --client-db-path " + clientDB);
            System.out.println("  --transport-cert " + transportCertFile);
            System.out.println("  --output " + outputPrefix);
            System.out.println("  --algorithm " + algorithm);
            if (algorithm.equalsIgnoreCase("rsa")) {
                System.out.println("  --key-length " + keyLength);
            } else {
                System.out.println("  --curve " + curve);
                if (sslECDH) {
                    System.out.println("  --ssl-ecdh " + sslECDH);
                }
            }
            System.out.println("  --temporary " + temporary);
            System.out.println("  --sensitive " + sensitive);
            System.out.println("  --extractable " + extractable);
            System.out.println("  --keywrap-alg \"" + keywrapAlg + "\"");
            System.out.println("  RSA session key wrap: " + (useOAEP ? "RSA-OAEP" : "RSA (PKCS#1 v1.5)"));
            if (useOAEP) {
                System.out.println("  --oaep");
            }
            System.out.println("  --verbose " + (verbose ? "enabled" : "disabled"));
            System.out.println();

            hsmCompatVerifyClnt client = new hsmCompatVerifyClnt();
            client.autoYes = autoYes;
            client.run(clientDB, clientPasswd, transportCertFile, outputPrefix,
                      algorithm, keyLength, curve, sslECDH, temporary, sensitive, extractable,
                      keywrapAlg, useOAEP, verbose);

        } catch (Exception e) {
            System.err.println();
            System.err.println("ERROR: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getName()));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static Options createOptions() {
        Options options = new Options();

        options.addOption(Option.builder()
                .longOpt("help")
                .desc("Show help message")
                .build());

        options.addOption(Option.builder()
                .longOpt("client-db-path")
                .hasArg()
                .argName("clientPath")
                .desc("Client NSS database directory path (required)")
                .build());

        options.addOption(Option.builder()
                .longOpt("client-passwd")
                .hasArg()
                .argName("password")
                .desc("Client NSS database password (INSECURE: visible in process listings; use --client-passwd-file instead)")
                .build());

        options.addOption(Option.builder()
                .longOpt("client-passwd-file")
                .hasArg()
                .argName("file")
                .desc("File containing client NSS database password (RECOMMENDED for security)")
                .build());

        options.addOption(Option.builder()
                .longOpt("transport-cert")
                .hasArg()
                .argName("file")
                .desc("KRA transport certificate file (PEM or DER) (required)")
                .build());

        options.addOption(Option.builder()
                .longOpt("output")
                .hasArg()
                .argName("prefix")
                .desc("Output file prefix (default: kra-test)")
                .build());

        options.addOption(Option.builder()
                .longOpt("algorithm")
                .hasArg()
                .argName("alg")
                .desc("Key algorithm: RSA or EC (default: RSA)")
                .build());

        Option option = new Option("l", "key-length", true, "RSA key length in bits (default: 2048)");
        option.setArgName("length");
        options.addOption(option);

        option = new Option("c", "curve", true, "ECC curve name (default: nistp256)");
        option.setArgName("curve");
        options.addOption(option);

        option = new Option("x", "ssl-ecdh", true, "SSL certificate with ECDH ECDSA (default: false)");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option("t", "temporary", true, "Temporary (default: true for EC, false for RSA)");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option("s", "sensitive", true, "Sensitive (-1: token-dependent, 0: non-sensitive, 1: sensitive, default: -1)");
        option.setArgName("sensitive");
        options.addOption(option);

        option = new Option("e", "extractable", true, "Extractable (-1: token-dependent, 0: non-extractable, 1: extractable, default: -1)");
        option.setArgName("extractable");
        options.addOption(option);

        option = new Option("w", "keywrap-alg", true, "Key wrap algorithm (default: AES KeyWrap/Wrapped)");
        option.setArgName("algorithm");
        options.addOption(option);

        options.addOption(Option.builder()
                .longOpt("rsa-keywrap")
                .hasArg()
                .argName("type")
                .desc("RSA key wrapping type: RSA or RSA-OAEP (default: RSA-OAEP)")
                .build());

        options.addOption(Option.builder()
                .longOpt("verbose")
                .desc("Verbose output")
                .build());

        options.addOption(Option.builder()
                .longOpt("yes")
                .desc("Automatically delete existing keys/certs and regenerate (non-interactive)")
                .build());

        return options;
    }

    private static void printHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("hsmCompatVerifyClnt",
                "\nGenerates keys and wraps them for KRA archival testing\n\n",
                options,
                "\nSimple example (using all defaults):\n" +
                "  hsmCompatVerifyClnt --client-passwd ClientSecret.123 --verbose\n\n" +
                "Full example with custom paths:\n" +
                "  hsmCompatVerifyClnt \\\n" +
                "    --client-db-path ~/.dogtag-kra-compat/client-nssdb \\\n" +
                "    --client-passwd ClientSecret.123 \\\n" +
                "    --transport-cert ~/.dogtag-kra-compat/pkiserv-nssdb/kra_transport.pem \\\n" +
                "    --verbose\n\n" +
                "Defaults:\n" +
                "  --client-db-path   ~/.dogtag-kra-compat/client-nssdb\n" +
                "  --transport-cert   ~/.dogtag-kra-compat/pkiserv-nssdb/kra_transport.pem\n" +
                "  --output           <client-db-path>/kra-test\n" +
                "  --keywrap-alg      AES KeyWrap/Wrapped\n" +
                "  --rsa-keywrap      RSA-OAEP\n\n" +
                "Valid keywrap algorithms:\n" +
                "    \"AES KeyWrap/Wrapped\"   - CKM_AES_KEY_WRAP_KWP (0x210B) (default, recommended for HSM/FIPS)\n" +
                "    \"AES KeyWrap/Padding\"   - CKM_AES_KEY_WRAP_PAD (0x210A)\n" +
                "    \"AES KeyWrap/NoPadding\" - CKM_AES_KEY_WRAP (0x2109) (requires 8-byte aligned input)\n" +
                "    \"AES/CBC/PKCS5Padding\"  - CKM_AES_CBC_PAD (0x1085) (uses IV)\n" +
                "  NOTE: Not all algorithms work with all PKCS#11 tokens - test with your HSM.\n\n" +
                "Output files:\n" +
                "  kra-test-wrapped-session.bin  - Wrapped session key\n" +
                "  kra-test-wrapped-private.bin  - Wrapped private key\n" +
                "  kra-test-public.der           - Public key\n" +
                "  kra-test-iv.bin               - IV (only for CBC mode algorithms)\n" +
                "\n" +
                "IMPORTANT: When running hsmCompatVerifyServ, use the same --keywrap-alg value!\n" +
                "Use these files with hsmCompatVerifyServ to verify HSM operations.\n",
                true);
    }

    private void run(String clientDB, String clientPasswd, String transportCertFile,
                     String outputPrefix, String algorithm, int keyLength, String curve,
                     boolean sslECDH, boolean temporary, int sensitive, int extractable,
                     String keywrapAlg, boolean useOAEP, boolean verbose) throws Exception {

        log("=== KRA Compatibility Verification - Client Side ===", verbose);
        log("Generating keys and creating wrapped output for KRA archival testing", verbose);
        log("", verbose);

        // Check if client NSS database exists
        java.io.File clientDBDir = new java.io.File(clientDB);
        if (!clientDBDir.exists()) {
            throw new Exception(
                "Client NSS database not found: " + clientDB + "\n\n" +
                "Please create it first:\n" +
                "  mkdir -p " + clientDB + "\n" +
                "  certutil -N -d " + clientDB
            );
        }

        // Step 1: Initialize NSS
        // Adopted from: CRMFPopClient.java (NSS initialization)
        log("Step 1: Initializing client NSS database", verbose);
        log("  Client DB: " + clientDB, verbose);
        org.mozilla.jss.CryptoManager.initialize(clientDB);
        org.mozilla.jss.CryptoManager manager = org.mozilla.jss.CryptoManager.getInstance();
        CryptoToken token = manager.getInternalKeyStorageToken();
        org.mozilla.jss.util.Password password = new org.mozilla.jss.util.Password(clientPasswd.toCharArray());
        try {
            token.login(password);
        } finally {
            password.clear();
        }
        log("  - NSS initialized", verbose);

        // Check for existing keys and certificates
        org.mozilla.jss.crypto.PrivateKey[] existingKeys = token.getCryptoStore().getPrivateKeys();
        org.mozilla.jss.crypto.X509Certificate[] existingCerts = token.getCryptoStore().getCertificates();

        int keyCount = existingKeys.length;
        int certCount = existingCerts.length;

        if (keyCount > 0 || certCount > 0) {
            log("", verbose);
            log("=== Existing Keys/Certificates Found ===", verbose);
            log("The client NSS database contains:", verbose);
            log("  - " + keyCount + " private key" + (keyCount != 1 ? "s" : ""), verbose);
            log("  - " + certCount + " certificate" + (certCount != 1 ? "s" : ""), verbose);
            log("", verbose);

            // Ask if user wants to delete existing and regenerate (default: No, keep existing)
            // With --yes flag, promptYesNo automatically returns true (delete and regenerate)
            if (promptYesNo("Delete existing and regenerate? (y/n, 'n' keeps existing): ")) {
                log("Deleting existing keys and certificates...", verbose);

                // Delete all existing certificates
                for (org.mozilla.jss.crypto.X509Certificate cert : existingCerts) {
                    try {
                        token.getCryptoStore().deleteCert(cert);
                        log("  - Deleted certificate: " + cert.getSubjectDN(), verbose);
                    } catch (Exception e) {
                        log("  - Warning: Failed to delete certificate: " + e.getMessage(), verbose);
                    }
                }

                // Delete all existing private keys
                for (org.mozilla.jss.crypto.PrivateKey key : existingKeys) {
                    try {
                        token.getCryptoStore().deletePrivateKey(key);
                        log("  - Deleted private key", verbose);
                    } catch (Exception e) {
                        log("  - Warning: Failed to delete private key: " + e.getMessage(), verbose);
                    }
                }

                log("Cleanup complete.", verbose);
                log("", verbose);
            } else {
                // User chose not to delete, keep existing and generate new alongside
                log("Keeping existing keys/certificates.", verbose);
                log("New test keys will be generated alongside existing keys.", verbose);
                log("", verbose);
            }
        }

        // Step 2: Load transport certificate
        // Adopted from: CRMFPopClient.java (loading transport cert for key archival)
        log("", verbose);
        log("Step 2: Loading KRA transport certificate", verbose);
        log("  Transport cert: " + transportCertFile, verbose);

        // Check if transport cert file exists
        java.io.File transportFile = new java.io.File(transportCertFile);
        if (!transportFile.exists()) {
            throw new Exception(
                "Transport certificate not found: " + transportCertFile + "\n\n" +
                "If you ran hsmCompatVerifyServ setup as a different user (e.g. root),\n" +
                "copy the transport certificate to this location:\n" +
                "  sudo cp /root/.dogtag-kra-compat/pkiserv-nssdb/kra_transport.pem " + transportCertFile + "\n" +
                "  sudo chown " + System.getProperty("user.name") + " " + transportCertFile + "\n\n" +
                "Or specify the actual location with:\n" +
                "  --transport-cert /root/.dogtag-kra-compat/pkiserv-nssdb/kra_transport.pem"
            );
        }

        byte[] certBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(transportCertFile));
        byte[] transportCertData;

        String pem = new String(certBytes, java.nio.charset.StandardCharsets.US_ASCII);
        if (pem.contains("-----BEGIN CERTIFICATE-----")) {
            transportCertData = org.mozilla.jss.netscape.security.util.Cert.parseCertificate(pem);
        } else {
            transportCertData = certBytes;
        }
        org.mozilla.jss.crypto.X509Certificate transportCert = manager.importCACertPackage(transportCertData);
        log("  - Transport certificate loaded", verbose);
        log("    Subject: " + transportCert.getSubjectDN(), verbose);

        // Step 3: Generate key pair
        // Adopted from: CRMFPopClient.java (key pair generation)
        log("", verbose);
        log("Step 3: Generating user key pair", verbose);
        log("  Algorithm: " + algorithm, verbose);

        KeyPair keyPair;
        if ("RSA".equalsIgnoreCase(algorithm)) {
            log("  Key length: " + keyLength, verbose);
            log("  Temporary: " + temporary, verbose);
            log("  Sensitive: " + sensitive, verbose);
            log("  Extractable: " + extractable, verbose);
            keyPair = CryptoUtil.generateRSAKeyPair(
                    token,
                    keyLength,
                    temporary,
                    sensitive == -1 ? null : sensitive == 1,
                    extractable == -1 ? null : extractable == 1,
                    null,  // usages - let token decide
                    null); // usagesMask - let token decide
        } else if ("EC".equalsIgnoreCase(algorithm)) {
            log("  Curve: " + curve, verbose);
            log("  SSL ECDH: " + sslECDH, verbose);
            log("  Temporary: " + temporary, verbose);
            log("  Sensitive: " + sensitive, verbose);
            log("  Extractable: " + extractable, verbose);
            // ECDH_USAGES_MASK: used with SSL server cert that does ECDH ECDSA (requires POP_NONE)
            // ECDHE_USAGES_MASK: used for other certs including SSL server cert that does ECDHE ECDSA
            // This matches CRMFPopClient behavior
            keyPair = CryptoUtil.generateECCKeyPair(
                    token,
                    curve,
                    temporary,
                    sensitive == -1 ? null : sensitive == 1,
                    extractable == -1 ? null : extractable == 1,
                    null,  // usages - let token decide
                    sslECDH ? CryptoUtil.ECDH_USAGES_MASK : CryptoUtil.ECDHE_USAGES_MASK); // usagesMask
        } else {
            throw new IllegalArgumentException(
                    "Unsupported --algorithm value: " + algorithm + ". Valid values: RSA, EC");
        }
        log("  - Key pair generated", verbose);

        // Step 4: Wrap keys for archival
        // Adopted from: CRMFUtil.createCertRequest() -> CryptoUtil.createPKIArchiveOptions()
        // This simulates what happens when a client creates a CRMF request with key archival
        log("", verbose);
        log("Step 4: Wrapping private key for archival", verbose);
        log("  Wrap algorithm: " + keywrapAlg, verbose);

        org.mozilla.jss.crypto.KeyWrapAlgorithm keyWrapAlgorithm =
                org.mozilla.jss.crypto.KeyWrapAlgorithm.fromString(keywrapAlg);
        // Only generate IV for algorithms that need it (not for KeyWrap modes)
        // Adopted from: base/common/src/main/java/org/dogtagpki/util/cert/CRMFUtil.java
        //   (but CRMFUtil always generates IV - this is a fix for KeyWrap modes)
        byte[] iv = null;
        if (keyWrapAlgorithm.getBlockSize() > 0 &&
            !keywrapAlg.toLowerCase().contains("keywrap")) {
            iv = CryptoUtil.getNonceData(keyWrapAlgorithm.getBlockSize());
        }
        WrappingParams params = CryptoUtil.getWrappingParams(keyWrapAlgorithm, iv, useOAEP);

        // CRITICAL FIX: CryptoUtil.getWrappingParams() passes useOAEP to determine RSA wrap algorithm,
        // but the WrappingParams constructor ignores it and always sets skWrapAlgorithm=RSA (see
        // WrappingParams.java line 114). We must explicitly override it when OAEP is requested.
        if (useOAEP) {
            params.setSkWrapAlgorithm(org.mozilla.jss.crypto.KeyWrapAlgorithm.RSA_OAEP);
        }

        org.mozilla.jss.pkix.primitive.AlgorithmIdentifier aid =
                new org.mozilla.jss.pkix.primitive.AlgorithmIdentifier(
                        CryptoUtil.getOID(params.getPayloadWrapAlgorithm()), null);

        // Use the shared utility method that returns wrapped keys separately
        CryptoToolsUtil.PKIArchiveOptionsData archiveData = CryptoToolsUtil.createPKIArchiveOptionsWithData(
                token,
                transportCert.getPublicKey(),
                (org.mozilla.jss.crypto.PrivateKey) keyPair.getPrivate(),
                params,
                aid);

        log("  - Private key wrapped with session key", verbose);
        log("  - Session key wrapped with transport public key", verbose);

        // Step 5: Write output files
        log("", verbose);
        log("Step 5: Writing output files", verbose);

        String wrappedSessionFile = outputPrefix + "-wrapped-session.bin";
        String wrappedPrivateFile = outputPrefix + "-wrapped-private.bin";
        String publicKeyFile = outputPrefix + "-public.der";

        try (FileOutputStream fos = new FileOutputStream(wrappedSessionFile)) {
            fos.write(archiveData.wrappedSessionKey);
        }
        log("  - Wrote: " + wrappedSessionFile + " (" + archiveData.wrappedSessionKey.length + " bytes)", verbose);

        try (FileOutputStream fos = new FileOutputStream(wrappedPrivateFile)) {
            fos.write(archiveData.wrappedPrivateKey);
        }
        log("  - Wrote: " + wrappedPrivateFile + " (" + archiveData.wrappedPrivateKey.length + " bytes)", verbose);

        PublicKey publicKey = keyPair.getPublic();
        try (FileOutputStream fos = new FileOutputStream(publicKeyFile)) {
            fos.write(publicKey.getEncoded());
        }
        log("  - Wrote: " + publicKeyFile + " (" + publicKey.getEncoded().length + " bytes)", verbose);

        // Save IV if one was generated (for CBC mode algorithms)
        if (iv != null) {
            String ivFile = outputPrefix + "-iv.bin";
            try (FileOutputStream fos = new FileOutputStream(ivFile)) {
                fos.write(iv);
            }
            log("  - Wrote: " + ivFile + " (" + iv.length + " bytes)", verbose);
        }

        log("", verbose);
        log("SUCCESS: Client-side key generation and wrapping completed!", verbose);
        log("", verbose);
        log("Next step:", verbose);
        log("  Run hsmCompatVerifyServ to verify HSM archival/recovery with these files", verbose);
    }

    private void log(String message, boolean verbose) {
        if (verbose || message.startsWith("===") || message.startsWith("SUCCESS") ||
            message.startsWith("ERROR") || message.isEmpty()) {
            System.out.println(message);
        }
    }

    private boolean promptYesNo(String prompt) throws java.io.IOException {
        if (autoYes) {
            System.out.println(prompt + "yes (--yes flag)");
            return true;
        }
        System.out.print(prompt);
        System.out.flush();
        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
        String response = reader.readLine();
        return response != null && (response.equalsIgnoreCase("y") || response.equalsIgnoreCase("yes"));
    }
}
