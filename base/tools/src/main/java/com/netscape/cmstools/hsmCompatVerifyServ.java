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
// (C) 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.nss.NSSExtensionGenerator;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.AuthorityKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.CertificateSerialNumber;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.CertificateVersion;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.CertBag;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.EncryptedPrivateKeyInfo;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.PlainPasswordFile;

/**
 * KRA HSM/PKCS#11 Compatibility Verification Tool
 *
 * This tool verifies the minimum capabilities required for
 * KRA key archival and recovery operations without requiring
 * a full PKI installation.
 *
 * Two-phase operation:
 * 1. Setup Phase (--setup-only): Creates CA/KRA certificates on HSM
 *    - CA signing certificate (self-signed)
 *    - KRA transport certificate (signed by CA)
 *    - KRA storage certificate (signed by CA)
 *
 * 2. Verification Phase: Verifies complete archival/recovery workflow
 *    - Generate user key on client token
 *    - Archive using transport key (HSM)
 *    - Store using storage key (HSM)
 *    - Recover using storage key (HSM)
 *    - Create PKCS#12
 *
 * This verifies essential PKCS#11 mechanisms:
 * HSM:
 * - RSA or EC key pair generation (for CA cert)
 * - RSA key pair generation (for transport/storage certs, required for key wrapping)
 * - Self-signed certificate creation
 * - Certificate signing
 * - RSA key wrapping/unwrapping (with optional OAEP support)
 * - Session key (AES) generation and operations
 * Client token:
 * - RSA or EC key pair generation (user keys)
 * - Symmetric key wrapping/unwrapping
 *
 * Note: KRA transport and storage certificates must be RSA for key wrapping operations.
 * CA and user certificates can be RSA or EC.
 *
 * Code references (mimicing the real PKI operations):
 * - Client-side wrapping: base/tools/src/main/java/com/netscape/cmstools/CRMFPopClient.java
 * - KRA archival: base/kra/src/main/java/com/netscape/kra/EnrollmentService.java
 * - KRA recovery: base/kra/src/main/java/com/netscape/kra/RecoveryService.java
 * - Transport key ops: base/kra/src/main/java/com/netscape/kra/TransportKeyUnit.java
 * - Storage key ops: base/kra/src/main/java/com/netscape/kra/StorageKeyUnit.java
 *
 * @author Christina Fu (cfu)
 */
public class hsmCompatVerifyServ {

    public static final String TOOL_NAME = "hsmCompatVerifyServ";

    // Default key usage flags for transport and storage keys (matches standard KRA behavior)
    // Based on: base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java:RSA_KEYPAIR_USAGES
    private static final String DEFAULT_OPFLAGS = "encrypt,decrypt,wrap,unwrap,sign,sign_recover";

    // Session key usages for key archival/recovery operations
    // This is copied from CryptoUtil.sess_key_usages (which is private and not accessible)
    // Based on: base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java:179-184
    // Used in: createPKIArchiveOptionsInternal for client-side session key generation
    private static final org.mozilla.jss.crypto.SymmetricKey.Usage[] SESSION_KEY_USAGES = {
        org.mozilla.jss.crypto.SymmetricKey.Usage.WRAP,
        org.mozilla.jss.crypto.SymmetricKey.Usage.UNWRAP,
        org.mozilla.jss.crypto.SymmetricKey.Usage.ENCRYPT,
        org.mozilla.jss.crypto.SymmetricKey.Usage.DECRYPT
    };

    // Storage key usages (for wrapping archived keys)
    // Based on: base/kra/src/main/java/com/netscape/kra/StorageKeyUnit.java (wrapPrivateKey method)
    private static final org.mozilla.jss.crypto.SymmetricKey.Usage[] STORAGE_KEY_USAGES = {
        org.mozilla.jss.crypto.SymmetricKey.Usage.WRAP,
        org.mozilla.jss.crypto.SymmetricKey.Usage.UNWRAP
    };

    public boolean verbose;
    private boolean useOAEP = false;
    private boolean autoYes = false;

    public static Options createOptions() {
        Options options = new Options();

        // PKI Server Setup Options
        Option option = new Option("S", "pkiserv-db-path", true, "PKI server NSS database directory path");
        option.setArgName("pkiServPath");
        options.addOption(option);

        option = new Option("Q", "pkiserv-passwd", true, "PKI server NSS database password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "pkiserv-passwd-file", true, "File containing PKI server NSS database password");
        option.setArgName("file");
        options.addOption(option);

        // HSM Options
        option = new Option("H", "hsm-token", true, "HSM token name");
        option.setArgName("token");
        options.addOption(option);

        option = new Option("P", "hsm-token-passwd", true, "HSM token password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "hsm-token-passwd-file", true, "File containing HSM token password");
        option.setArgName("file");
        options.addOption(option);

        // Setup Control
        options.addOption(null, "setup-only", false, "Only run setup, don't test");
        options.addOption(null, "yes", false, "Automatically regenerate existing certificates without prompting (non-interactive)");

        // CA Options
        option = new Option(null, "ca-key-algorithm", true, "CA key algorithm: rsa or ec (default: rsa)");
        option.setArgName("algorithm");
        options.addOption(option);

        option = new Option(null, "ca-key-size", true, "CA key size (RSA: default 4096, EC: curve name, default nistp256)");
        option.setArgName("size or curve");
        options.addOption(option);

        option = new Option(null, "ca-subject", true, "CA subject DN (default: CN=Test CA,O=Dogtag)");
        option.setArgName("subject DN");
        options.addOption(option);

        option = new Option(null, "ca-validity", true, "CA validity in days (default: 3650)");
        option.setArgName("days");
        options.addOption(option);

        option = new Option(null, "ca-nickname", true, "CA cert nickname on HSM (default: test CA Signing Certificate)");
        option.setArgName("nickname");
        options.addOption(option);

        // Transport Options
        option = new Option(null, "transport-subject", true, "Transport subject DN (default: CN=test KRA Transport,O=Dogtag)");
        option.setArgName("subject DN");
        options.addOption(option);

        option = new Option(null, "transport-validity", true, "Transport validity in days (default: 365)");
        option.setArgName("days");
        options.addOption(option);

        option = new Option(null, "transport-nickname", true, "Transport cert nickname on HSM (default: test KRA Transport Certificate)");
        option.setArgName("nickname");
        options.addOption(option);

        // Storage Options
        option = new Option(null, "storage-subject", true, "Storage subject DN (default: CN=test KRA Storage,O=Dogtag)");
        option.setArgName("subject DN");
        options.addOption(option);

        option = new Option(null, "storage-validity", true, "Storage validity in days (default: 365)");
        option.setArgName("days");
        options.addOption(option);

        option = new Option(null, "storage-nickname", true, "Storage cert nickname on HSM (default: test KRA Storage Certificate)");
        option.setArgName("nickname");
        options.addOption(option);

        // Transport/Storage Key Usage Options (for HSM-specific requirements)
        option = new Option(null, "transport-opflags", true, "Transport key usage flags (comma-separated). Default: encrypt,decrypt,wrap,unwrap,sign,sign_recover");
        option.setArgName("flags");
        options.addOption(option);

        option = new Option(null, "transport-opflags-mask", true, "Transport key usage flags mask (comma-separated). Default: same as opflags");
        option.setArgName("mask");
        options.addOption(option);

        option = new Option(null, "storage-opflags", true, "Storage key usage flags (comma-separated). Default: encrypt,decrypt,wrap,unwrap,sign,sign_recover");
        option.setArgName("flags");
        options.addOption(option);

        option = new Option(null, "storage-opflags-mask", true, "Storage key usage flags mask (comma-separated). Default: same as opflags");
        option.setArgName("mask");
        options.addOption(option);

        // Client Database Path
        option = new Option(null, "client-db-path", true, "Client NSS database directory path (base path for wrapped key files)");
        option.setArgName("clientPath");
        options.addOption(option);

        // Test Input Files (from hsmCompatVerifyClnt)
        option = new Option(null, "wrapped-session", true, "Wrapped session key file (from hsmCompatVerifyClnt)");
        option.setArgName("file");
        options.addOption(option);

        option = new Option(null, "wrapped-private", true, "Wrapped private key file (from hsmCompatVerifyClnt)");
        option.setArgName("file");
        options.addOption(option);

        option = new Option(null, "public-key", true, "Public key file in DER format (from hsmCompatVerifyClnt)");
        option.setArgName("file");
        options.addOption(option);

        option = new Option(null, "iv-file", true, "IV file (from hsmCompatVerifyClnt, for CBC mode algorithms)");
        option.setArgName("file");
        options.addOption(option);

        // Test Parameters
        option = new Option("n", "subject-dn", true, "Subject DN for test certificate");
        option.setArgName("subject DN");
        options.addOption(option);

        option = new Option("a", "algorithm", true, "Key algorithm (rsa|ec, default: rsa)");
        option.setArgName("algorithm");
        options.addOption(option);

        option = new Option("l", "key-length", true, "RSA key length (default: 2048)");
        option.setArgName("length");
        options.addOption(option);

        option = new Option("c", "curve", true, "ECC curve name (default: nistp256)");
        option.setArgName("curve");
        options.addOption(option);

        option = new Option("x", "ssl-ecdh", true, "EC: SSL certificate with ECDH ECDSA (default: false)");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option("t", "temporary", true, "Temporary key (default: true)");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option("s", "sensitive", true, "Sensitive (-1: token-dependent, 0: non-sensitive, 1: sensitive, default: -1)");
        option.setArgName("sensitive");
        options.addOption(option);

        option = new Option("e", "extractable", true, "Extractable (-1: token-dependent, 0: non-extractable, 1: extractable, default: -1)");
        option.setArgName("extractable");
        options.addOption(option);

        option = new Option("w", "keywrap-alg", true, "Key wrap algorithm (default: AES KeyWrap/Padding)");
        option.setArgName("algorithm");
        options.addOption(option);

        option = new Option("o", "p12-output", true, "Output PKCS#12 file (default: <client-db-path>/kra-recovered.p12)");
        option.setArgName("file");
        options.addOption(option);

        option = new Option("r", "recovery-passwd", true, "Recovery password for PKCS#12");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "recovery-passwd-file", true, "File containing recovery password for PKCS#12");
        option.setArgName("file");
        options.addOption(option);

        options.addOption(null, "archive-only", false, "Archive only mode - create LDIF and stop (no recovery)");
        options.addOption(null, "recover-only", false, "Recovery only mode - recover from existing LDIF (no archival)");

        option = new Option(null, "ldif-file", true, "LDIF file path (default: <client-db-path>/kra-archived-key.ldif)");
        option.setArgName("file");
        options.addOption(option);

        option = new Option(null, "rsa-keywrap", true, "RSA key wrapping type: RSA or RSA-OAEP (default: RSA-OAEP)");
        option.setArgName("type");
        options.addOption(option);

        options.addOption(null, "legacyPKCS12", false, "Use legacy PKCS#12 format (PBE_SHA1_DES3_CBC). Default: non-legacy (AES-256-KWP)");

        options.addOption("v", "verbose", false, "Run in verbose mode");
        options.addOption(null, "help", false, "Show help message");

        return options;
    }

    public static void printHelp() {
        System.out.println("Usage: " + TOOL_NAME + " [OPTIONS]");
        System.out.println();
        System.out.println("Verify HSM/PKCS#11 compatibility for KRA key archival and recovery");
        System.out.println();
        System.out.println("=== PHASE 1: SETUP (run once by admin) ===");
        System.out.println();
        System.out.println("PKI Server Setup Options:");
        System.out.println("  -S, --pkiserv-db-path <path>  PKI server NSS DB path (default: ~/.dogtag-kra-compat/pkiserv-nssdb)");
        System.out.println("  -Q, --pkiserv-passwd <pass>   PKI server NSS DB password (required for setup)");
        System.out.println();
        System.out.println("HSM Options:");
        System.out.println("  -H, --hsm-token <name>        HSM token name (required)");
        System.out.println("  -P, --hsm-token-passwd <pass> HSM token password (required)");
        System.out.println();
        System.out.println("Setup Control:");
        System.out.println("      --setup-only              Only run setup, don't verify");
        System.out.println("      --yes                     Automatically regenerate existing certificates (non-interactive)");
        System.out.println();
        System.out.println("CA Certificate Options:");
        System.out.println("      --ca-key-algorithm <alg>  CA key algorithm: rsa or ec (default: rsa)");
        System.out.println("      --ca-key-size <size>      CA key size (RSA: default 4096, EC: curve, default nistp256)");
        System.out.println("      --ca-subject <dn>         CA subject DN (default: CN=Test CA,O=Dogtag)");
        System.out.println("      --ca-validity <days>      CA validity days (default: 3650)");
        System.out.println("      --ca-nickname <nick>      CA nickname on HSM (default: test CA Signing Certificate)");
        System.out.println();
        System.out.println("Transport Certificate Options (RSA-2048 only, required for key wrapping):");
        System.out.println("      --transport-subject <dn>  Transport subject DN (default: CN=test KRA Transport,O=Dogtag)");
        System.out.println("      --transport-validity <d>  Transport validity (default: 365)");
        System.out.println("      --transport-nickname <n>  Transport nickname (default: test KRA Transport Certificate)");
        System.out.println();
        System.out.println("Storage Certificate Options (RSA-2048 only, required for key wrapping):");
        System.out.println("      --storage-subject <dn>    Storage subject DN (default: CN=test KRA Storage,O=Dogtag)");
        System.out.println("      --storage-validity <d>    Storage validity (default: 365)");
        System.out.println("      --storage-nickname <n>    Storage nickname (default: test KRA Storage Certificate)");
        System.out.println();
        System.out.println("Key Usage Options (for HSM-specific compatibility):");
        System.out.println("  Available flags: encrypt, decrypt, sign, sign_recover, verify, verify_recover, wrap, unwrap, derive");
        System.out.println("      --transport-opflags <f>   Transport key usage flags (comma-separated)");
        System.out.println("                                Default: encrypt,decrypt,wrap,unwrap,sign,sign_recover");
        System.out.println("      --transport-opflags-mask  Transport key usage mask (comma-separated)");
        System.out.println("                                Default: same as transport-opflags");
        System.out.println("      --storage-opflags <f>     Storage key usage flags (comma-separated)");
        System.out.println("                                Default: encrypt,decrypt,wrap,unwrap,sign,sign_recover");
        System.out.println("      --storage-opflags-mask    Storage key usage mask (comma-separated)");
        System.out.println("                                Default: same as storage-opflags");
        System.out.println();
        System.out.println("=== PHASE 2: VERIFICATION (run multiple times) ===");
        System.out.println();
        System.out.println("Client Database:");
        System.out.println("      --client-db-path <path>   Client NSS database directory path (base path for wrapped key files)");
        System.out.println("                                Default: ~/.dogtag-kra-compat/client-nssdb");
        System.out.println();
        System.out.println("Input Files (generated by hsmCompatVerifyClnt):");
        System.out.println("      --wrapped-session <file>  Wrapped session key file");
        System.out.println("                                Default: <client-db-path>/kra-test-wrapped-session.bin");
        System.out.println("      --wrapped-private <file>  Wrapped private key file");
        System.out.println("                                Default: <client-db-path>/kra-test-wrapped-private.bin");
        System.out.println("      --public-key <file>       Public key file (DER format)");
        System.out.println("                                Default: <client-db-path>/kra-test-public.der");
        System.out.println("      --iv-file <file>          IV file (for CBC mode algorithms)");
        System.out.println("                                Default: <client-db-path>/kra-test-iv.bin");
        System.out.println();
        System.out.println("Verification Certificate Options:");
        System.out.println("  -n, --subject-dn <dn>         Subject DN for verification cert (required for verification)");
        System.out.println();
        System.out.println("Output Options:");
        System.out.println("  -o, --p12-output <file>       Output PKCS#12 file (required for verification)");
        System.out.println("                                Default: <client-db-path>/kra-recovered.p12");
        System.out.println("                                For multiple LDIF records: used as base name (e.g., key.p12 -> key-<serial>.p12)");
        System.out.println("  -r, --recovery-passwd <pass>  PKCS#12 password (required for verification)");
        System.out.println();
        System.out.println("Verification Mode Options:");
        System.out.println("      --archive-only            Archive only - create LDIF and stop (no recovery)");
        System.out.println("      --recover-only            Recovery only - recover from existing LDIF (no archival)");
        System.out.println("      --ldif-file <file>        LDIF file path (default: <client-db-path>/kra-archived-key.ldif)");
        System.out.println("                                For recover-only: processes all key records, creating one PKCS#12 per record");
        System.out.println();
        System.out.println("Key Wrap Algorithm Options:");
        System.out.println("  -w, --keywrap-alg <algorithm> Key wrap algorithm (default: AES KeyWrap/Wrapped)");
        System.out.println("      Valid algorithms:");
        System.out.println("        \"AES KeyWrap/Wrapped\"   - CKM_AES_KEY_WRAP_KWP (0x210B) (default, recommended for HSM/FIPS)");
        System.out.println("        \"AES KeyWrap/Padding\"   - CKM_AES_KEY_WRAP_PAD (0x210A)");
        System.out.println("        \"AES KeyWrap/NoPadding\" - CKM_AES_KEY_WRAP (0x2109)");
        System.out.println("        \"AES/CBC/PKCS5Padding\"  - CKM_AES_CBC_PAD (0x1085) (uses IV)");
        System.out.println("      Must match what hsmCompatVerifyClnt used!");
        System.out.println("      NOTE: Not all algorithms work with all PKCS#11 tokens - verify with your HSM.");
        System.out.println();
        System.out.println("RSA Key Wrap Options:");
        System.out.println("      --rsa-keywrap <type>      RSA key wrapping type (default: RSA-OAEP)");
        System.out.println("                                Valid values: RSA, RSA-OAEP");
        System.out.println("                                Must match what hsmCompatVerifyClnt used!");
        System.out.println();
        System.out.println("Other Options:");
        System.out.println("  -v, --verbose                 Run in verbose mode");
        System.out.println("      --help                    Show this help message");
        System.out.println();
        System.out.println("=== EXAMPLES ===");
        System.out.println();
        System.out.println("Setup (run once, assuming passwords are stored in password files):");
        System.out.println("  " + TOOL_NAME + " --setup-only \\");
        System.out.println("    --pkiserv-db-path ~/.dogtag-kra-compat/pkiserv-nssdb \\");
        System.out.println("    --pkiserv-passwd-file ~/pkiserv.pwd \\");
        System.out.println("    --hsm-token \"TestHSM\" --hsm-token-passwd-file ~/hsm.pwd \\");
        System.out.println("    --verbose");
        System.out.println();
        System.out.println("Generate client keys (run hsmCompatVerifyClnt first, assuming client password in file):");
        System.out.println("  hsmCompatVerifyClnt --client-passwd-file ~/client.pwd --verbose");
        System.out.println();
        System.out.println("Verify with generated keys (run multiple times, assuming passwords in files):");
        System.out.println("  " + TOOL_NAME + " \\");
        System.out.println("    --hsm-token \"TestHSM\" --hsm-token-passwd-file ~/hsm.pwd \\");
        System.out.println("    --subject-dn \"CN=Test User\" \\");
        System.out.println("    --p12-output ~/test.p12 --recovery-passwd-file ~/p12.pwd \\");
        System.out.println("    --verbose");
        System.out.println();
        System.out.println("Archive to LDIF (archival only, assuming HSM password in file):");
        System.out.println("  " + TOOL_NAME + " \\");
        System.out.println("    --hsm-token \"TestHSM\" --hsm-token-passwd-file ~/hsm.pwd \\");
        System.out.println("    --subject-dn \"CN=Test User\" \\");
        System.out.println("    --archive-only \\");
        System.out.println("    --verbose");
        System.out.println();
        System.out.println("Recover from LDIF (recovery only, assuming passwords in files):");
        System.out.println("  " + TOOL_NAME + " \\");
        System.out.println("    --hsm-token \"TestHSM\" --hsm-token-passwd-file ~/hsm.pwd \\");
        System.out.println("    --recover-only \\");
        System.out.println("    --p12-output ~/recovered.p12 --recovery-passwd-file ~/p12.pwd \\");
        System.out.println("    --verbose");
    }

    public static void printError(String message) {
        System.err.println("ERROR: " + message);
        System.err.println("Try '" + TOOL_NAME + " --help' for more information.");
    }

    public static void main(String args[]) throws Exception {
        Options options = createOptions();
        CommandLine cmd = null;

        try {
            CommandLineParser parser = new DefaultParser();
            cmd = parser.parse(options, args);
        } catch (Exception e) {
            printError(e.getMessage());
            System.exit(1);
        }

        if (cmd.hasOption("help")) {
            printHelp();
            System.exit(0);
        }

        boolean setupOnly = cmd.hasOption("setup-only");
        String rsaKeywrap = cmd.getOptionValue("rsa-keywrap", "RSA-OAEP");
        boolean useOAEP = rsaKeywrap.equals("RSA-OAEP");
        boolean verbose = cmd.hasOption("v");
        boolean autoYes = cmd.hasOption("yes");
        boolean archiveOnly = cmd.hasOption("archive-only");
        boolean recoverOnly = cmd.hasOption("recover-only");
        boolean legacyPKCS12 = cmd.hasOption("legacyPKCS12");

        // Validate rsa-keywrap value
        if (!rsaKeywrap.equals("RSA") && !rsaKeywrap.equals("RSA-OAEP")) {
            printError("Invalid --rsa-keywrap value: " + rsaKeywrap);
            System.err.println("       Valid values: RSA, RSA-OAEP");
            System.exit(1);
        }

        // PKI Server options
        String pkiservDB = cmd.getOptionValue("S", System.getProperty("user.home") + "/.dogtag-kra-compat/pkiserv-nssdb");
        String pkiservPasswd = cmd.getOptionValue("Q");
        String pkiservPasswdFile = cmd.getOptionValue("pkiserv-passwd-file");

        // Read pkiserv password from file if specified
        if (pkiservPasswd == null && pkiservPasswdFile != null) {
            try {
                pkiservPasswd = new String(java.nio.file.Files.readAllBytes(
                    java.nio.file.Paths.get(pkiservPasswdFile))).trim();
            } catch (Exception e) {
                printError("Failed to read password from file: " + pkiservPasswdFile);
                System.err.println("       " + e.getMessage());
                System.exit(1);
            }
        }

        // HSM options
        String hsmToken = cmd.getOptionValue("H");
        String hsmTokenPasswd = cmd.getOptionValue("P");
        String hsmTokenPasswdFile = cmd.getOptionValue("hsm-token-passwd-file");

        // Read HSM token password from file if specified
        if (hsmTokenPasswd == null && hsmTokenPasswdFile != null) {
            try {
                hsmTokenPasswd = new String(java.nio.file.Files.readAllBytes(
                    java.nio.file.Paths.get(hsmTokenPasswdFile))).trim();
            } catch (Exception e) {
                printError("Failed to read password from file: " + hsmTokenPasswdFile);
                System.err.println("       " + e.getMessage());
                System.exit(1);
            }
        }

        // CA options
        String caKeyAlgorithm = cmd.getOptionValue("ca-key-algorithm", "rsa");
        String caKeySize = cmd.getOptionValue("ca-key-size");
        String caSubject = cmd.getOptionValue("ca-subject", "CN=Test CA,O=Dogtag");
        int caValidity = Integer.parseInt(cmd.getOptionValue("ca-validity", "3650"));
        String caNickname = cmd.getOptionValue("ca-nickname", "test CA Signing Certificate");

        // Transport options
        String transportSubject = cmd.getOptionValue("transport-subject", "CN=test KRA Transport,O=Dogtag");
        int transportValidity = Integer.parseInt(cmd.getOptionValue("transport-validity", "365"));
        String transportNickname = cmd.getOptionValue("transport-nickname", "test KRA Transport Certificate");

        // Storage options
        String storageSubject = cmd.getOptionValue("storage-subject", "CN=test KRA Storage,O=Dogtag");
        int storageValidity = Integer.parseInt(cmd.getOptionValue("storage-validity", "365"));
        String storageNickname = cmd.getOptionValue("storage-nickname", "test KRA Storage Certificate");

        // Key usage options (for HSM-specific requirements)
        String transportOpFlagsStr = cmd.getOptionValue("transport-opflags", DEFAULT_OPFLAGS);
        String transportOpFlagsMaskStr = cmd.getOptionValue("transport-opflags-mask", transportOpFlagsStr);
        String storageOpFlagsStr = cmd.getOptionValue("storage-opflags", DEFAULT_OPFLAGS);
        String storageOpFlagsMaskStr = cmd.getOptionValue("storage-opflags-mask", storageOpFlagsStr);

        // Client database path
        String clientDB = cmd.getOptionValue("client-db-path", System.getProperty("user.home") + "/.dogtag-kra-compat/client-nssdb");

        // LDIF file path (default based on client-db-path)
        String ldifFile = cmd.getOptionValue("ldif-file", clientDB + "/kra-archived-key.ldif");

        // Test input files (from hsmCompatVerifyClnt)
        String wrappedSessionFile = cmd.getOptionValue("wrapped-session", clientDB + "/kra-test-wrapped-session.bin");
        String wrappedPrivateFile = cmd.getOptionValue("wrapped-private", clientDB + "/kra-test-wrapped-private.bin");
        String publicKeyFile = cmd.getOptionValue("public-key", clientDB + "/kra-test-public.der");
        String ivFile = cmd.getOptionValue("iv-file", clientDB + "/kra-test-iv.bin");

        // Test certificate parameters
        String subjectDN = cmd.getOptionValue("n");
        String algorithm = cmd.getOptionValue("a", "rsa");
        int keyLength = Integer.parseInt(cmd.getOptionValue("l", "2048"));
        String curve = cmd.getOptionValue("c", "nistp256");
        boolean sslECDH = Boolean.parseBoolean(cmd.getOptionValue("x", "false"));
        boolean temporary = Boolean.parseBoolean(cmd.getOptionValue("t", "true"));
        int sensitive = Integer.parseInt(cmd.getOptionValue("s", "-1"));
        int extractable = Integer.parseInt(cmd.getOptionValue("e", "-1"));
        String keywrapAlg = cmd.getOptionValue("w", "AES KeyWrap/Wrapped");
        String outputFile = cmd.getOptionValue("o");
        if (outputFile == null) {
            outputFile = clientDB + "/kra-recovered.p12";
        } else {
            // If relative path, resolve it relative to client-db-path
            java.io.File outputFileObj = new java.io.File(outputFile);
            if (!outputFileObj.isAbsolute()) {
                outputFile = clientDB + "/" + outputFile;
            }
        }
        String recoveryPasswd = cmd.getOptionValue("r");
        String recoveryPasswdFile = cmd.getOptionValue("recovery-passwd-file");

        // Read recovery password from file if specified
        if (recoveryPasswd == null && recoveryPasswdFile != null) {
            try {
                recoveryPasswd = new String(java.nio.file.Files.readAllBytes(
                    java.nio.file.Paths.get(recoveryPasswdFile))).trim();
            } catch (Exception e) {
                printError("Failed to read password from file: " + recoveryPasswdFile);
                System.err.println("       " + e.getMessage());
                System.exit(1);
            }
        }

        // Validate required parameters based on mode
        if (hsmToken == null) {
            printError("Missing HSM token name (--hsm-token)");
            System.exit(1);
        }
        if (hsmTokenPasswd == null) {
            printError("Missing HSM token password (--hsm-token-passwd)");
            System.exit(1);
        }

        // Validate mutually exclusive modes
        if (archiveOnly && recoverOnly) {
            printError("Cannot specify both --archive-only and --recover-only");
            System.exit(1);
        }

        if (setupOnly) {
            // Setup mode validation
            if (pkiservPasswd == null) {
                printError("Missing PKI server password (--pkiserv-passwd) - required for setup");
                System.exit(1);
            }
        } else {
            // Test mode validation
            if (recoverOnly) {
                // Recovery only mode - only need LDIF file and recovery password
                if (!new java.io.File(ldifFile).exists()) {
                    printError("LDIF file not found: " + ldifFile);
                    System.exit(1);
                }
                if (recoveryPasswd == null) {
                    printError("Missing recovery password (--recovery-passwd) - required for recovery");
                    System.exit(1);
                }
            } else {
                // Archive mode (with or without recovery) - check that wrapped key files exist
                if (!new java.io.File(wrappedSessionFile).exists()) {
                    printError("Wrapped session key file not found: " + wrappedSessionFile + "\n" +
                              "Run hsmCompatVerifyClnt first to generate test keys.");
                    System.exit(1);
                }
                if (!new java.io.File(wrappedPrivateFile).exists()) {
                    printError("Wrapped private key file not found: " + wrappedPrivateFile + "\n" +
                              "Run hsmCompatVerifyClnt first to generate test keys.");
                    System.exit(1);
                }
                if (!new java.io.File(publicKeyFile).exists()) {
                    printError("Public key file not found: " + publicKeyFile + "\n" +
                              "Run hsmCompatVerifyClnt first to generate test keys.");
                    System.exit(1);
                }
                if (subjectDN == null) {
                    printError("Missing subject DN (--subject-dn) - required for archival");
                    System.exit(1);
                }
                if (!archiveOnly && recoveryPasswd == null) {
                    printError("Missing recovery password (--recovery-passwd) - required for recovery");
                    System.exit(1);
                }
            }
        }

        try {
            hsmCompatVerifyServ tool = new hsmCompatVerifyServ();
            tool.setVerbose(verbose);
            tool.setUseOAEP(useOAEP);
            tool.setAutoYes(autoYes);

            if (setupOnly) {
                // Print setup configuration
                System.out.println("=== hsmCompatVerifyServ Setup Configuration ===");
                System.out.println("Parameters (including defaults):");
                System.out.println("  --setup-only");
                System.out.println("  --pkiserv-db-path " + pkiservDB);
                System.out.println("  --hsm-token \"" + hsmToken + "\"");
                System.out.println("  --ca-key-algorithm " + caKeyAlgorithm);
                if (caKeySize != null) {
                    System.out.println("  --ca-key-size " + caKeySize);
                } else {
                    System.out.println("  --ca-key-size " + (caKeyAlgorithm.equalsIgnoreCase("ec") ? "nistp256" : "4096") + " (default)");
                }
                System.out.println("  --ca-subject \"" + caSubject + "\"");
                System.out.println("  --ca-validity " + caValidity);
                System.out.println("  --ca-nickname \"" + caNickname + "\"");
                System.out.println("  --transport-subject \"" + transportSubject + "\"");
                System.out.println("  --transport-validity " + transportValidity);
                System.out.println("  --transport-nickname \"" + transportNickname + "\"");
                System.out.println("  --transport-opflags \"" + transportOpFlagsStr + "\"");
                System.out.println("  --storage-subject \"" + storageSubject + "\"");
                System.out.println("  --storage-validity " + storageValidity);
                System.out.println("  --storage-nickname \"" + storageNickname + "\"");
                System.out.println("  --storage-opflags \"" + storageOpFlagsStr + "\"");
                if (autoYes) {
                    System.out.println("  --yes");
                }
                System.out.println("  --verbose " + (verbose ? "enabled" : "disabled"));
                System.out.println();

                tool.runSetup(
                    pkiservDB, pkiservPasswd,
                    hsmToken, hsmTokenPasswd,
                    caKeyAlgorithm, caKeySize, caSubject, caValidity, caNickname,
                    transportSubject, transportValidity, transportNickname,
                    transportOpFlagsStr, transportOpFlagsMaskStr,
                    storageSubject, storageValidity, storageNickname,
                    storageOpFlagsStr, storageOpFlagsMaskStr
                );
                System.out.println();
                System.out.println("SUCCESS: Setup completed!");
            } else {
                // Print test configuration
                System.out.println("=== hsmCompatVerifyServ Verification Configuration ===");
                System.out.println("Parameters (including defaults):");
                System.out.println("  --pkiserv-db-path " + pkiservDB);
                System.out.println("  --hsm-token \"" + hsmToken + "\"");
                if (recoverOnly) {
                    System.out.println("  --recover-only");
                    System.out.println("  --ldif-file " + ldifFile);
                } else {
                    System.out.println("  --client-db-path " + clientDB);
                    System.out.println("  --wrapped-session " + wrappedSessionFile);
                    System.out.println("  --wrapped-private " + wrappedPrivateFile);
                    System.out.println("  --public-key " + publicKeyFile);
                    System.out.println("  --subject-dn \"" + subjectDN + "\"");
                    System.out.println("  --ldif-file " + ldifFile);
                    if (archiveOnly) {
                        System.out.println("  --archive-only");
                    }
                }
                System.out.println("  --ca-nickname \"" + caNickname + "\"");
                System.out.println("  --transport-nickname \"" + transportNickname + "\"");
                System.out.println("  --storage-nickname \"" + storageNickname + "\"");
                if (!archiveOnly) {
                    System.out.println("  --p12-output " + outputFile);
                }
                System.out.println("  --keywrap-alg \"" + keywrapAlg + "\"");
                System.out.println("  --rsa-keywrap " + rsaKeywrap);
                System.out.println("  --verbose " + (verbose ? "enabled" : "disabled"));
                System.out.println();

                tool.runTest(
                    pkiservDB,
                    clientDB,
                    wrappedSessionFile, wrappedPrivateFile, publicKeyFile, ivFile,
                    hsmToken, hsmTokenPasswd,
                    caNickname, transportNickname, storageNickname,
                    subjectDN,
                    outputFile, recoveryPasswd,
                    keywrapAlg,
                    archiveOnly,
                    recoverOnly,
                    ldifFile,
                    legacyPKCS12
                );
                System.out.println();
                if (archiveOnly) {
                    System.out.println("SUCCESS: Archival completed - LDIF file created!");
                    System.out.println("LDIF file: " + ldifFile);
                    System.out.println("Next: Run hsmCompatVerifyServ with --recover-only to verify recovery");
                } else {
                    System.out.println("SUCCESS: KRA compatibility verification completed!");
                    if (!recoverOnly) {
                        System.out.println("LDIF file: " + ldifFile);
                    }
                    System.out.println("Output: " + outputFile);
                }
            }

        } catch (Exception e) {
            System.err.println();
            printError(e.getMessage() != null ? e.getMessage() : e.getClass().getName());
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public void setUseOAEP(boolean useOAEP) {
        this.useOAEP = useOAEP;
    }

    public void setAutoYes(boolean autoYes) {
        this.autoYes = autoYes;
    }

    /**
     * Setup phase: Creates PKI infrastructure on HSM
     *
     * Creates three certificate/key pairs on the HSM:
     * 1. CA signing certificate (self-signed)
     * 2. KRA transport certificate (signed by CA)
     * 3. KRA storage certificate (signed by CA)
     *
     * Also stores public certificates in PKI server NSS DB for reference.
     *
     * Adopted from various PKI cert generation utilities, but simplified for testing.
     */
    public void runSetup(
        String pkiservDB,
        String pkiservPasswd,
        String hsmToken,
        String hsmTokenPasswd,
        String caKeyAlgorithm,
        String caKeySize,
        String caSubject,
        int caValidity,
        String caNickname,
        String transportSubject,
        int transportValidity,
        String transportNickname,
        String transportOpFlagsStr,
        String transportOpFlagsMaskStr,
        String storageSubject,
        int storageValidity,
        String storageNickname,
        String storageOpFlagsStr,
        String storageOpFlagsMaskStr
    ) throws Exception {

        log("=== KRA HSM Compatibility Verification - Setup Phase ===");
        log("Creating PKI infrastructure on HSM");
        log("");

        // Parse key usage flags
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] transportUsages = parseUsageFlags(transportOpFlagsStr);
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] transportUsagesMask = parseUsageFlags(transportOpFlagsMaskStr);
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] storageUsages = parseUsageFlags(storageOpFlagsStr);
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] storageUsagesMask = parseUsageFlags(storageOpFlagsMaskStr);

        // Initialize HSM
        log("Step 1: Initializing HSM");
        log("  HSM Token: " + hsmToken);

        // We need to initialize with pkisystem DB to have a place to store public certs
        CryptoManager.initialize(pkiservDB);
        CryptoManager manager = CryptoManager.getInstance();

        CryptoToken hsmTokenObj = CryptoUtil.getKeyStorageToken(hsmToken);
        if (hsmTokenObj == null) {
            throw new Exception("HSM token not found: " + hsmToken);
        }

        Password hsmPassword = new Password(hsmTokenPasswd.toCharArray());
        try {
            hsmTokenObj.login(hsmPassword);
            log("  - HSM token login successful");
        } catch (Exception e) {
            throw new Exception("Unable to login to HSM token: " + e.getMessage(), e);
        } finally {
            hsmPassword.clear();
        }

        // Initialize PKI server NSS DB
        log("");
        log("Step 2: Initializing PKI server NSS database");
        log("  PKI Server DB: " + pkiservDB);

        NSSDatabase pkiservNSSDB = new NSSDatabase(pkiservDB);
        PlainPasswordFile pkiservPasswordStore = new PlainPasswordFile();
        pkiservPasswordStore.putPassword("internal", pkiservPasswd);
        pkiservNSSDB.setPasswordStore(pkiservPasswordStore);

        CryptoToken internalToken = manager.getInternalKeyStorageToken();
        Password internalPassword = new Password(pkiservPasswd.toCharArray());
        try {
            internalToken.login(internalPassword);
            log("  - PKI system DB initialized");
        } catch (Exception e) {
            throw new Exception("Unable to initialize PKI system DB: " + e.getMessage(), e);
        } finally {
            internalPassword.clear();
        }

        // Check for and clean up existing certificates from previous runs
        cleanupExistingCerts(manager, hsmTokenObj, caNickname, transportNickname, storageNickname);

        // Create CA signing certificate
        log("");
        log("Step 3: Creating CA signing certificate on HSM");
        log("  Algorithm: " + caKeyAlgorithm.toUpperCase());
        X509Certificate caCert = handleCertificateCreation(
            manager, hsmTokenObj, caNickname, caSubject, caValidity,
            null, null, caKeyAlgorithm, caKeySize, "CA Signing Certificate",
            null, null  // CA cert doesn't need special usage flags
        );

        // Create transport certificate (always RSA-2048 for key wrapping)
        log("");
        log("Step 4: Creating KRA transport certificate on HSM");
        log("  Algorithm: RSA-2048 (required for key wrapping)");
        log("  Key Usage: " + transportOpFlagsStr);
        X509Certificate transportCert = handleCertificateCreation(
            manager, hsmTokenObj, transportNickname, transportSubject, transportValidity,
            caCert, caNickname, "rsa", "2048", "Transport Certificate",
            transportUsages, transportUsagesMask
        );

        // Create storage certificate (always RSA-2048 for key wrapping)
        log("");
        log("Step 5: Creating KRA storage certificate on HSM");
        log("  Algorithm: RSA-2048 (required for key wrapping)");
        log("  Key Usage: " + storageOpFlagsStr);
        X509Certificate storageCert = handleCertificateCreation(
            manager, hsmTokenObj, storageNickname, storageSubject, storageValidity,
            caCert, caNickname, "rsa", "2048", "Storage Certificate",
            storageUsages, storageUsagesMask
        );

        log("");
        log("=== Setup Summary ===");
        log("+ CA certificate: " + caNickname);
        log("+ Transport certificate: " + transportNickname);
        log("+ Storage certificate: " + storageNickname);
        log("+ All certificates created on HSM token: " + hsmToken);

        // Export transport certificate for use by hsmCompatVerifyClnt
        log("");
        log("Step 6: Exporting transport certificate for client use");
        String transportCertFile = pkiservDB + "/kra_transport.pem";
        byte[] transportCertBytes = transportCert.getEncoded();
        String transportCertPEM = org.mozilla.jss.netscape.security.util.Cert.HEADER + "\n" +
                java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(transportCertBytes) + "\n" +
                org.mozilla.jss.netscape.security.util.Cert.FOOTER;
        java.nio.file.Files.write(java.nio.file.Paths.get(transportCertFile), transportCertPEM.getBytes());
        log("  - Transport certificate exported to: " + transportCertFile);
        log("");
        log("NOTE: If running hsmCompatVerifyClnt as a different user (e.g. non-root),");
        log("      copy the transport certificate to a location accessible by that user:");
        log("      sudo cp " + transportCertFile + " ~otheruser/.dogtag-kra-compat/pkiserv-nssdb/");
        log("      sudo chown otheruser:otheruser ~otheruser/.dogtag-kra-compat/pkiserv-nssdb/kra_transport.pem");

        // Export storage certificate for other use
        log("");
        log("Step 7: Exporting storage certificate for other use");
        String storageCertFile = pkiservDB + "/kra_storage.pem";
        byte[] storageCertBytes = storageCert.getEncoded();
        String storageCertPEM = org.mozilla.jss.netscape.security.util.Cert.HEADER + "\n" +
                java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(storageCertBytes) + "\n" +
                org.mozilla.jss.netscape.security.util.Cert.FOOTER;
        java.nio.file.Files.write(java.nio.file.Paths.get(storageCertFile), storageCertPEM.getBytes());
        log("  - Storage certificate exported to: " + storageCertFile);
    }

    /**
     * Handles certificate creation with collision detection and user prompts.
     *
     * Returns existing certificate if user chooses to reuse,
     * or creates new certificate after deleting old one.
     *
     * @param keyAlgorithm "rsa" or "ec"
     * @param keySize For RSA: key size in bits (e.g. "2048", "4096"), For EC: curve name (e.g. "nistp256")
     */
    private X509Certificate handleCertificateCreation(
        CryptoManager manager,
        CryptoToken token,
        String nickname,
        String subject,
        int validityDays,
        X509Certificate issuerCert,
        String issuerNickname,
        String keyAlgorithm,
        String keySize,
        String certType,
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usages,
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usagesMask
    ) throws Exception {

        // Check if certificate already exists
        X509Certificate existingCert = null;
        try {
            existingCert = manager.findCertByNickname(nickname);
        } catch (ObjectNotFoundException e) {
            // Doesn't exist, we'll create it
        }

        if (existingCert != null) {
            log("  " + certType + " '" + nickname + "' already exists:");
            displayCertInfo(existingCert);

            // Ask if user wants to regenerate (default: No, keep existing)
            // With --yes flag, promptYesNo automatically returns true (regenerate)
            if (promptYesNo("  Regenerate certificate? (y/n): ")) {
                deleteCertAndKey(manager, token, nickname, existingCert);
                // Continue to create new cert
            } else {
                // User chose not to regenerate, keep existing
                log("  - Keeping existing " + certType.toLowerCase());
                return existingCert;
            }
        }

        // Create new certificate
        X509Certificate newCert;
        if (issuerCert == null) {
            // Self-signed CA (usages not applicable for CA signing cert)
            newCert = createSelfSignedCert(token, manager, nickname, subject, validityDays,
                                         keyAlgorithm, keySize);
        } else {
            // Signed by CA (pass usage flags for transport/storage certs)
            newCert = createSignedCert(token, manager, nickname, subject, validityDays,
                                     issuerCert, issuerNickname, keyAlgorithm, keySize,
                                     usages, usagesMask);
        }

        log("  - " + certType + " created: " + nickname);
        return newCert;
    }

    /**
     * Creates a self-signed certificate on the HSM.
     *
     * Adopted from various PKI cert generation utilities.
     * Simplified for testing purposes - supports RSA and EC key pairs.
     *
     * @param keyAlgorithm "rsa" or "ec"
     * @param keySize For RSA: key size in bits, For EC: curve name (if null, uses defaults: RSA=4096, EC=nistp256)
     */
    private X509Certificate createSelfSignedCert(
        CryptoToken token,
        CryptoManager manager,
        String nickname,
        String subject,
        int validityDays,
        String keyAlgorithm,
        String keySize
    ) throws Exception {

        // Generate key pair on HSM based on algorithm
        KeyPair keyPair;
        SignatureAlgorithm sigAlg;
        AlgorithmId algId;

        if (keyAlgorithm.equalsIgnoreCase("ec")) {
            String curve = (keySize != null) ? keySize : "nistp256";
            keyPair = CryptoUtil.generateECCKeyPair(token, curve);
            sigAlg = SignatureAlgorithm.ECSignatureWithSHA256Digest;
            algId = new AlgorithmId(AlgorithmId.sha256WithEC_oid);
        } else {
            // RSA (default)
            int rsaKeySize = (keySize != null) ? Integer.parseInt(keySize) : 4096;
            keyPair = CryptoUtil.generateRSAKeyPair(token, rsaKeySize);
            sigAlg = SignatureAlgorithm.RSASignatureWithSHA256Digest;
            algId = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid);
        }

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();

        // Prepare certificate parameters
        SecureRandom random = new SecureRandom();
        BigInteger serialNumber = new BigInteger(128, random);
        X500Name subjectName = new X500Name(subject);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + (validityDays * 24L * 60L * 60L * 1000L));
        X509Key x509key = CryptoUtil.createX509Key(publicKey);

        // Create CA certificate extensions
        // Based on: base/ca/shared/conf/caCert.profile
        CertificateExtensions extensions = createCACertExtensions(x509key);

        // Create certificate info using CryptoUtil
        // Based on: base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java:998-1027
        X509CertInfo certInfo = CryptoUtil.createX509CertInfo(
            x509key,
            serialNumber,
            new CertificateIssuerName(subjectName),  // issuer = subject (self-signed)
            subjectName,
            notBefore,
            notAfter,
            algId.getName(),
            extensions
        );

        // Sign the certificate using CryptoUtil
        // Based on: base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java:1041-1048
        X509CertImpl cert = CryptoUtil.signCert(privateKey, certInfo, algId.getName());

        // Import certificate with nickname - it will be associated with the private key on the HSM
        org.mozilla.jss.crypto.X509Certificate jssCert =
            manager.importCertPackage(cert.getEncoded(), nickname);

        return jssCert;
    }

    /**
     * Creates a certificate signed by the CA on the HSM.
     *
     * @param keyAlgorithm "rsa" or "ec"
     * @param keySize For RSA: key size in bits, For EC: curve name (if null, uses defaults: RSA=2048, EC=nistp256)
     * @param usages Key usage flags (null to use defaults)
     * @param usagesMask Key usage flags mask (null to use defaults)
     */
    private X509Certificate createSignedCert(
        CryptoToken token,
        CryptoManager manager,
        String nickname,
        String subject,
        int validityDays,
        X509Certificate issuerCert,
        String issuerNickname,
        String keyAlgorithm,
        String keySize,
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usages,
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usagesMask
    ) throws Exception {

        // Generate key pair on HSM based on algorithm with usage flags
        KeyPair keyPair;
        if (keyAlgorithm.equalsIgnoreCase("ec")) {
            String curve = (keySize != null) ? keySize : "nistp256";
            // EC keys don't support usage flags in current implementation
            keyPair = CryptoUtil.generateECCKeyPair(token, curve);
        } else {
            // RSA (default) - supports usage flags
            int rsaKeySize = (keySize != null) ? Integer.parseInt(keySize) : 2048;
            keyPair = CryptoUtil.generateRSAKeyPair(token, rsaKeySize, usages, usagesMask);
        }
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();

        // Find CA private key by matching public key (like NSSDatabase does)
        // Based on: base/common/src/main/java/org/dogtagpki/nss/NSSDatabase.java:1426-1446
        PrivateKey caPrivateKey = null;
        byte[] issuerPublicKeyBytes = issuerCert.getPublicKey().getEncoded();

        org.mozilla.jss.crypto.CryptoStore store = token.getCryptoStore();
        for (PrivateKey privKey : store.getPrivateKeys()) {
            try {
                org.mozilla.jss.pkcs11.PK11PrivKey pk11PrivKey = (org.mozilla.jss.pkcs11.PK11PrivKey) privKey;
                org.mozilla.jss.pkcs11.PK11PubKey pk11PubKey = pk11PrivKey.getPublicKey();
                if (pk11PubKey == null) {
                    continue; // Skip keys without accessible public key
                }
                byte[] pubKeyBytes = pk11PubKey.getEncoded();

                if (java.util.Arrays.equals(issuerPublicKeyBytes, pubKeyBytes)) {
                    caPrivateKey = privKey;
                    break;
                }
            } catch (Exception e) {
                // Skip keys that don't allow reading public key (common on HSMs)
                continue;
            }
        }

        if (caPrivateKey == null) {
            throw new Exception("CA private key not found for: " + issuerNickname);
        }

        // Prepare certificate parameters
        SecureRandom random = new SecureRandom();
        BigInteger serialNumber = new BigInteger(128, random);
        X500Name subjectName = new X500Name(subject);
        X500Name issuerName = new X500Name(issuerCert.getSubjectDN().toString());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + (validityDays * 24L * 60L * 60L * 1000L));
        X509Key x509key = CryptoUtil.createX509Key(publicKey);

        // Determine signature algorithm based on CA cert's key type
        String caKeyType = issuerCert.getPublicKey().getAlgorithm();
        String algName;
        if (caKeyType.equalsIgnoreCase("EC")) {
            algName = "SHA256withEC";
        } else {
            algName = "SHA256withRSA";
        }

        // Create certificate extensions for KRA transport/storage cert
        CertificateExtensions extensions = createKRACertExtensions(x509key, issuerCert);

        // Create certificate info using CryptoUtil
        // Based on: base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java:998-1027
        X509CertInfo certInfo = CryptoUtil.createX509CertInfo(
            x509key,
            serialNumber,
            new CertificateIssuerName(issuerName),  // CA is the issuer
            subjectName,
            notBefore,
            notAfter,
            algName,
            extensions
        );

        // Sign with CA private key using CryptoUtil
        // Based on: base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java:1041-1048
        X509CertImpl cert = CryptoUtil.signCert(caPrivateKey, certInfo, algName);

        // Import certificate - it will be associated with the private key on the HSM
        org.mozilla.jss.crypto.X509Certificate jssCert =
            manager.importCertPackage(cert.getEncoded(), nickname);

        return jssCert;
    }

    /**
     * Displays certificate information for user review.
     */
    private void displayCertInfo(X509Certificate cert) {
        log("    Subject: " + cert.getSubjectDN());
        log("    Issuer: " + cert.getIssuerDN());
        log("    Serial: 0x" + cert.getSerialNumber().toString(16));
        log("    Valid: " + cert.getNotBefore() + " to " + cert.getNotAfter());
    }

    /**
     * Deletes certificate and associated private key from HSM.
     *
     * Adopted from: PKI cert/key management utilities
     */
    private void deleteCertAndKey(
        CryptoManager manager,
        CryptoToken token,
        String nickname,
        X509Certificate cert
    ) throws Exception {

        // Find and delete private key
        try {
            PrivateKey privKey = manager.findPrivKeyByCert(cert);
            if (privKey != null) {
                token.getCryptoStore().deletePrivateKey(privKey);
                log("    OK Deleted private key");
            }
        } catch (Exception e) {
            log("    Note: Could not delete private key: " + e.getMessage());
        }

        // Delete certificate
        try {
            token.getCryptoStore().deleteCert(cert);
            log("    OK Deleted certificate");
        } catch (Exception e) {
            throw new Exception("Failed to delete certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Cleans up existing certificates from previous runs.
     *
     * Searches for certificates matching the configured nicknames and prompts
     * user for confirmation before deleting them along with their private keys.
     * This ensures a clean test environment for each setup run.
     */
    private void cleanupExistingCerts(
        CryptoManager manager,
        CryptoToken token,
        String caNickname,
        String transportNickname,
        String storageNickname
    ) throws Exception {

        java.util.Map<String, X509Certificate> foundCerts = new java.util.LinkedHashMap<>();

        // Check for existing certificates (with and without token prefix)
        String tokenName = token.getName();
        String[] nicknamesToCheck = {caNickname, transportNickname, storageNickname};

        for (String nickname : nicknamesToCheck) {
            // Try with token prefix first (for HSM certs)
            String fullNickname = tokenName + ":" + nickname;
            try {
                X509Certificate cert = manager.findCertByNickname(fullNickname);
                if (cert != null) {
                    foundCerts.put(fullNickname, cert);
                }
            } catch (ObjectNotFoundException e) {
                // Try without token prefix (for internal token certs)
                try {
                    X509Certificate cert = manager.findCertByNickname(nickname);
                    if (cert != null) {
                        foundCerts.put(nickname, cert);
                    }
                } catch (ObjectNotFoundException e2) {
                    // Certificate doesn't exist in either location, skip
                }
            }
        }

        if (foundCerts.isEmpty()) {
            // No existing certificates, nothing to clean up
            return;
        }

        // Inform user about what will be deleted
        log("");
        log("=== Existing Certificates Found ===");
        log("The following certificates from previous test runs were found:");
        log("");
        for (java.util.Map.Entry<String, X509Certificate> entry : foundCerts.entrySet()) {
            String nickname = entry.getKey();
            X509Certificate cert = entry.getValue();
            log("  Certificate: " + nickname);
            log("    Subject: " + cert.getSubjectDN());
            log("    Serial: 0x" + cert.getSerialNumber().toString(16));
            log("");
        }

        log("These certificates and their private keys will be deleted to ensure a clean test environment.");
        log("");
        log("Alternatives (press 'n' to cancel):");
        log("  1. Back up existing certificates, then re-run setup");
        log("  2. Use different nicknames with --ca-nickname, --transport-nickname, --storage-nickname options");
        log("");

        if (!promptYesNo("Delete existing certificates and private keys? (y/n): ")) {
            throw new Exception("Setup cancelled by user. Please back up certificates or use different nicknames.");
        }

        // Delete certificates and keys (handle duplicates by deleting repeatedly)
        for (java.util.Map.Entry<String, X509Certificate> entry : foundCerts.entrySet()) {
            String nickname = entry.getKey();

            // Delete all certificates with this nickname (handles duplicates)
            int deleteCount = 0;
            while (true) {
                try {
                    X509Certificate cert = manager.findCertByNickname(nickname);
                    if (cert == null) {
                        break;
                    }
                    deleteCertAndKey(manager, token, nickname, cert);
                    deleteCount++;
                } catch (ObjectNotFoundException e) {
                    // No more certificates with this nickname
                    break;
                }
            }

            if (deleteCount > 0) {
                log("  - Deleted: " + nickname + (deleteCount > 1 ? " (" + deleteCount + " duplicates)" : ""));
            }
        }
        log("");
    }

    /**
     * Prompts user for yes/no confirmation.
     * Returns true if --yes flag is set (non-interactive mode).
     */
    private boolean promptYesNo(String message) throws Exception {
        if (autoYes) {
            log(message + "yes (--yes flag)");
            return true;
        }

        System.out.print(message);
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String response = reader.readLine();
        if (response == null) {
            return false;
        }
        response = response.trim().toLowerCase();
        return response.equals("y") || response.equals("yes");
    }

    /**
     * Test phase: Runs archival and/or recovery workflow
     *
     * This method supports three modes:
     * 1. Archival only (archiveOnly=true): Archive keys to LDIF and stop
     * 2. Recovery only (recoverOnly=true): Read from LDIF and recover to PKCS#12
     * 3. Combined (neither flag): Full archival+recovery workflow (creates LDIF + recovers to PKCS#12)
     *
     * Adopted from: CRMFPopClient, EnrollmentService, RecoveryService,
     * TransportKeyUnit, StorageKeyUnit (see detailed comments inline)
     *
     * @param pkiservDB PKI system NSS database path - REQUIRED for HSM access.
     *                    CryptoManager must be initialized with this database because
     *                    it contains the modutil configuration that loads the
     *                    HSM PKCS#11 module. Without this, the HSM token won't be found.
     * @param clientDB Client NSS database directory (base path for wrapped key files and p12 output)
     * @param wrappedSessionFile Wrapped session key file (from hsmCompatVerifyClnt, null for recovery mode)
     * @param wrappedPrivateFile Wrapped private key file (from hsmCompatVerifyClnt, null for recovery mode)
     * @param publicKeyFile Public key file in DER format (from hsmCompatVerifyClnt, null for recovery mode)
     * @param archiveOnly If true, create LDIF and stop (archival only mode, no recovery)
     * @param recoverOnly If true, read from existing LDIF file (recovery only mode, no archival)
     * @param ldifFile LDIF file path for archival output or recovery input
     */
    public void runTest(
        String pkiservDB,
        String clientDB,
        String wrappedSessionFile,
        String wrappedPrivateFile,
        String publicKeyFile,
        String ivFile,
        String hsmToken,
        String hsmTokenPasswd,
        String caNickname,
        String transportNickname,
        String storageNickname,
        String subjectDN,
        String outputFile,
        String recoveryPasswd,
        String keywrapAlg,
        boolean archiveOnly,
        boolean recoverOnly,
        String ldifFile,
        boolean legacyPKCS12
    ) throws Exception {

        log("=== KRA HSM Compatibility Verification - Verification Phase ===");
        if (recoverOnly) {
            log("Mode: Recovery from LDIF file");
        } else if (archiveOnly) {
            log("Mode: Archival to LDIF file (no recovery)");
        } else {
            log("Mode: Full archival and recovery workflow");
        }
        log("");

        // Step 1: Initialize NSS with PKI server DB (for HSM access via modutil)
        // The PKI server DB has HSM module configured via modutil, allowing access to HSM
        // Adopted from: base/tools/src/main/java/com/netscape/cmstools/CRMFPopClient.java:410-428
        log("Step 1: Initializing NSS database");
        log("  PKI Server DB: " + pkiservDB + " (for HSM access)");

        // Initialize with PKI server DB so HSM module is loaded
        CryptoManager.initialize(pkiservDB);
        CryptoManager manager = CryptoManager.getInstance();

        // Step 2: Initialize HSM
        // Adopted from: base/kra/src/main/java/com/netscape/kra/StorageKeyUnit.java:248-253
        log("");
        log("Step 2: Initializing HSM");
        log("  HSM Token: " + hsmToken);

        CryptoToken hsmTokenObj = CryptoUtil.getKeyStorageToken(hsmToken);
        if (hsmTokenObj == null) {
            throw new Exception("HSM token not found: " + hsmToken);
        }

        Password hsmPassword = new Password(hsmTokenPasswd.toCharArray());
        try {
            hsmTokenObj.login(hsmPassword);
            log("  - HSM token login successful");
        } catch (Exception e) {
            throw new Exception("Unable to login to HSM token: " + e.getMessage(), e);
        } finally {
            hsmPassword.clear();
        }

        // Step 3: Load CA, transport, and storage certificates from HSM
        // Adopted from: base/kra/src/main/java/com/netscape/kra/TransportKeyUnit.java:80-109
        log("");
        log("Step 3: Loading CA and KRA certificates from HSM");
        log("  CA cert: " + caNickname);
        log("  Transport cert: " + transportNickname);
        log("  Storage cert: " + storageNickname);

        // Certificates on HSM are stored with token prefix
        String hsmTokenName = hsmTokenObj.getName();
        String caCertNickname = hsmTokenName + ":" + caNickname;
        String transportCertNickname = hsmTokenName + ":" + transportNickname;
        String storageCertNickname = hsmTokenName + ":" + storageNickname;

        X509Certificate caCert = manager.findCertByNickname(caCertNickname);
        if (caCert == null) {
            throw new Exception("CA certificate not found: " + caCertNickname);
        }
        log("  - CA certificate loaded");

        X509Certificate transportCert = manager.findCertByNickname(transportCertNickname);
        if (transportCert == null) {
            throw new Exception("Transport certificate not found: " + transportCertNickname);
        }
        log("  - Transport certificate loaded");

        X509Certificate storageCert = manager.findCertByNickname(storageCertNickname);
        if (storageCert == null) {
            throw new Exception("Storage certificate not found: " + storageCertNickname);
        }
        log("  - Storage certificate loaded");

        // Find private keys on HSM
        PrivateKey transportPrivateKey = manager.findPrivKeyByCert(transportCert);
        if (transportPrivateKey == null) {
            throw new Exception("Transport private key not found on HSM");
        }
        log("  - Transport private key found on HSM");

        PrivateKey storagePrivateKey = manager.findPrivKeyByCert(storageCert);
        if (storagePrivateKey == null) {
            throw new Exception("Storage private key not found on HSM");
        }
        log("  - Storage private key found on HSM");

        // Determine RSA wrap algorithm (based on --oaep flag)
        KeyWrapAlgorithm rsaWrapAlg = useOAEP ? KeyWrapAlgorithm.RSA_OAEP : KeyWrapAlgorithm.RSA;
        KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.fromString(keywrapAlg);

        // Variables for recovery (populated differently based on mode)
        byte[] archivedUserPrivate = null;
        byte[] wrappedStorageSessionKey = null;
        PublicKey userPublicKey = null;
        X509CertImpl userCert = null;
        org.mozilla.jss.crypto.IVParameterSpec storageIvSpec = null;

        // Mode 1: Recovery from LDIF
        if (recoverOnly) {
            log("");
            log("Step 4: Reading archived key data from LDIF file");

            java.util.List<Map<String, Object>> keyRecords = readLDIFFile(ldifFile);

            // Process each key record
            int successCount = 0;
            java.util.List<String> outputFiles = new java.util.ArrayList<>();

            for (int recordNum = 0; recordNum < keyRecords.size(); recordNum++) {
                Map<String, Object> ldifData = keyRecords.get(recordNum);

                log("");
                log("Processing key record " + (recordNum + 1) + " of " + keyRecords.size());
                log("  Serial: " + ldifData.get("serialno"));
                log("  Owner: " + ldifData.get("ownerName"));

                archivedUserPrivate = (byte[]) ldifData.get("wrappedPrivateKey");
                wrappedStorageSessionKey = (byte[]) ldifData.get("wrappedSessionKey");
                userPublicKey = (PublicKey) ldifData.get("publicKey");
                byte[] ivBytes = (byte[]) ldifData.get("payloadWrapIV");
                storageIvSpec = null;
                if (ivBytes != null) {
                    storageIvSpec = new org.mozilla.jss.crypto.IVParameterSpec(ivBytes);
                }

                // Create user certificate using owner name from LDIF (or use provided subjectDN)
                String certSubjectDN = (String) ldifData.get("ownerName");
                if (certSubjectDN == null || certSubjectDN.isEmpty()) {
                    certSubjectDN = subjectDN != null ? subjectDN : "CN=Recovered User";
                }

                log("");
                log("Step 4a: Creating user certificate signed by CA");
                userCert = createUserCert(
                    hsmTokenObj,
                    manager,
                    caCert,
                    caNickname,
                    certSubjectDN,
                    userPublicKey
                );
                log("  - User certificate created and signed by CA");

                // Step 7: KRA recovery - unwrap from storage on HSM
                log("");
                log("Step 7: KRA recovery - unwrapping with storage key on HSM");

                SymmetricKey recoveredStorageSessionKey = CryptoUtil.unwrap(
                    hsmTokenObj,
                    SymmetricKey.AES,
                    128,
                    SymmetricKey.Usage.UNWRAP,
                    storagePrivateKey,
                    wrappedStorageSessionKey,
                    rsaWrapAlg
                );
                log("  - Storage session key unwrapped using storage private key on HSM");

                PrivateKey recoveredUserPrivate = CryptoUtil.unwrap(
                    hsmTokenObj,
                    userPublicKey,
                    true,
                    recoveredStorageSessionKey,
                    archivedUserPrivate,
                    keyWrapAlgorithm,
                    storageIvSpec  // IV: must match the IV used during wrapping
                );
                log("  - User private key recovered from archive on HSM");

                // Step 8: Create PKCS#12 with recovered key and CA-signed certificate
                log("");
                log("Step 8: Creating PKCS#12 file");

                // Generate unique output filename
                String recordOutputFile;
                if (keyRecords.size() == 1) {
                    recordOutputFile = outputFile;
                } else {
                    // Multiple records - append serial number or index
                    String serialno = (String) ldifData.get("serialno");
                    String baseName = outputFile;
                    String suffix = ".p12";
                    if (baseName.endsWith(".p12")) {
                        baseName = baseName.substring(0, baseName.length() - 4);
                    }
                    if (serialno != null && !serialno.isEmpty()) {
                        recordOutputFile = baseName + "-" + serialno + suffix;
                    } else {
                        recordOutputFile = baseName + "-" + (recordNum + 1) + suffix;
                    }
                }

                // Create PKCS#12 file with recovered key
                createPKCS12(
                    userCert,
                    recoveredUserPrivate,
                    hsmTokenObj,
                    recoveryPasswd,
                    recordOutputFile,
                    legacyPKCS12
                );

                log("  - PKCS#12 file created: " + recordOutputFile);
                log("  - PKCS#12 format: " + (legacyPKCS12 ? "Legacy (PBE_SHA1_DES3_CBC)" : "Non-legacy (AES-KWP)"));
                log("  - Using token: " + hsmTokenObj.getName());

                outputFiles.add(recordOutputFile);
                successCount++;
            }

            // Summary for LDIF recovery mode
            log("");
            log("=== Recovery Summary ===");
            log("+ Processed " + keyRecords.size() + " key record(s)");
            log("+ Successfully recovered " + successCount + " key(s)");
            log("+ All cryptographic operations completed successfully");
            log("");
            log("=== Output Files ===");
            for (String outFile : outputFiles) {
                log("+ PKCS#12 file: " + outFile);
            }

            return;  // Exit early for recovery mode

        } else {
            // Mode 2 & 3: Archival mode (with or without recovery)
            // Step 4: Load wrapped keys and public key from files
            // These were generated by hsmCompatVerifyClnt
            log("");
            log("Step 4: Loading wrapped keys from files (generated by hsmCompatVerifyClnt)");
            log("  Wrapped session key: " + wrappedSessionFile);
            log("  Wrapped private key: " + wrappedPrivateFile);
            log("  Public key: " + publicKeyFile);

            byte[] wrappedSessionKey = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(wrappedSessionFile));
            log("  - Wrapped session key loaded (" + wrappedSessionKey.length + " bytes)");

            byte[] wrappedUserPrivate = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(wrappedPrivateFile));
            log("  - Wrapped private key loaded (" + wrappedUserPrivate.length + " bytes)");

            byte[] publicKeyBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(publicKeyFile));
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            userPublicKey = keyFactory.generatePublic(
                new java.security.spec.X509EncodedKeySpec(publicKeyBytes)
            );
            log("  - Public key loaded (" + publicKeyBytes.length + " bytes)");

            // Load IV only if the algorithm requires it (CBC mode algorithms)
            // Don't load IV for KeyWrap algorithms even if the file exists
            org.mozilla.jss.crypto.IVParameterSpec ivSpec = null;
            if (keyWrapAlgorithm.getBlockSize() > 0 &&
                !keywrapAlg.toLowerCase().contains("keywrap")) {
                // CBC mode - IV is required
                java.nio.file.Path ivPath = java.nio.file.Paths.get(ivFile);
                if (java.nio.file.Files.exists(ivPath)) {
                    byte[] ivBytes = java.nio.file.Files.readAllBytes(ivPath);
                    ivSpec = new org.mozilla.jss.crypto.IVParameterSpec(ivBytes);
                    log("  - IV loaded (" + ivBytes.length + " bytes)");
                } else {
                    throw new Exception("IV file required for " + keywrapAlg + " but not found: " + ivFile);
                }
            }

            // Step 4a: Create user certificate signed by CA
            // This simulates getting a certificate from CA before archival
            log("");
            log("Step 4a: Creating user certificate signed by CA");

            userCert = createUserCert(
                hsmTokenObj,
                manager,
                caCert,
                caNickname,
                subjectDN,
                userPublicKey
            );
            log("  - User certificate created and signed by CA");

            // Step 5: KRA archival - unwrap from transport on HSM
            // Adopted from: base/kra/src/main/java/com/netscape/kra/TransportKeyUnit.java:413-450
            // and base/kra/src/main/java/com/netscape/kra/EnrollmentService.java:326-349
            log("");
            log("Step 5: KRA archival - unwrapping with transport key on HSM");

            SymmetricKey unwrappedSessionKey = null;
                try {
                    log("  Attempting: Unwrap AES-128 session key using " + rsaWrapAlg + " with RSA transport private key");
                unwrappedSessionKey = CryptoUtil.unwrap(
                    hsmTokenObj,
                    SymmetricKey.AES,
                    128,
                    SymmetricKey.Usage.UNWRAP,
                    transportPrivateKey,
                    wrappedSessionKey,
                    rsaWrapAlg
                );
                log("  - Session key unwrapped using transport private key on HSM");
            } catch (Exception e) {
                logError("Failed to unwrap session key on HSM", rsaWrapAlg.toString(),
                        "Unwrap AES-128 symmetric key using RSA private key", e);
                throw e;
            }

            // Unwrap user private key with transport session key
            PrivateKey unwrappedUserPrivate = null;
            try {
                log("  Attempting: Unwrap RSA private key using " + keyWrapAlgorithm + " with AES session key");
                unwrappedUserPrivate = CryptoUtil.unwrap(
                    hsmTokenObj,
                    userPublicKey,
                    true,
                    unwrappedSessionKey,
                    wrappedUserPrivate,
                    keyWrapAlgorithm,
                    ivSpec  // IV: null for KeyWrap algorithms, non-null for CBC algorithms
                );
                log("  - User private key unwrapped on HSM");
            } catch (Exception e) {
                logError("Failed to unwrap user private key on HSM", keyWrapAlgorithm.toString(),
                        "Unwrap RSA private key using AES symmetric key", e);
                throw e;
            }

            // Step 6: KRA archival - rewrap with storage key on HSM
            // Adopted from: base/kra/src/main/java/com/netscape/kra/StorageKeyUnit.java:1158-1234
            log("");
            log("Step 6: KRA archival - re-wrapping with storage key on HSM");

            // Generate storage session key with WRAP/UNWRAP usages (matches StorageKeyUnit)
            SymmetricKey storageSessionKey = null;
            try {
                log("  Attempting: Generate AES-128 storage session key on HSM");
                storageSessionKey = CryptoUtil.generateKey(
                    hsmTokenObj,
                    KeyGenAlgorithm.AES,
                    128,
                    STORAGE_KEY_USAGES,
                    true
                );
                log("  - Storage session key generated on HSM");
            } catch (Exception e) {
                logError("Failed to generate storage session key", "AES-128 KeyGen",
                        "Generate temporary AES key with WRAP/UNWRAP usage", e);
                throw e;
            }

            // Generate IV for storage wrapping if using CBC mode
            if (keyWrapAlgorithm.getBlockSize() > 0 &&
                !keywrapAlg.toLowerCase().contains("keywrap")) {
                byte[] storageIv = CryptoUtil.getNonceData(keyWrapAlgorithm.getBlockSize());
                storageIvSpec = new org.mozilla.jss.crypto.IVParameterSpec(storageIv);
            }

            try {
                log("  Attempting: Wrap RSA private key using " + keyWrapAlgorithm + " with AES storage session key");
                archivedUserPrivate = CryptoUtil.wrapUsingSymmetricKey(
                    hsmTokenObj,
                    storageSessionKey,
                    unwrappedUserPrivate,
                    storageIvSpec,  // IV: null for KeyWrap algorithms, non-null for CBC
                    keyWrapAlgorithm
                );
                log("  - User private key wrapped with storage session key on HSM");
            } catch (Exception e) {
                logError("Failed to wrap user private key with storage session key", keyWrapAlgorithm.toString(),
                        "Wrap RSA private key using AES symmetric key", e);
                throw e;
            }

            try {
                log("  Attempting: Wrap AES storage session key using " + rsaWrapAlg + " with RSA storage public key");
                wrappedStorageSessionKey = CryptoUtil.wrapUsingPublicKey(
                    hsmTokenObj,
                    storageCert.getPublicKey(),
                    storageSessionKey,
                    rsaWrapAlg
                );
                log("  - Storage session key wrapped with storage public key on HSM");
                log("  (User key is now 'archived')");
            } catch (Exception e) {
                logError("Failed to wrap storage session key with public key", rsaWrapAlg.toString(),
                        "Wrap AES symmetric key using RSA public key", e);
                throw e;
            }

            // Step 6a: Create LDIF file with archived data (always created during archival)
            log("");
            log("Step 6a: Creating LDIF file with archived key data");

            createLDIFFile(
                ldifFile,
                userCert,
                userPublicKey,
                archivedUserPrivate,
                wrappedStorageSessionKey,
                rsaWrapAlg,
                keyWrapAlgorithm,
                storageIvSpec,
                subjectDN
            );

            log("  - LDIF file created: " + ldifFile);

            // If archive-only mode, stop here
            if (archiveOnly) {
                log("");
                log("=== Archival Summary ===");
                log("+ LDIF file: " + ldifFile);
                log("+ Archival completed successfully");
                log("");
                log("To test recovery, run:");
                log("  hsmCompatVerifyServ --recover-only \\");
                log("    --hsm-token \"" + hsmToken + "\" --hsm-token-passwd <password> \\");
                log("    --p12-output <output.p12> --recovery-passwd <password>");
                return;  // Stop here in archival-only mode
            }

            // Step 7: KRA recovery - unwrap from storage on HSM
            // Adopted from: base/kra/src/main/java/com/netscape/kra/StorageKeyUnit.java:1296-1319
            // and base/kra/src/main/java/com/netscape/kra/RecoveryService.java:510-554
            log("");
            log("Step 7: KRA recovery - unwrapping with storage key on HSM");

            SymmetricKey recoveredStorageSessionKey = CryptoUtil.unwrap(
                hsmTokenObj,
                SymmetricKey.AES,
                128,
                SymmetricKey.Usage.UNWRAP,
                storagePrivateKey,
                wrappedStorageSessionKey,
                rsaWrapAlg
            );
            log("  - Storage session key unwrapped using storage private key on HSM");

            PrivateKey recoveredUserPrivate = CryptoUtil.unwrap(
                hsmTokenObj,
                userPublicKey,
                true,
                recoveredStorageSessionKey,
                archivedUserPrivate,
                keyWrapAlgorithm,
                storageIvSpec  // IV: must match the IV used during wrapping
            );
            log("  - User private key recovered from archive on HSM");

            // Step 8: Create PKCS#12 with recovered key and CA-signed certificate
            // Adopted from: base/kra/src/main/java/com/netscape/kra/RecoveryService.java:564-724
            log("");
            log("Step 8: Creating PKCS#12 file");

            // Use HSM token for P12 creation (same token where key was recovered)
            // This matches KRA's pattern where ct (P12 token) is used for both key recovery and P12 creation
            createPKCS12(
                userCert,
                recoveredUserPrivate,
                hsmTokenObj,
                recoveryPasswd,
                outputFile,
                legacyPKCS12
            );

            log("  - PKCS#12 file created: " + outputFile);
            log("  - PKCS#12 format: " + (legacyPKCS12 ? "Legacy (PBE_SHA1_DES3_CBC)" : "Non-legacy (AES-KWP)"));
            log("  - Using token: " + hsmTokenObj.getName());

            // Verification Summary
            log("");
            log("=== Verification Summary ===");
            log("+ All cryptographic operations completed successfully");
            log("+ HSM/PKCS#11 token supports required KRA mechanisms:");
            log("  - CA certificate signing");
            log("  - User certificate issuance (CA-signed)");
            log("  - Session key unwrapping with transport private key (HSM)");
            log("  - Private key unwrapping with session key (HSM)");
            log("  - Storage session key generation (HSM)");
            log("  - Key wrapping/unwrapping with symmetric keys (HSM)");
            log("  - Key wrapping with storage public key (HSM)");
            log("  - Key unwrapping with storage private key (HSM)");
            log("  - RSA key wrapping" + (useOAEP ? " with OAEP" : ""));
            log("  - PKCS#12 creation");
            log("  - Complete key archival and recovery workflow");
            log("");
            log("=== Output Files ===");
            if (ldifFile != null) {
                log("+ LDIF archive file: " + ldifFile);
            }
            log("+ PKCS#12 file: " + outputFile);
        }
    }

    /**
     * Creates a user certificate signed by the CA.
     *
     * This simulates the certificate issuance that would happen before key archival.
     * The certificate is signed by the CA on the HSM.
     *
     * @param hsmToken HSM token where CA private key resides
     * @param manager CryptoManager instance
     * @param caCert CA certificate
     * @param caNickname CA certificate nickname
     * @param subjectDN User subject DN
     * @param userPublicKey User's public key to be certified
     * @return User certificate signed by CA
     */
    private X509CertImpl createUserCert(
        CryptoToken hsmToken,
        CryptoManager manager,
        X509Certificate caCert,
        String caNickname,
        String subjectDN,
        PublicKey userPublicKey
    ) throws Exception {

        // Find CA private key on HSM
        PrivateKey caPrivateKey = manager.findPrivKeyByCert(caCert);
        if (caPrivateKey == null) {
            throw new Exception("CA private key not found for: " + caNickname);
        }

        // Prepare certificate parameters
        SecureRandom random = new SecureRandom();
        BigInteger serialNumber = new BigInteger(128, random);
        X500Name subjectName = new X500Name(subjectDN);
        X500Name issuerName = new X500Name(caCert.getSubjectDN().toString());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + (365L * 24L * 60L * 60L * 1000L));  // 1 year validity
        X509Key x509key = CryptoUtil.createX509Key(userPublicKey);

        // Determine signature algorithm based on CA cert's key type
        String caKeyType = caCert.getPublicKey().getAlgorithm();
        String algName;
        if (caKeyType.equalsIgnoreCase("EC")) {
            algName = "SHA256withEC";
        } else {
            algName = "SHA256withRSA";
        }

        // Create certificate extensions for user cert
        CertificateExtensions extensions = createUserCertExtensions(x509key, caCert);

        // Create certificate info using CryptoUtil
        // Based on: base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java:998-1027
        X509CertInfo certInfo = CryptoUtil.createX509CertInfo(
            x509key,
            serialNumber,
            new CertificateIssuerName(issuerName),  // CA is the issuer
            subjectName,
            notBefore,
            notAfter,
            algName,
            extensions
        );

        // Sign with CA private key using CryptoUtil
        // Based on: base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java:1041-1048
        X509CertImpl cert = CryptoUtil.signCert(caPrivateKey, certInfo, algName);

        return cert;
    }

    /**
     * Creates a minimal self-signed test certificate.
     *
     * This is a simplified version for testing. In production, a proper
     * certificate would be issued by the CA.
     */
    private X509CertImpl createMinimalTestCert(
        CryptoToken token,
        String subject,
        PublicKey publicKey,
        PrivateKey privateKey
    ) throws Exception {

        // Prepare certificate parameters
        SecureRandom random = new SecureRandom();
        BigInteger serialNumber = new BigInteger(128, random);
        X500Name subjectName = new X500Name(subject);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + (24L * 60L * 60L * 1000L));  // 1 day validity
        X509Key x509key = CryptoUtil.createX509Key(publicKey);

        // Determine signature algorithm based on key type
        String keyType = publicKey.getAlgorithm();
        String algName;
        if (keyType.equalsIgnoreCase("EC")) {
            algName = "SHA256withEC";
        } else {
            algName = "SHA256withRSA";
        }

        // Create certificate info using CryptoUtil
        // Based on: base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java:998-1027
        X509CertInfo certInfo = CryptoUtil.createX509CertInfo(
            x509key,
            serialNumber,
            new CertificateIssuerName(subjectName),  // issuer = subject (self-signed)
            subjectName,
            notBefore,
            notAfter,
            algName,
            null  // no extensions for test cert
        );

        // Sign using CryptoUtil
        // Based on: base/common/src/main/java/com/netscape/cmsutil/crypto/CryptoUtil.java:1041-1048
        X509CertImpl cert = CryptoUtil.signCert(privateKey, certInfo, algName);

        return cert;
    }

    /**
     * Creates a PKCS#12 file with the recovered private key.
     *
     * Adopted from: base/kra/src/main/java/com/netscape/kra/RecoveryService.java:564-724
     * (createPFX method with PrivateKey parameter)
     *
     * Differences: Simplified, no request object, no audit logging, always legacy PKCS#12
     */
    private void createPKCS12(
        X509CertImpl cert,
        PrivateKey privateKey,
        CryptoToken token,
        String password,
        String outputFile,
        boolean legacyPKCS12
    ) throws Exception {

        Password pass = new Password(password.toCharArray());

        try {
            // Add certificate to PKCS#12
            SEQUENCE encSafeContents = new SEQUENCE();
            ASN1Value certValue = new OCTET_STRING(cert.getEncoded());

            byte[] localKeyId = createLocalKeyId(cert);
            SET certAttrs = createBagAttrs(cert.getSubjectDN().toString(), localKeyId);

            SafeBag certBag = new SafeBag(
                SafeBag.CERT_BAG,
                new CertBag(CertBag.X509_CERT_TYPE, certValue),
                certAttrs
            );
            encSafeContents.addElement(certBag);

            // Add private key to PKCS#12
            SEQUENCE safeContents = new SEQUENCE();

            ASN1Value key;
            if (legacyPKCS12) {
                // Legacy PKCS#12: PBE_SHA1_DES3_CBC
                // Compatible with older systems but may fail on some HSMs (e.g., Thales FIPS 140-3)
                PasswordConverter passConverter = new PasswordConverter();
                SecureRandom random = new SecureRandom();
                byte[] salt = new byte[20];
                random.nextBytes(salt);

                key = EncryptedPrivateKeyInfo.createPBE(
                    PBEAlgorithm.PBE_SHA1_DES3_CBC,
                    pass,
                    salt,
                    1,
                    passConverter,
                    privateKey,
                    token
                );
            } else {
                // Non-legacy PKCS#12: AES Key Wrap with Padding (AES-KWP)
                // This matches the recommended KRA settings for HSM compatibility:
                //   keyWrap.useOAEP=true
                //   kra.legacyPKCS12=false
                //   kra.nonLegacyAlg=AES/None/PKCS5Padding/Kwp/256
                // AES-KWP is secure, modern, and compatible with HSMs in FIPS mode
                // Unlike AES-CBC, KWP doesn't require an IV, avoiding HSM compatibility issues
                String nonLegacyAlg = "AES/None/PKCS5Padding/Kwp/256";
                EncryptionAlgorithm encAlg = EncryptionAlgorithm.fromString(nonLegacyAlg);
                if (encAlg == null) {
                    // Fallback to AES-256-CBC if KWP is not available
                    encAlg = EncryptionAlgorithm.AES_256_CBC;
                }
                byte[] epkiBytes = token.getCryptoStore().getEncryptedPrivateKeyInfo(
                    null, // No password converter for non-legacy
                    pass,
                    encAlg,
                    0, // Use default iterations
                    privateKey
                );
                key = new ANY(epkiBytes);
            }

            SET keyAttrs = createBagAttrs(cert.getSubjectDN().toString(), localKeyId);
            SafeBag keyBag = new SafeBag(SafeBag.PKCS8_SHROUDED_KEY_BAG, key, keyAttrs);
            safeContents.addElement(keyBag);

            // Build PKCS#12 structure
            AuthenticatedSafes authSafes = new AuthenticatedSafes();
            authSafes.addSafeContents(safeContents);
            authSafes.addSafeContents(encSafeContents);

            PFX pfx = new PFX(authSafes);
            pfx.computeMacData(pass, null, 5);

            // Write to file
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 FileOutputStream fos = new FileOutputStream(outputFile)) {
                pfx.encode(baos);
                fos.write(baos.toByteArray());
            }

        } finally {
            pass.clear();
        }
    }

    /**
     * Creates a local key identifier (SHA-1 hash of certificate).
     *
     * Adopted from: base/kra/src/main/java/com/netscape/kra/RecoveryService.java:897-917
     * Difference: None, identical implementation
     */
    private byte[] createLocalKeyId(X509CertImpl cert) throws Exception {
        try {
            byte[] certDer = cert.getEncoded();
            MessageDigest md = MessageDigest.getInstance("SHA");
            md.update(certDer);
            return md.digest();
        } catch (CertificateEncodingException e) {
            throw new Exception("Failed to create local key ID: " + e.getMessage(), e);
        }
    }

    /**
     * Creates bag attributes for PKCS#12 (friendly name and local key ID).
     *
     * Adopted from: base/kra/src/main/java/com/netscape/kra/RecoveryService.java:922-947
     * Difference: None, identical implementation
     */
    private SET createBagAttrs(String nickName, byte[] localKeyId) throws Exception {
        SET attrs = new SET();

        SEQUENCE nickNameAttr = new SEQUENCE();
        nickNameAttr.addElement(SafeBag.FRIENDLY_NAME);
        SET nickNameSet = new SET();
        nickNameSet.addElement(new BMPString(nickName));
        nickNameAttr.addElement(nickNameSet);
        attrs.addElement(nickNameAttr);

        SEQUENCE localKeyAttr = new SEQUENCE();
        localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);
        SET localKeySet = new SET();
        localKeySet.addElement(new OCTET_STRING(localKeyId));
        localKeyAttr.addElement(localKeySet);
        attrs.addElement(localKeyAttr);

        return attrs;
    }

    /**
     * Parses comma-separated key usage flags into Usage array.
     * Valid flags: encrypt, decrypt, sign, sign_recover, verify, verify_recover, wrap, unwrap, derive
     *
     * @param flagsStr Comma-separated list of flags, or null for defaults
     * @return Array of Usage enums, or null if flagsStr is null/empty
     */
    private org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] parseUsageFlags(String flagsStr) throws Exception {
        if (flagsStr == null || flagsStr.trim().isEmpty()) {
            return null;
        }

        String[] flagNames = flagsStr.split(",");
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usages =
            new org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[flagNames.length];

        for (int i = 0; i < flagNames.length; i++) {
            String flag = flagNames[i].trim().toUpperCase();
            try {
                usages[i] = org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.valueOf(flag);
            } catch (IllegalArgumentException e) {
                throw new Exception("Invalid key usage flag: " + flagNames[i].trim() +
                    ". Valid flags: encrypt, decrypt, sign, sign_recover, verify, verify_recover, wrap, unwrap, derive");
            }
        }
        return usages;
    }

    /**
     * Creates certificate extensions for CA signing certificate.
     *
     * Uses NSSExtensionGenerator with hardcoded defaults that match:
     * base/ca/shared/conf/caCert.profile
     *
     * Extensions:
     * - Subject Key Identifier (hash)
     * - Authority Key Identifier (keyid, self-signed so same as subject)
     * - Basic Constraints (critical, CA:TRUE, pathlen:-1)
     * - Key Usage (critical: digitalSignature, nonRepudiation, keyCertSign, cRLSign)
     */
    private CertificateExtensions createCACertExtensions(X509Key publicKey) throws Exception {
        NSSExtensionGenerator generator = new NSSExtensionGenerator();

        // Hardcoded parameters matching caCert.profile
        Map<String, String> params = new java.util.LinkedHashMap<>();
        params.put("subjectKeyIdentifier", "hash");
        params.put("authorityKeyIdentifier", "keyid");
        params.put("basicConstraints", "critical,CA:TRUE,pathlen:-1");
        params.put("keyUsage", "critical,digitalSignature,nonRepudiation,keyCertSign,cRLSign");

        generator.setParameters(params);

        // Generate Extensions
        Extensions extensions = generator.createExtensions(publicKey, null, null);

        // Convert Extensions to CertificateExtensions
        return convertToCertificateExtensions(extensions);
    }

    /**
     * Creates certificate extensions for KRA transport/storage certificates.
     *
     * Uses NSSExtensionGenerator with hardcoded defaults that match:
     * - base/ca/shared/profiles/ca/caInternalAuthTransportCert.cfg
     * - base/ca/shared/profiles/ca/caInternalAuthDRMstorageCert.cfg
     *
     * Extensions:
     * - Authority Key Identifier (keyid from issuer CA)
     * - Key Usage (critical: digitalSignature, nonRepudiation, dataEncipherment, keyEncipherment)
     * - Extended Key Usage (clientAuth - OID 1.3.6.1.5.5.7.3.2)
     *
     * Note: The full profiles also include AIA, but this is not essential for
     * basic KRA key wrapping operations and is omitted for simplicity.
     */
    private CertificateExtensions createKRACertExtensions(X509Key publicKey, X509Certificate issuerCert) throws Exception {
        NSSExtensionGenerator generator = new NSSExtensionGenerator();

        // Hardcoded parameters matching transport/storage cert profiles
        Map<String, String> params = new java.util.LinkedHashMap<>();
        params.put("authorityKeyIdentifier", "keyid");
        params.put("keyUsage", "critical,digitalSignature,nonRepudiation,dataEncipherment,keyEncipherment");
        params.put("extendedKeyUsage", "clientAuth");

        generator.setParameters(params);

        // Generate Extensions (issuer provides AKID)
        Extensions extensions = generator.createExtensions(publicKey, issuerCert, null);

        // Convert Extensions to CertificateExtensions
        return convertToCertificateExtensions(extensions);
    }

    /**
     * Creates certificate extensions for user certificates.
     *
     * Uses NSSExtensionGenerator with hardcoded defaults that match:
     * base/ca/shared/profiles/ca/caAdminCert.cfg
     *
     * Extensions:
     * - Authority Key Identifier (keyid from issuer CA)
     * - Key Usage (critical: digitalSignature, nonRepudiation, keyEncipherment)
     * - Extended Key Usage (clientAuth, emailProtection - OIDs 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.4)
     *
     * Note: The full profile also includes AIA, but this is not essential for
     * basic archival/recovery testing and is omitted for simplicity.
     */
    private CertificateExtensions createUserCertExtensions(X509Key publicKey, X509Certificate issuerCert) throws Exception {
        NSSExtensionGenerator generator = new NSSExtensionGenerator();

        // Hardcoded parameters matching caAdminCert.cfg
        Map<String, String> params = new java.util.LinkedHashMap<>();
        params.put("authorityKeyIdentifier", "keyid");
        params.put("keyUsage", "critical,digitalSignature,nonRepudiation,keyEncipherment");
        params.put("extendedKeyUsage", "clientAuth,emailProtection");

        generator.setParameters(params);

        // Generate Extensions (issuer provides AKID)
        Extensions extensions = generator.createExtensions(publicKey, issuerCert, null);

        // Convert Extensions to CertificateExtensions
        return convertToCertificateExtensions(extensions);
    }

    /**
     * Converts Extensions to CertificateExtensions.
     *
     * Based on: base/common/src/main/java/org/dogtagpki/nss/NSSDatabase.java:1399-1409
     */
    private CertificateExtensions convertToCertificateExtensions(Extensions extensions) throws Exception {
        CertificateExtensions certExts = new CertificateExtensions();

        if (extensions != null) {
            java.util.Enumeration<String> names = extensions.getAttributeNames();
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                org.mozilla.jss.netscape.security.x509.Extension extension =
                    (org.mozilla.jss.netscape.security.x509.Extension) extensions.get(name);
                certExts.set(name, extension);
            }
        }

        return certExts;
    }

    /**
     * Logs detailed error information for PKCS#11/cryptographic operation failures.
     * This helps identify which specific mechanism/operation is not supported by the HSM.
     */
    private void logError(String context, String mechanism, String operation, Exception e) {
        System.out.println("");
        System.out.println("-------------------------------------------------------------------------------");
        System.out.println("- HSM COMPATIBILITY ISSUE DETECTED");
        System.out.println("-------------------------------------------------------------------------------");
        System.out.println("- Context:    " + context);
        System.out.println("- Mechanism:  " + mechanism);
        System.out.println("- Operation:  " + operation);
        System.out.println("- Error:      " + e.getClass().getSimpleName() + ": " + e.getMessage());

        // Check if it's a PKCS#11 error
        if (e instanceof org.mozilla.jss.crypto.TokenException) {
            System.out.println("-");
            System.out.println("- This appears to be a PKCS#11 token error. Possible causes:");
            System.out.println("-   1. HSM does not support the " + mechanism + " mechanism");
            System.out.println("-   2. HSM does not support " + operation);
            System.out.println("-   3. Key attributes are incompatible with this operation on this HSM");
            System.out.println("-");
            System.out.println("- Recommendation:");
            System.out.println("-   - Check HSM documentation for supported PKCS#11 mechanisms");
            System.out.println("-   - Try alternative wrap algorithms (e.g., --keywrap-alg \"AES KeyWrap\")");
            System.out.println("-   - Verify HSM supports unwrapping private keys with symmetric keys");
        }

        System.out.println("-------------------------------------------------------------------------------");
        System.out.println("");
    }

    /**
     * Creates an LDIF file mimicking KRA's archived key record format.
     *
     * The LDIF format matches what KRA stores in LDAP directory:
     * - privateKeyData: base64-encoded wrapped private key
     * - publicKeyData: base64-encoded public key
     * - metaInfo: key-value pairs with wrapping algorithms and parameters
     *
     * Based on: base/server/src/main/java/com/netscape/cmscore/dbs/KeyRecord.java
     * and base/kra/src/main/java/com/netscape/kra/StorageKeyUnit.java
     */
    private void createLDIFFile(
        String ldifFile,
        X509CertImpl cert,
        PublicKey publicKey,
        byte[] wrappedPrivateKey,
        byte[] wrappedSessionKey,
        KeyWrapAlgorithm sessionKeyWrapAlg,
        KeyWrapAlgorithm payloadWrapAlg,
        org.mozilla.jss.crypto.IVParameterSpec ivSpec,
        String ownerName
    ) throws Exception {

        java.text.SimpleDateFormat ldapDateFormat = new java.text.SimpleDateFormat("yyyyMMddHHmmss'Z'");
        ldapDateFormat.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        String currentDate = ldapDateFormat.format(new Date());

        // Generate a serial number for this key record
        SecureRandom random = new SecureRandom();
        BigInteger serialNo = new BigInteger(64, random);

        // Encode public key in DER format (X.509 SubjectPublicKeyInfo)
        byte[] publicKeyData = publicKey.getEncoded();

        // Get key algorithm OID
        String algorithmOID = publicKey.getAlgorithm().equals("RSA") ?
            "1.2.840.113549.1.1.1" : // RSA encryption OID
            "1.2.840.10045.2.1";      // EC public key OID

        // Get key size (for RSA)
        int keySize = 0;
        if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
            keySize = ((java.security.interfaces.RSAPublicKey) publicKey).getModulus().bitLength();
        }

        // Build LDIF content
        StringBuilder ldif = new StringBuilder();

        // DN and object class
        ldif.append("dn: cn=").append(serialNo.toString()).append(",ou=keyRepository,ou=kra,o=kra-hsm-compat-test\n");
        ldif.append("objectClass: top\n");
        ldif.append("objectClass: keyRecord\n");
        // Key record attributes
        ldif.append("keyState: VALID\n");
        ldif.append("serialno: ").append(serialNo.toString()).append("\n");
        ldif.append("ownerName: ").append(ownerName).append("\n");
        ldif.append("keySize: ").append(keySize).append("\n");
        ldif.append("algorithm: ").append(algorithmOID).append("\n");

        // Private key data (base64-encoded) - DER SEQUENCE containing wrapped session key and wrapped private key
        // This matches the format used by StorageKeyUnit.wrap() in base/kra/src/main/java/com/netscape/kra/StorageKeyUnit.java
        // DER SEQUENCE { encryptedSession OCTET STRING, encryptedPrivate OCTET STRING }
        byte[] privateKeyDataDER;
        try (org.mozilla.jss.netscape.security.util.DerOutputStream out = new org.mozilla.jss.netscape.security.util.DerOutputStream()) {
            org.mozilla.jss.netscape.security.util.DerOutputStream tmp = new org.mozilla.jss.netscape.security.util.DerOutputStream();
            tmp.putOctetString(wrappedSessionKey);
            tmp.putOctetString(wrappedPrivateKey);
            out.write(org.mozilla.jss.netscape.security.util.DerValue.tag_Sequence, tmp);
            privateKeyDataDER = out.toByteArray();
        }
        ldif.append("privateKeyData:: ").append(java.util.Base64.getEncoder().encodeToString(privateKeyDataDER)).append("\n");

        // Public key data (base64-encoded)
        ldif.append("publicKeyData:: ").append(java.util.Base64.getEncoder().encodeToString(publicKeyData)).append("\n");

        // Request type - required by KRATool to identify record type
        // "enrollment" starts with "CA" which matches KRA_LDIF_CA_KEY_RECORD
        ldif.append("extdata-requesttype: enrollment\n");

        // Metadata - wrapping algorithms and parameters
        // These match what KRA stores in the metaInfo field
        ldif.append("metaInfo: sessionKeyWrapAlgorithm:").append(sessionKeyWrapAlg.toString()).append("\n");
        ldif.append("metaInfo: payloadEncrypted:false\n");
        ldif.append("metaInfo: sessionKeyKeyGenAlgorithm:AES\n");
        ldif.append("metaInfo: sessionKeyType:AES\n");
        ldif.append("metaInfo: sessionKeyLength:128\n");
        // Payload wrap algorithm OID (AES KeyWrap OIDs from NIST)
        String payloadWrapOID;
        if (payloadWrapAlg.toString().contains("KeyWrap/Padding")) {
            payloadWrapOID = "2.16.840.1.101.3.4.1.8";  // AES-128 Key Wrap with Padding
        } else if (payloadWrapAlg.toString().contains("KeyWrap")) {
            payloadWrapOID = "2.16.840.1.101.3.4.1.5";  // AES-128 Key Wrap
        } else if (payloadWrapAlg.toString().contains("CBC")) {
            payloadWrapOID = "2.16.840.1.101.3.4.1.2";  // AES-128 CBC
        } else {
            payloadWrapOID = "unknown";
        }
        ldif.append("metaInfo: payloadEncryptionOID:").append(payloadWrapOID).append("\n");
        // IV (if used)
        if (ivSpec != null) {
            String ivBase64 = java.util.Base64.getEncoder().encodeToString(ivSpec.getIV());
            ldif.append("metaInfo: payloadEncryptionIV:").append(ivBase64).append("\n");
        }
        ldif.append("metaInfo: payloadWrapAlgorithm:").append(payloadWrapAlg.toString()).append("\n");
        // Timestamps
        ldif.append("dateOfCreate: ").append(currentDate).append("\n");
        ldif.append("dateOfModify: ").append(currentDate).append("\n");
        // Archived by
        ldif.append("archivedBy: CA-hsmCompatVerifyServ\n");
        // Common name
        ldif.append("cn: ").append(serialNo.toString()).append("\n");
        // Append the actual wrapped private key as a comment for reference
        ldif.append("# Wrapped Private Key Data (for reference):\n");
        ldif.append("# This is the user's private key wrapped with the storage session key\n");
        ldif.append("# wrappedPrivateKeyData:: ").append(java.util.Base64.getEncoder().encodeToString(wrappedPrivateKey)).append("\n");

        // Write to file
        java.nio.file.Files.write(java.nio.file.Paths.get(ldifFile), ldif.toString().getBytes());
    }

    /**
     * Reads archived key data from LDIF file.
     *
     * Parses the LDIF file and extracts all key records.
     * Each record contains:
     * - Wrapped private key (from privateKeyData DER SEQUENCE)
     * - Wrapped session key (from privateKeyData DER SEQUENCE)
     * - Public key (from publicKeyData)
     * - Metadata (algorithms, IV, etc.)
     *
     * @return List of Maps, each with keys: wrappedPrivateKey, wrappedSessionKey, publicKey, sessionKeyWrapAlg, payloadWrapAlg, payloadWrapIV, ownerName, serialno
     */
    private java.util.List<Map<String, Object>> readLDIFFile(String ldifFile) throws Exception {
        log("Reading archived key data from LDIF file");
        log("  LDIF file: " + ldifFile);

        java.util.List<Map<String, Object>> keyRecords = new java.util.ArrayList<>();

        // Read LDIF file line by line
        java.util.List<String> lines = java.nio.file.Files.readAllLines(java.nio.file.Paths.get(ldifFile));

        // Parse LDIF records (separated by blank lines)
        Map<String, Object> currentRecord = null;
        String privateKeyDataB64 = null;
        String publicKeyDataB64 = null;
        String sessionKeyWrapAlg = null;
        String payloadWrapAlg = null;
        String payloadWrapIV = null;
        String ownerName = null;
        String serialno = null;

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();

            // Blank line or end of file = end of record
            if (line.isEmpty() || i == lines.size() - 1) {
                if (privateKeyDataB64 != null && publicKeyDataB64 != null) {
                    // Process current record
                    currentRecord = new LinkedHashMap<>();

                    // Decode privateKeyData (DER SEQUENCE containing wrapped session key and wrapped private key)
                    byte[] privateKeyDataDER = java.util.Base64.getDecoder().decode(privateKeyDataB64);
                    org.mozilla.jss.netscape.security.util.DerInputStream dis =
                        new org.mozilla.jss.netscape.security.util.DerInputStream(privateKeyDataDER);
                    org.mozilla.jss.netscape.security.util.DerValue[] seq = dis.getSequence(2);
                    if (seq.length != 2) {
                        throw new Exception("Invalid privateKeyData format in LDIF - expected SEQUENCE of 2 elements");
                    }

                    byte[] wrappedSessionKey = seq[0].getOctetString();
                    byte[] wrappedPrivateKey = seq[1].getOctetString();

                    // Decode public key
                    byte[] publicKeyData = java.util.Base64.getDecoder().decode(publicKeyDataB64);
                    java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
                    PublicKey publicKey = keyFactory.generatePublic(
                        new java.security.spec.X509EncodedKeySpec(publicKeyData)
                    );

                    // Parse IV if present
                    byte[] iv = null;
                    if (payloadWrapIV != null) {
                        iv = java.util.Base64.getDecoder().decode(payloadWrapIV);
                    }

                    // Store in record
                    currentRecord.put("wrappedPrivateKey", wrappedPrivateKey);
                    currentRecord.put("wrappedSessionKey", wrappedSessionKey);
                    currentRecord.put("publicKey", publicKey);
                    currentRecord.put("sessionKeyWrapAlg", sessionKeyWrapAlg);
                    currentRecord.put("payloadWrapAlg", payloadWrapAlg);
                    currentRecord.put("payloadWrapIV", iv);
                    currentRecord.put("ownerName", ownerName);
                    currentRecord.put("serialno", serialno);

                    keyRecords.add(currentRecord);
                }

                // Reset for next record
                privateKeyDataB64 = null;
                publicKeyDataB64 = null;
                sessionKeyWrapAlg = null;
                payloadWrapAlg = null;
                payloadWrapIV = null;
                ownerName = null;
                serialno = null;
                continue;
            }

            // Skip comments and non-data lines
            if (line.startsWith("#") || line.startsWith("dn:") || line.startsWith("objectClass:") ||
                line.startsWith("keyState:") || line.startsWith("keySize:") || line.startsWith("algorithm:") ||
                line.startsWith("dateOfCreate:") || line.startsWith("dateOfModify:") ||
                line.startsWith("archivedBy:") || line.startsWith("cn:") || line.startsWith("extdata-requesttype:")) {
                continue;
            }

            // Parse key data fields
            if (line.startsWith("privateKeyData:: ")) {
                privateKeyDataB64 = line.substring("privateKeyData:: ".length());
            } else if (line.startsWith("publicKeyData:: ")) {
                publicKeyDataB64 = line.substring("publicKeyData:: ".length());
            } else if (line.startsWith("metaInfo: sessionKeyWrapAlgorithm:")) {
                sessionKeyWrapAlg = line.substring("metaInfo: sessionKeyWrapAlgorithm:".length());
            } else if (line.startsWith("metaInfo: payloadWrapAlgorithm:")) {
                payloadWrapAlg = line.substring("metaInfo: payloadWrapAlgorithm:".length());
            } else if (line.startsWith("metaInfo: payloadWrapIV:")) {
                payloadWrapIV = line.substring("metaInfo: payloadWrapIV:".length());
            } else if (line.startsWith("ownerName: ")) {
                ownerName = line.substring("ownerName: ".length());
            } else if (line.startsWith("serialno: ")) {
                serialno = line.substring("serialno: ".length());
            }
        }

        if (keyRecords.isEmpty()) {
            throw new Exception("No valid key records found in LDIF file");
        }

        log("  - Found " + keyRecords.size() + " key record(s)");
        for (int i = 0; i < keyRecords.size(); i++) {
            Map<String, Object> record = keyRecords.get(i);
            log("    Record " + (i + 1) + ":");
            log("      Serial: " + record.get("serialno"));
            log("      Owner: " + record.get("ownerName"));
            log("      Algorithms: session=" + record.get("sessionKeyWrapAlg") + ", payload=" + record.get("payloadWrapAlg"));
        }

        return keyRecords;
    }

    private void log(String message) {
        if (verbose || message.startsWith("===") || message.startsWith("OK") ||
            message.startsWith("ERROR") || message.startsWith("SUCCESS") ||
            message.isEmpty() || message.trim().startsWith("Step ")) {
            System.out.println(message);
        }
    }
}
