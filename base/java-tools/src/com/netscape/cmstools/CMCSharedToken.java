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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.io.FileUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.Utils;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * A command-line utility used to take a passphrase as an input and
 * generate an encrypted entry for ldap entry
 *
 * <pre>
 * IMPORTANT:  The issuance protection certificate file needs to be created to
 * contain the certificate in its PEM format.
 * </pre>
 * <p>
 * @author cfu
 */
public class CMCSharedToken {
    public boolean verbose = false;

    public static Options createOptions() {

        Options options = new Options();

        Option option = new Option("d", true, "Security database location");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("h", true, "Security token name");
        option.setArgName("token");
        options.addOption(option);

        option = new Option("o", true, "Output file to store base-64 secret data");
        option.setArgName("output");
        options.addOption(option);

        option = new Option("p", true, "passphrase");
        option.setArgName("passphrase");
        options.addOption(option);

        option = new Option("b", true, "PEM issuance protection certificate");
        option.setArgName("issuance protection cert");
        options.addOption(option);

        option = new Option("n", true, "Issuance Protection certificate nickname");
        option.setArgName("issuance protection cert nickname");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "help", false, "Show help message.");

        return options;
    }

    public static void printHelp() {

        System.out.println("Usage: CMCSharedToken [OPTIONS]");
        System.out.println("       If the issuance protection cert was previously imported into the");
        System.out.println("       nss database, then -n <nickname> can be used instead of -b <PEM>");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -d <database>                Security database location (default: current directory)");
        System.out.println("  -h <token>                   Security token name (default: internal)");
        System.out.println("  -p <passphrase>              CMC enrollment passphrase (put in \"\" if containing spaces)");
        System.out.println("     Use either -b OR -n below");
        System.out.println("  -b <issuance protection cert>          PEM issuance protection certificate");
        System.out.println("  -n <issuance protection cert nickname>          issuance protection certificate nickname");
        System.out.println("To store the base-64 secret data, the following options are required:");
        System.out.println("  -o <output>                  Output file to store base-64 secret data");
        System.out.println();
        System.out.println("  -v, --verbose                Run in verbose mode.");
        System.out.println("      --help                   Show help message.");
        System.out.println();
    }


    public static void printError(String message) {
        System.err.println("ERROR: " + message);
        System.err.println("Try 'CMCSharedToken --help' for more information.");
    }

    /*
     * used for isVerificationMode only
     */
    public static java.security.PrivateKey getPrivateKey(String tokenName, String nickname)
            throws Exception {

        X509Certificate cert = getCertificate(tokenName, nickname);
        if (cert != null)
            System.out.println("getPrivateKey: got cert");

        return CryptoManager.getInstance().findPrivKeyByCert(cert);
    }

    public static X509Certificate getCertificate(String tokenName,
            String nickname) throws Exception {
        CryptoManager manager = CryptoManager.getInstance();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        StringBuffer certname = new StringBuffer();

        if (!token.equals(manager.getInternalKeyStorageToken())) {
            certname.append(tokenName);
            certname.append(":");
        }
        certname.append(nickname);
        try {
            return manager.findCertByNickname(certname.toString());
        } catch (ObjectNotFoundException e) {
            throw new IOException("Certificate not found");
        }
    }

    public static void main(String args[]) throws Exception {
        boolean isVerificationMode = false; // developer debugging only

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
        String passphrase = cmd.getOptionValue("p");
        if (passphrase == null) {
            printError("Missing passphrase");
            System.exit(1);
        }
        if (verbose) {
            System.out.println("passphrase String = " + passphrase);
            System.out.println("passphrase UTF-8 bytes = ");
            System.out.println(Arrays.toString(passphrase.getBytes("UTF-8")));
        }
        String tokenName = cmd.getOptionValue("h");

        String issuanceProtCertFilename = cmd.getOptionValue("b");
        String issuanceProtCertNick = cmd.getOptionValue("n");
        String output = cmd.getOptionValue("o");

        try {
            CryptoManager.initialize(databaseDir);

            CryptoManager manager = CryptoManager.getInstance();

            CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
            tokenName = token.getName();
            manager.setThreadToken(token);
            X509Certificate  issuanceProtCert = null;
            if (issuanceProtCertFilename != null) {
                if (verbose) System.out.println("Loading issuance protection certificate");
                String encoded = FileUtils.readFileToString(new File(issuanceProtCertFilename));
                byte[] issuanceProtCertData = Cert.parseCertificate(encoded);

                issuanceProtCert = manager.importCACertPackage(issuanceProtCertData);
                if (verbose) System.out.println("issuance protection certificate imported");
            } else {
                // must have issuance protection cert nickname if file not provided
                if (verbose) System.out.println("Getting cert by nickname: " + issuanceProtCertNick);
                if (issuanceProtCertNick == null) {
                    System.out.println("Invallid command: either nickname or PEM file must be provided for Issuance Protection Certificate");
                    System.exit(1);
                }
                issuanceProtCert = getCertificate(tokenName, issuanceProtCertNick);
            }

            EncryptionAlgorithm encryptAlgorithm = EncryptionAlgorithm.AES_128_CBC_PAD;
            KeyWrapAlgorithm wrapAlgorithm = KeyWrapAlgorithm.RSA;

            if (verbose) System.out.println("Generating session key");
            SymmetricKey sessionKey = CryptoUtil.generateKey(
                    token,
                    KeyGenAlgorithm.AES,
                    128,
                    null,
                    true);

            if (verbose) System.out.println("Encrypting passphrase");
            byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            byte[] secret_data = CryptoUtil.encryptUsingSymmetricKey(
                    token,
                    sessionKey,
                    passphrase.getBytes("UTF-8"),
                    encryptAlgorithm,
                    new IVParameterSpec(iv));

            if (verbose) System.out.println("Wrapping session key with issuance protection cert");
            byte[] issuanceProtWrappedSessionKey = CryptoUtil.wrapUsingPublicKey(
                    token,
                    issuanceProtCert.getPublicKey(),
                    sessionKey,
                    wrapAlgorithm);

            // final_data takes this format:
            // SEQUENCE {
            //     encryptedSession OCTET STRING,
            //     encryptedPrivate OCTET STRING
            // }

            DerOutputStream tmp = new DerOutputStream();

            tmp.putOctetString(issuanceProtWrappedSessionKey);
            tmp.putOctetString(secret_data);
            DerOutputStream out = new DerOutputStream();
            out.write(DerValue.tag_Sequence, tmp);

            byte[] final_data = out.toByteArray();
            String final_data_b64 = Utils.base64encode(final_data, true);
            if (final_data_b64 != null) {
                System.out.println("\nEncrypted Secret Data:");
                System.out.println(final_data_b64);
            } else
                System.out.println("Failed to produce final data");

            if (output != null) {
                System.out.println("\nStoring Base64 secret data into " + output);
                try (FileWriter fout = new FileWriter(output)) {
                    fout.write(final_data_b64);
                }
            }

            if (isVerificationMode) { // developer use only
                PrivateKey wrappingKey = null;
                if (issuanceProtCertNick != null)
                    wrappingKey = (org.mozilla.jss.crypto.PrivateKey) getPrivateKey(tokenName, issuanceProtCertNick);
                else
                    wrappingKey = CryptoManager.getInstance().findPrivKeyByCert(issuanceProtCert);

                System.out.println("\nVerification begins...");
                byte[] wrapped_secret_data = Utils.base64decode(final_data_b64);
                DerValue wrapped_val = new DerValue(wrapped_secret_data);
                // val.tag == DerValue.tag_Sequence
                DerInputStream wrapped_in = wrapped_val.data;
                DerValue wrapped_dSession = wrapped_in.getDerValue();
                byte wrapped_session[] = wrapped_dSession.getOctetString();
                System.out.println("wrapped session key retrieved");
                DerValue wrapped_dPassphrase = wrapped_in.getDerValue();
                byte wrapped_passphrase[] = wrapped_dPassphrase.getOctetString();
                System.out.println("wrapped passphrase retrieved");

                SymmetricKey ver_session = CryptoUtil.unwrap(token,  SymmetricKey.AES, 128, SymmetricKey.Usage.UNWRAP, wrappingKey, wrapped_session, wrapAlgorithm);
                byte[] ver_passphrase = CryptoUtil.decryptUsingSymmetricKey(token, new IVParameterSpec(iv), wrapped_passphrase,
                ver_session, EncryptionAlgorithm.AES_128_CBC_PAD);

                String ver_spassphrase = new String(ver_passphrase, "UTF-8");

                System.out.println("ver_passphrase String = " + ver_spassphrase);
                System.out.println("ver_passphrase UTF-8 bytes = ");
                System.out.println(Arrays.toString(ver_spassphrase.getBytes("UTF-8")));

                if (ver_spassphrase.equals(passphrase))
                    System.out.println("Verification success!");
                else
                    System.out.println("Verification failure! ver_spassphrase="+ ver_spassphrase);
            }

        } catch (Exception e) {
            if (verbose) e.printStackTrace();
            printError(e.getMessage());
            System.exit(1);
        }
    }
}
