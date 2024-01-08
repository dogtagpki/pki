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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.nss;

import java.security.KeyPair;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.pkcs11.PK11PrivKey;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class NSSKeyCreateCLI extends CommandCLI {

    public NSSKeyCLI keyCLI;

    public NSSKeyCreateCLI(NSSKeyCLI keyCLI) {
        super("create", "Create key in NSS database", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nickname]", options);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "key-type", true, "Key type: RSA (default), EC, AES");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "key-size", true, "Key size (RSA default: 2048, AES default: 256)");
        option.setArgName("size");
        options.addOption(option);

        options.addOption(null, "key-wrap", false, "Generate RSA key for wrapping/unwrapping.");

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

        option = new Option(null, "op-flags", true, "Custom flags for key usage");
        option.setArgName("usage list");
        options.addOption(option);

        option = new Option(null, "op-flags-mask", true, "Custom flags mask for key usage");
        option.setArgName("usage list");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json.");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(LogLevel.INFO);
        }


        String[] cmdArgs = cmd.getArgs();

        String nickname = null;
        if (cmdArgs.length >= 1) {
            nickname = cmdArgs[0];
        }

        String keyType = cmd.getOptionValue("key-type", "RSA");
        String keySize = cmd.getOptionValue("key-size");
        boolean keyWrap = cmd.hasOption("key-wrap");
        String curve = cmd.getOptionValue("curve", "nistp256");
        boolean sslECDH = cmd.hasOption("ssl-ecdh");

        boolean temporary = cmd.hasOption("temporary");

        String sensitiveStr = cmd.getOptionValue("sensitive");
        Boolean sensitive = null;
        if (sensitiveStr != null) {
            sensitive = Boolean.valueOf(sensitiveStr);
        }

        String extractableStr = cmd.getOptionValue("extractable");
        Boolean extractable = null;
        if (extractableStr != null) {
            extractable = Boolean.valueOf(extractableStr);
        }

        String opFlags = cmd.getOptionValue("op-flags");
        String opFlagsMask = cmd.getOptionValue("op-flags-mask");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        KeyInfo keyInfo = new KeyInfo();

        logger.info("Creating " + keyType + " in token " + tokenName);

        Usage[] usages = null;
        Usage[] usagesMask = null;

        if ("RSA".equalsIgnoreCase(keyType)) {
            if (keySize == null) keySize = "2048";
            if (opFlags != null && !opFlags.isEmpty()) {
                usages = CryptoUtil.generateUsage(opFlags);
            } else {
                usages = keyWrap ? CryptoUtil.RSA_KEYPAIR_USAGES : null;
            }
            if (opFlagsMask != null && !opFlagsMask.isEmpty()) {
                usagesMask = CryptoUtil.generateUsage(opFlagsMask);
            } else {
                usagesMask = keyWrap ? CryptoUtil.RSA_KEYPAIR_USAGES_MASK : null;
            }

            KeyPair keyPair = nssdb.createRSAKeyPair(
                    token,
                    Integer.parseInt(keySize),
                    temporary,
                    sensitive,
                    extractable,
                    usages,
                    usagesMask);

            PK11PrivKey privateKey = (PK11PrivKey) keyPair.getPrivate();

            String hexKeyID = "0x" + Utils.HexEncode(privateKey.getUniqueID());
            keyInfo.setKeyId(new KeyId(hexKeyID));
            keyInfo.setType(privateKey.getType().toString());
            keyInfo.setAlgorithm(privateKey.getAlgorithm());

        } else if ("EC".equalsIgnoreCase(keyType)) {
            if (opFlags != null && !opFlags.isEmpty()) {
                usages = CryptoUtil.generateUsage(opFlagsMask);
            }
            if (opFlagsMask != null && !opFlagsMask.isEmpty()) {
                usagesMask = CryptoUtil.generateUsage(opFlagsMask);
            } else {
                usagesMask = sslECDH ? CryptoUtil.ECDH_USAGES_MASK : CryptoUtil.ECDHE_USAGES_MASK;
            }

            KeyPair keyPair = nssdb.createECKeyPair(
                    token,
                    curve,
                    temporary,
                    sensitive,
                    extractable,
                    usages,
                    usagesMask);

            PK11PrivKey privateKey = (PK11PrivKey) keyPair.getPrivate();

            String hexKeyID = "0x" + Utils.HexEncode(privateKey.getUniqueID());
            keyInfo.setKeyId(new KeyId(hexKeyID));
            keyInfo.setType(privateKey.getType().toString());
            keyInfo.setAlgorithm(privateKey.getAlgorithm());

        } else if ("AES".equalsIgnoreCase(keyType)) {

            if (keySize == null) keySize = "256";

            if (nickname == null) {
                throw new CLIException("Missing key nickname");
            }

            KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.AES);
            kg.initialize(Integer.parseInt(keySize));
            kg.temporaryKeys(temporary);

            if (sensitive != null) {
                kg.sensitiveKeys(sensitive);
            }

            SymmetricKey symmetricKey = kg.generate();
            symmetricKey.setNickName(nickname);

            keyInfo.setNickname(nickname);
            keyInfo.setType(symmetricKey.getType().toString());
            keyInfo.setAlgorithm(symmetricKey.getAlgorithm());

        } else {
            throw new Exception("Unsupported key type: " + keyType);
        }

        String outputFormat = cmd.getOptionValue("output-format", "text");

        if (outputFormat.equalsIgnoreCase("json")) {
            System.out.println(keyInfo.toJSON());

        } else if (outputFormat.equalsIgnoreCase("text")) {
            NSSKeyCLI.printKeyInfo(keyInfo);

        } else {
            throw new Exception("Unsupported output format: " + outputFormat);
        }
    }
}
