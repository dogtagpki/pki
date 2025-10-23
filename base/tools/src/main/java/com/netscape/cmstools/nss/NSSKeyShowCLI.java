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
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.pkcs11.PK11SymKey;
import org.mozilla.jss.symkey.SessionKey;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class NSSKeyShowCLI extends CommandCLI {

    public NSSKeyCLI keyCLI;

    public NSSKeyShowCLI(NSSKeyCLI keyCLI) {
        super("show", "Show key in NSS database", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "key-id", true, "Key ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "key-id-file", true, "File containing key ID");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "key-nickname", true, "Key nickname");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json");
        option.setArgName("format");
        options.addOption(option);
    }

    public void printKeyInfo(KeyInfo keyInfo, String outputFormat) throws Exception {
        if (outputFormat.equalsIgnoreCase("json")) {
            System.out.println(keyInfo.toJSON());

        } else if (outputFormat.equalsIgnoreCase("text")) {
            NSSKeyCLI.printKeyInfo(keyInfo);

        } else {
            throw new Exception("Unsupported output format: " + outputFormat);
        }
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(LogLevel.INFO);
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        String keyID = cmd.getOptionValue("key-id");
        String keyIDFile = cmd.getOptionValue("key-id-file");

        if (keyID == null && keyIDFile != null) {
            // load key ID from file
            keyID = Files.readString(Paths.get(keyIDFile)).strip();
        }

        String keyNickname = cmd.getOptionValue("key-nickname");
        String outputFormat = cmd.getOptionValue("output-format", "text");

        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        CryptoStore cryptoStore = token.getCryptoStore();

        if (keyID != null) {

            // TODO: implement cryptoStore.getPrivateKey(keyID)
            PrivateKey[] privateKeys = cryptoStore.getPrivateKeys();
            logger.info("Private keys: " + privateKeys);

            for (PrivateKey privateKey : privateKeys) {

                String hexKeyID = "0x" + Utils.HexEncode(privateKey.getUniqueID());
                if (!keyID.equals(hexKeyID)) continue;

                KeyInfo keyInfo = new KeyInfo();
                keyInfo.setKeyId(new KeyId(hexKeyID));
                keyInfo.setType(privateKey.getType().toString());
                keyInfo.setAlgorithm(privateKey.getAlgorithm());

                printKeyInfo(keyInfo, outputFormat);
                break;
            }

        } else if (keyNickname != null) {

            // TODO: implement cryptoStore.getSymmetricKey(keyNickname)
            String nicknames = SessionKey.ListSymmetricKeys(tokenName);
            logger.info("Symmetric keys: " + nicknames);

            for (String nickname : nicknames.split(",")) {
                if (StringUtils.isEmpty(nickname)) continue;
                if (!keyNickname.equals(nickname)) continue;

                PK11SymKey symmetricKey = SessionKey.GetSymKeyByName(tokenName, nickname);

                KeyInfo keyInfo = new KeyInfo();
                keyInfo.setNickname(symmetricKey.getNickName());
                keyInfo.setType(symmetricKey.getType().toString());
                keyInfo.setAlgorithm(symmetricKey.getAlgorithm());

                printKeyInfo(keyInfo, outputFormat);
                break;
            }

        } else {
            throw new CLIException("Missing key ID or key nickname");
        }
    }
}
