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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.pkcs11.PK11SymKey;
import org.mozilla.jss.symkey.SessionKey;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.certsrv.key.KeyInfoCollection;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class NSSKeyFindCLI extends CommandCLI {

    public NSSKeyCLI keyCLI;

    public NSSKeyFindCLI(NSSKeyCLI keyCLI) {
        super("find", "Find keys in NSS database", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "nickname", true, "Certificate nickname");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json.");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        String nickname = cmd.getOptionValue("nickname");

        List<PrivateKey> privateKeys;
        List<SymmetricKey> symmetricKeys;

        if (nickname != null) {
            CryptoManager cm = CryptoManager.getInstance();
            privateKeys = new ArrayList<>();
            for (X509Certificate cert : cm.findCertsByNickname(nickname)) {
                try {
                    PrivateKey privateKey = cm.findPrivKeyByCert(cert);
                    privateKeys.add(privateKey);
                } catch (ObjectNotFoundException e) {
                    // cert doesn't have a key, skip
                }
            }

            symmetricKeys = new ArrayList<>();

        } else {
            String tokenName = getConfig().getTokenName();
            CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
            CryptoStore cryptoStore = token.getCryptoStore();

            privateKeys = Arrays.asList(cryptoStore.getPrivateKeys());
            logger.info("Private keys: " + privateKeys);

            symmetricKeys = new ArrayList<>();
            String nicknames = SessionKey.ListSymmetricKeys(tokenName);
            logger.info("Symmetric keys: " + nicknames);

            for (String n : nicknames.split(",")) {
                if (StringUtils.isEmpty(n)) continue;
                PK11SymKey symmetricKey = SessionKey.GetSymKeyByName(tokenName, n);
                symmetricKeys.add(symmetricKey);
            }
        }

        KeyInfoCollection keyInfoCollection = new KeyInfoCollection();

        for (PrivateKey privateKey : privateKeys) {
            KeyInfo keyInfo = new KeyInfo();

            String hexKeyID = "0x" + Utils.HexEncode(privateKey.getUniqueID());
            keyInfo.setKeyId(new KeyId(hexKeyID));
            keyInfo.setType(privateKey.getType().toString());
            keyInfo.setAlgorithm(privateKey.getAlgorithm());
            keyInfoCollection.addEntry(keyInfo);
        }

        for (SymmetricKey symmetricKey : symmetricKeys) {
            KeyInfo keyInfo = new KeyInfo();

            keyInfo.setNickname(symmetricKey.getNickName());
            keyInfo.setType(symmetricKey.getType().toString());
            keyInfo.setAlgorithm(symmetricKey.getAlgorithm());
            keyInfoCollection.addEntry(keyInfo);
        }

        keyInfoCollection.setTotal(keyInfoCollection.getEntries().size());

        String outputFormat = cmd.getOptionValue("output-format", "text");

        if (outputFormat.equalsIgnoreCase("json")) {
            System.out.println(keyInfoCollection.toJSON());

        } else if (outputFormat.equalsIgnoreCase("text")) {
            boolean first = true;

            for (KeyInfo keyInfo : keyInfoCollection.getEntries()) {

                if (first) {
                    first = false;
                } else {
                    System.out.println();
                }

                NSSKeyCLI.printKeyInfo(keyInfo);
            }

        } else {
            throw new Exception("Unsupported output format: " + outputFormat);
        }
    }
}
