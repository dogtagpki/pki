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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.codec.binary.Hex;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;

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
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        CryptoStore cryptoStore = token.getCryptoStore();

        PrivateKey[] privateKeys = cryptoStore.getPrivateKeys();
        KeyInfoCollection keyInfoCollection = new KeyInfoCollection();
        keyInfoCollection.setTotal(privateKeys.length);

        for (PrivateKey privateKey : privateKeys) {
            KeyInfo keyInfo = new KeyInfo();
            String keyID = "0x" + Hex.encodeHexString(privateKey.getUniqueID());
            keyInfo.setKeyId(new KeyId(keyID));
            keyInfo.setAlgorithm(privateKey.getAlgorithm());
            keyInfoCollection.addEntry(keyInfo);
        }

        boolean first = true;

        for (KeyInfo keyInfo : keyInfoCollection.getEntries()) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            NSSKeyCLI.printKeyInfo(keyInfo);
        }
    }
}
