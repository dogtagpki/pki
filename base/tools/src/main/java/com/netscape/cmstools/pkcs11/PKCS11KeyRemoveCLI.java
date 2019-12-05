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

package com.netscape.cmstools.pkcs11;

import java.security.Key;
import java.security.KeyStore;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.provider.java.security.JSSLoadStoreParameter;

import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class PKCS11KeyRemoveCLI extends CommandCLI {

    public PKCS11KeyCLI keyCLI;

    public PKCS11KeyRemoveCLI(PKCS11KeyCLI keyCLI) {
        super("del", "Remove PKCS #11 key", keyCLI);
        this.keyCLI = keyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <Key ID>", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing key ID.");
        }

        String alias = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        KeyStore ks = KeyStore.getInstance("pkcs11");
        ks.load(new JSSLoadStoreParameter(token));

        Key key = ks.getKey(alias, null);

        if (key == null) {
            throw new Exception("Key not found: " + alias);
        }

        ks.deleteEntry(alias);
    }
}
