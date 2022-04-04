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
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage;
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
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "key-type", true, "Key type: RSA (default), EC");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "key-size", true, "RSA key size (default: 2048)");
        option.setArgName("size");
        options.addOption(option);

        options.addOption(null, "key-wrap", false, "Generate RSA key for wrapping/unwrapping.");

        option = new Option(null, "curve", true, "Elliptic curve name (default: nistp256)");
        option.setArgName("name");
        options.addOption(option);

        options.addOption(null, "ssl-ecdh", false, "Generate EC key for SSL with ECDH ECDSA.");

        option = new Option(null, "output-format", true, "Output format: text (default), json.");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String keyType = cmd.getOptionValue("key-type", "RSA");
        String keySize = cmd.getOptionValue("key-size", "2048");
        boolean keyWrap = cmd.hasOption("key-wrap");
        String curve = cmd.getOptionValue("curve", "nistp256");
        boolean sslECDH = cmd.hasOption("ssl-ecdh");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        KeyPair keyPair;

        if ("RSA".equalsIgnoreCase(keyType)) {

            Usage[] usages = keyWrap ? CryptoUtil.RSA_KEYPAIR_USAGES : null;
            Usage[] usagesMask = keyWrap ? CryptoUtil.RSA_KEYPAIR_USAGES_MASK : null;

            keyPair = nssdb.createRSAKeyPair(
                    token,
                    Integer.parseInt(keySize),
                    usages,
                    usagesMask);

        } else if ("EC".equalsIgnoreCase(keyType)) {

            Usage[] usages = null;
            Usage[] usagesMask = sslECDH ? CryptoUtil.ECDH_USAGES_MASK : CryptoUtil.ECDHE_USAGES_MASK;

            keyPair = nssdb.createECKeyPair(
                    token,
                    curve,
                    usages,
                    usagesMask);

        } else {
            throw new Exception("Unsupported key type: " + keyType);
        }

        PK11PrivKey privateKey = (PK11PrivKey) keyPair.getPrivate();
        String hexKeyID = "0x" + Utils.HexEncode(privateKey.getUniqueID());

        KeyInfo keyInfo = new KeyInfo();
        keyInfo.setKeyId(new KeyId(hexKeyID));
        keyInfo.setAlgorithm(privateKey.getAlgorithm());

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
