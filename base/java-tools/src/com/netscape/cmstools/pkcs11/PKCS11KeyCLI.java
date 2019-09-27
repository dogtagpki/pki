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

import org.dogtagpki.cli.CLI;
import org.mozilla.jss.crypto.PrivateKey;

/**
 * @author Endi S. Dewata
 */
public class PKCS11KeyCLI extends CLI {

    public PKCS11CLI pkcs11CLI;

    public PKCS11KeyCLI(PKCS11CLI pkcs11CLI) {
        super("key", "PKCS #11 key management commands", pkcs11CLI);
        this.pkcs11CLI = pkcs11CLI;

        addModule(new PKCS11KeyFindCLI(this));
        addModule(new PKCS11KeyShowCLI(this));
        addModule(new PKCS11KeyRemoveCLI(this));
    }

    public static void printKeyInfo(String alias, Key key) {

        System.out.println("  Key ID: " + alias);

        if (key instanceof PrivateKey) {
            PrivateKey privateKey = (PrivateKey) key;

            PrivateKey.Type keyType = privateKey.getType();
            System.out.println("  Type: " + keyType);
        }

        System.out.println("  Algorithm: " + key.getAlgorithm());

        String format = key.getFormat();
        if (format != null) {
            System.out.println("  Format: " + format);
        }
    }
}
