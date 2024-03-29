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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.pkcs12;

import org.dogtagpki.cli.CLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS12KeyInfo;
import org.mozilla.jss.netscape.security.util.Utils;

/**
 * @author Endi S. Dewata
 */
public class PKCS12KeyCLI extends CLI {

    public PKCS12CLI pkcs12CLI;

    public PKCS12KeyCLI(PKCS12CLI pkcs12CLI) {
        super("key", "PKCS #12 key management commands", pkcs12CLI);
        this.pkcs12CLI = pkcs12CLI;

        addModule(new PKCS12KeyFindCLI(this));
        addModule(new PKCS12KeyRemoveCLI(this));
    }

    public static void printKeyInfo(PKCS12KeyInfo keyInfo) throws Exception {

        String hexKeyID = "0x" + Utils.HexEncode(keyInfo.getID());
        System.out.println("  Key ID: " + hexKeyID);
        System.out.println("  Friendly Name: " + keyInfo.getFriendlyName());
    }
}
