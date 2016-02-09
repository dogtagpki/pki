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

import com.netscape.cmstools.cli.CLI;

import netscape.security.pkcs.PKCS12Util.PKCS12KeyInfo;

/**
 * @author Endi S. Dewata
 */
public class PKCS12KeyCLI extends CLI {

    public PKCS12KeyCLI(PKCS12CLI parent) {
        super("key", "PKCS #12 key management commands", parent);

        addModule(new PKCS12KeyFindCLI(this));
    }

    public static void printKeyInfo(PKCS12KeyInfo keyInfo) throws Exception {
        System.out.println("  Subject: " + keyInfo.subjectDN);

        if (keyInfo.privateKeyInfo != null) {
            System.out.println("  Algorithm: " + keyInfo.privateKeyInfo.getAlgorithm());
        }
    }
}
