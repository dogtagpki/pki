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

import org.dogtagpki.cli.CLI;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class PKCS11CLI extends CLI {

    public MainCLI mainCLI;

    public PKCS11CLI(MainCLI mainCLI) {
        super("pkcs11", "PKCS #11 utilities", mainCLI);
        this.mainCLI = mainCLI;

        addModule(new PKCS11CertCLI(this));
        addModule(new PKCS11KeyCLI(this));
    }

    @Override
    public String getFullName() {
        // do not include MainCLI's name
        return parent instanceof MainCLI ? name : parent.getFullName() + "-" + name;
    }
}
