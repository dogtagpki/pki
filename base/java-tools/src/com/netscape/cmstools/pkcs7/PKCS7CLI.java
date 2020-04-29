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

package com.netscape.cmstools.pkcs7;

import org.dogtagpki.cli.CLI;

import com.netscape.cmstools.cli.MainCLI;

public class PKCS7CLI extends CLI {

    public MainCLI mainCLI;

    public PKCS7CLI(MainCLI mainCLI) {
        super("pkcs7", "PKCS #7 utilities", mainCLI);
        this.mainCLI = mainCLI;

        addModule(new PKCS7CertCLI(this));
        addModule(new PKCS7ImportCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }
}
