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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.client;

import org.dogtagpki.cli.CLI;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientCLI extends CLI {

    public MainCLI mainCLI;

    public ClientCLI(MainCLI mainCLI) {
        super("client", "Client management commands", mainCLI);
        this.mainCLI = mainCLI;

        addModule(new ClientInitCLI(this));
        addModule(new ClientCertFindCLI(this));
        addModule(new ClientCertImportCLI(this));
        addModule(new ClientCertModifyCLI(this));
        addModule(new ClientCertRemoveCLI(this));
        addModule(new ClientCertRequestCLI(this));
        addModule(new ClientCertShowCLI(this));
        addModule(new ClientCertValidateCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    @Override
    public String getManPage() {
        return "pki-client";
    }

    public static void printCertInfo(X509Certificate cert) {
        System.out.println("  Serial Number: "+new CertId(cert.getSerialNumber()).toHexString());
        System.out.println("  Nickname: "+cert.getNickname());
        System.out.println("  Subject DN: "+cert.getSubjectDN());
        System.out.println("  Issuer DN: "+cert.getIssuerDN());
    }
}
