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

import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientCLI extends CLI {

    public ClientCLI(CLI parent) {
        super("client", "Client management commands", parent);

        addModule(new ClientInitCLI(this));
        addModule(new ClientCertFindCLI(this));
        addModule(new ClientCertImportCLI(this));
        addModule(new ClientCertRemoveCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();

        super.execute(args);
    }

    public static void printCertInfo(X509Certificate cert) {
        System.out.println("  Serial Number: "+new CertId(cert.getSerialNumber()).toHexString());
        System.out.println("  Nickname: "+cert.getNickname());
        System.out.println("  Subject DN: "+cert.getSubjectDN());
        System.out.println("  Issuer DN: "+cert.getIssuerDN());
    }
}
