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

package com.netscape.cmstools.tps.cert;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.tps.cert.TPSCertClient;
import com.netscape.certsrv.tps.cert.TPSCertData;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class TPSCertCLI extends CLI {

    public TPSCertClient certClient;

    public TPSCertCLI(CLI parent) {
        super("cert", "Certificate management commands", parent);

        addModule(new TPSCertFindCLI(this));
        addModule(new TPSCertShowCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        certClient = (TPSCertClient)parent.getClient("cert");

        super.execute(args);
    }

    public static void printCert(TPSCertData cert) {
        System.out.println("  Cert ID: " + cert.getID());
        if (cert.getSerialNumber() != null) System.out.println("  Serial Number: " + cert.getSerialNumber());
        if (cert.getSubject() != null) System.out.println("  Subject: " + cert.getSubject());
        if (cert.getTokenID() != null) System.out.println("  Token ID: " + cert.getTokenID());
        if (cert.getKeyType() != null) System.out.println("  Key Type: " + cert.getKeyType());
        if (cert.getStatus() != null) System.out.println("  Status: " + cert.getStatus());
        if (cert.getUserID() != null) System.out.println("  User ID: " + cert.getUserID());
        if (cert.getCreateTime() != null) System.out.println("  Create Time: " + cert.getCreateTime());
        if (cert.getModifyTime() != null) System.out.println("  Modify Time: " + cert.getModifyTime());

        Link link = cert.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
