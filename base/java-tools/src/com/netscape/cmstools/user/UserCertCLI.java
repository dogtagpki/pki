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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.user;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserClient;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class UserCertCLI extends CLI {

    public UserClient userClient;

    public UserCertCLI(UserCLI parent) {
        super("cert", "User certificate management commands", parent);

        addModule(new UserCertFindCLI(this));
        addModule(new UserCertShowCLI(this));
        addModule(new UserCertAddCLI(this));
        addModule(new UserCertRemoveCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        userClient = ((UserCLI)parent).userClient;

        super.execute(args);
    }

    public static void printCert(
            UserCertData userCertData,
            boolean showPrettyPrint,
            boolean showEncoded) {

        System.out.println("  Cert ID: " + userCertData.getID());
        System.out.println("  Version: " + userCertData.getVersion());
        System.out.println("  Serial Number: " + userCertData.getSerialNumber().toHexString());
        System.out.println("  Issuer: " + userCertData.getIssuerDN());
        System.out.println("  Subject: " + userCertData.getSubjectDN());

        Link link = userCertData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }

        String prettyPrint = userCertData.getPrettyPrint();
        if (showPrettyPrint && prettyPrint != null) {
            System.out.println();
            System.out.println(prettyPrint);
        }

        String encoded = userCertData.getEncoded();
        if (showEncoded && encoded != null) {
            System.out.println();
            System.out.println(encoded);
        }
    }
}