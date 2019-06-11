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
package com.netscape.cmstools.system;

import org.dogtagpki.cli.CLI;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.TPSConnectorClient;
import com.netscape.certsrv.system.TPSConnectorData;

/**
 * @author Ade Lee
 */
public class TPSConnectorCLI extends CLI {

    public TPSConnectorClient tpsConnectorClient;

    public TPSConnectorCLI(CLI parent) {
        super("tpsconnector", "TPS connector management commands", parent);

        addModule(new TPSConnectorAddCLI(this));
        addModule(new TPSConnectorFindCLI(this));
        addModule(new TPSConnectorModCLI(this));
        addModule(new TPSConnectorRemoveCLI(this));
    }

    public String getFullName() {
        return parent.getFullName() + "-" + name;
    }

    public TPSConnectorClient getTPSConnectorClient() throws Exception {

        if (tpsConnectorClient != null) return tpsConnectorClient;

        PKIClient client = getClient();
        tpsConnectorClient = (TPSConnectorClient)parent.getClient("tpsconnector");

        return tpsConnectorClient;
    }

    public static void printConnectorInfo(TPSConnectorData data) {
        System.out.println("  Connector ID: " + data.getID());
        if (data.getHost() != null) System.out.println("  Host: " + data.getHost());
        if (data.getPort() != null) System.out.println("  Port: " + data.getPort());
        if (data.getUserID() != null) System.out.println("  User ID: " + data.getUserID());
        if (data.getNickname() != null) System.out.println("  Nickname: " + data.getNickname());

        Link link = data.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }

}
