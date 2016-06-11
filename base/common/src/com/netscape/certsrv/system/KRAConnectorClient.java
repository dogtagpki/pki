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

package com.netscape.certsrv.system;

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Ade Lee
 */
public class KRAConnectorClient extends Client {

    public KRAConnectorResource kraConnectorClient;

    public KRAConnectorClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "kraconnector");
        init();
    }

    public void init() throws URISyntaxException {
        kraConnectorClient = createProxy(KRAConnectorResource.class);
    }

    public void addConnector(KRAConnectorInfo info) {
        Response response = kraConnectorClient.addConnector(info);
        client.getEntity(response, Void.class);
    }

    public void addHost(String host, String port) {
        Response response = kraConnectorClient.addHost(host, port);
        client.getEntity(response, Void.class);
    }

    public void removeConnector(String host, String port) {
        Response response = kraConnectorClient.removeConnector(host, port);
        client.getEntity(response, Void.class);
    }

    public KRAConnectorInfo getConnectorInfo() {
        Response response = kraConnectorClient.getConnectorInfo();
        return client.getEntity(response, KRAConnectorInfo.class);
    }

}
