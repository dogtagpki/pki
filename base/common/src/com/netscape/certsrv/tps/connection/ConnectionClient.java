//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2013 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.tps.connection;

import java.net.URISyntaxException;

import org.jboss.resteasy.client.ClientResponse;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class ConnectionClient extends Client {

    public ConnectionResource resource;

    public ConnectionClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "connection");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(ConnectionResource.class);
    }

    public ConnectionCollection findConnections(Integer start, Integer size) {
        return resource.findConnections(start, size);
    }

    public ConnectionData getConnection(String connectionID) {
        return resource.getConnection(connectionID);
    }

    public ConnectionData addConnection(ConnectionData connectionData) {
        @SuppressWarnings("unchecked")
        ClientResponse<ConnectionData> response = (ClientResponse<ConnectionData>)resource.addConnection(connectionData);
        return client.getEntity(response);
    }

    public ConnectionData updateConnection(String connectionID, ConnectionData connectionData) {
        @SuppressWarnings("unchecked")
        ClientResponse<ConnectionData> response = (ClientResponse<ConnectionData>)resource.updateConnection(connectionID, connectionData);
        return client.getEntity(response);
    }

    public void removeConnection(String connectionID) {
        resource.removeConnection(connectionID);
    }
}
