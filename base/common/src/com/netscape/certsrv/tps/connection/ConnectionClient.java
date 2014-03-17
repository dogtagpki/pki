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

import javax.ws.rs.core.Response;

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

    public ConnectionCollection findConnections(String filter, Integer start, Integer size) {
        Response response = resource.findConnections(filter, start, size);
        return client.getEntity(response, ConnectionCollection.class);
    }

    public ConnectionData getConnection(String connectionID) {
        Response response = resource.getConnection(connectionID);
        return client.getEntity(response, ConnectionData.class);
    }

    public ConnectionData addConnection(ConnectionData connectionData) {
        Response response = resource.addConnection(connectionData);
        return client.getEntity(response, ConnectionData.class);
    }

    public ConnectionData updateConnection(String connectionID, ConnectionData connectionData) {
        Response response = resource.updateConnection(connectionID, connectionData);
        return client.getEntity(response, ConnectionData.class);
    }

    public ConnectionData changeConnectionStatus(String connectionID, String action) {
        Response response = resource.changeConnectionStatus(connectionID, action);
        return client.getEntity(response, ConnectionData.class);
    }

    public void removeConnection(String connectionID) {
        Response response = resource.removeConnection(connectionID);
        client.getEntity(response, Void.class);
    }
}
