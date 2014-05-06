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
package com.netscape.certsrv.tps.connector;

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class ConnectorClient extends Client {

    public ConnectorResource resource;

    public ConnectorClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "connector");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(ConnectorResource.class);
    }

    public ConnectorCollection findConnectors(String filter, Integer start, Integer size) {
        Response response = resource.findConnectors(filter, start, size);
        return client.getEntity(response, ConnectorCollection.class);
    }

    public ConnectorData getConnector(String connectorID) {
        Response response = resource.getConnector(connectorID);
        return client.getEntity(response, ConnectorData.class);
    }

    public ConnectorData addConnector(ConnectorData connectorData) {
        Response response = resource.addConnector(connectorData);
        return client.getEntity(response, ConnectorData.class);
    }

    public ConnectorData updateConnector(String connectorID, ConnectorData connectorData) {
        Response response = resource.updateConnector(connectorID, connectorData);
        return client.getEntity(response, ConnectorData.class);
    }

    public ConnectorData changeConnectorStatus(String connectorID, String action) {
        Response response = resource.changeConnectorStatus(connectorID, action);
        return client.getEntity(response, ConnectorData.class);
    }

    public void removeConnector(String connectorID) {
        Response response = resource.removeConnector(connectorID);
        client.getEntity(response, Void.class);
    }
}
