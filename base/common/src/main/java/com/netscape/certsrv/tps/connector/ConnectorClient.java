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

import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpEntity;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;

/**
 * @author Endi S. Dewata
 */
public class ConnectorClient extends Client {

    public ConnectorClient(SubsystemClient subsystemClient) throws Exception {
        this(subsystemClient.client, subsystemClient.name);
    }

    public ConnectorClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "connectors");
    }

    public ConnectorCollection findConnectors(String filter, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (filter != null) params.put("filter", filter);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(null, params, ConnectorCollection.class);
    }

    public ConnectorData getConnector(String connectorID) throws Exception {
        return get(connectorID, ConnectorData.class);
    }

    public ConnectorData addConnector(ConnectorData connectorData) throws Exception {
        HttpEntity entity = client.entity(connectorData);
        return post(null, null, entity, ConnectorData.class);
    }

    public ConnectorData updateConnector(String connectorID, ConnectorData connectorData) throws Exception {
        HttpEntity entity = client.entity(connectorData);
        return patch(connectorID, null, entity, ConnectorData.class);
    }

    public ConnectorData changeConnectorStatus(String connectorID, String action) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (action != null) params.put("action", action);
        return post(connectorID, params, null, ConnectorData.class);
    }

    public void removeConnector(String connectorID) throws Exception {
        delete(connectorID, Void.class);
    }
}
