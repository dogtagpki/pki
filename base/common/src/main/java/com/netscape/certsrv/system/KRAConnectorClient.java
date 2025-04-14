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

import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpEntity;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Ade Lee
 */
public class KRAConnectorClient extends Client {

    public KRAConnectorClient(PKIClient client, String subsystem) {
        super(client, subsystem, "admin/kraconnector");
    }

    public void addConnector(KRAConnectorInfo info) throws Exception {
        HttpEntity entity = client.entity(info);
        post("add", null, entity, Void.class);
    }

    public void addHost(String host, String port) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (host != null) params.put("host", host);
        if (port != null) params.put("port", port);
        post("addHost", params, null, Void.class);
    }

    public void removeConnector(String host, String port) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (host != null) params.put("host", host);
        if (port != null) params.put("port", port);
        post("remove", params, null, Void.class);
    }

    public KRAConnectorInfo getConnectorInfo() throws Exception {
        return get(KRAConnectorInfo.class);
    }

}
