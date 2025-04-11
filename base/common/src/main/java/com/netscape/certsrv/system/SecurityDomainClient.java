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
package com.netscape.certsrv.system;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.client.Entity;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;


/**
 * @author alee
 */
public class SecurityDomainClient extends Client {

    public SecurityDomainClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "securityDomain");
    }

    public InstallToken getInstallToken(String hostname, String subsystem) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (hostname != null) params.put("hostname", hostname);
        if (subsystem != null) params.put("subsystem", subsystem);
        return get("installToken", params, InstallToken.class);
    }

    public DomainInfo getDomainInfo() throws Exception {
        return get("domainInfo", DomainInfo.class);
    }

    public Collection<SecurityDomainHost> getHosts() throws Exception {
        return getCollection("hosts", null,  SecurityDomainHost.class);
    }

    public SecurityDomainHost getHost(String hostID) throws Exception {
        return get("hosts/" + hostID, null, SecurityDomainHost.class);
    }

    public void addHost(SecurityDomainHost host) throws Exception {
        Entity<SecurityDomainHost> entity = client.entity(host);
        put("hosts", null, entity, Void.class);
    }

    public void removeHost(String hostID) throws Exception {
        delete("hosts/" + hostID, Void.class);
    }
}
