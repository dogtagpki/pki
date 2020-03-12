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

import java.net.URISyntaxException;
import java.util.Collection;

import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;


/**
 * @author alee
 */
public class SecurityDomainClient extends Client {

    private SecurityDomainResource securityDomainClient;
    private SecurityDomainHostResource securityDomainHostClient;

    public SecurityDomainClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "securitydomain");
        init();
    }

    public void init() throws URISyntaxException {
        securityDomainClient = createProxy(SecurityDomainResource.class);
        securityDomainHostClient = createProxy(SecurityDomainHostResource.class);
    }

    public InstallToken getInstallToken(String hostname, String subsystem) throws Exception {
        Response response = securityDomainClient.getInstallToken(hostname, subsystem);
        return client.getEntity(response, InstallToken.class);
    }

    public DomainInfo getDomainInfo() throws Exception {
        Response response = securityDomainClient.getDomainInfo();
        return client.getEntity(response, DomainInfo.class);
    }

    public Collection<SecurityDomainHost> getHosts() throws Exception {
        Response response = securityDomainHostClient.getHosts();
        GenericType<Collection<SecurityDomainHost>> type = new GenericType<Collection<SecurityDomainHost>>() {};
        return client.getEntity(response, type);
    }

    public SecurityDomainHost getHost(String hostID) throws Exception {
        Response response = securityDomainHostClient.getHost(hostID);
        return client.getEntity(response, SecurityDomainHost.class);
    }

    public void addHost(SecurityDomainHost host) throws Exception {
        Response response = securityDomainHostClient.addHost(host);
        client.getEntity(response, Void.class);
    }
}
