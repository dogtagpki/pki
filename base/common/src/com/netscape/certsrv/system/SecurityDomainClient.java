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

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;


/**
 * @author alee
 */
public class SecurityDomainClient extends Client {

    private SecurityDomainResource securityDomainClient;

    public SecurityDomainClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "securitydomain");
        init();
    }

    public void init() throws URISyntaxException {
        securityDomainClient = createProxy(SecurityDomainResource.class);
    }

    public InstallToken getInstallToken(String hostname, String subsystem) {
        return securityDomainClient.getInstallToken(hostname, subsystem);
    }

    public DomainInfo getDomainInfo() {
        return securityDomainClient.getDomainInfo();
    }
}
