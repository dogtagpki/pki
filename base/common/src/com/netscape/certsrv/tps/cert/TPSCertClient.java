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
package com.netscape.certsrv.tps.cert;

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class TPSCertClient extends Client {

    public TPSCertResource resource;

    public TPSCertClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "cert");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(TPSCertResource.class);
    }

    public TPSCertCollection findCerts(String filter, String tokenID, Integer start, Integer size) {
        Response response = resource.findCerts(filter, tokenID, start, size);
        return client.getEntity(response, TPSCertCollection.class);
    }

    public TPSCertData getCert(String tokenID) {
        Response response = resource.getCert(tokenID);
        return client.getEntity(response, TPSCertData.class);
    }
}
