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
//(C) 2015 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.authority;

import java.net.URISyntaxException;
import java.util.List;

import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Fraser Tweedale <ftweedal@redhat.com>
 */
public class AuthorityClient extends Client {

    public AuthorityResource proxy;

    public AuthorityClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "authority");
        proxy = createProxy(AuthorityResource.class);
    }

    public List<AuthorityData> listCAs() {
        Response response = proxy.listCAs();
        GenericType<List<AuthorityData>> type = new GenericType<List<AuthorityData>>() {};
        return client.getEntity(response, type);
    }

    public AuthorityData getCA(String caIDString) {
        Response response = proxy.getCA(caIDString);
        return client.getEntity(response, AuthorityData.class);
    }

    public AuthorityData createCA(AuthorityData data) {
        Response response = proxy.createCA(data);
        return client.getEntity(response, AuthorityData.class);
    }

    public AuthorityData modifyCA(AuthorityData data) {
        Response response = proxy.modifyCA(data.getID(), data);
        return client.getEntity(response, AuthorityData.class);
    }

    public void deleteCA(String aidString) {
        Response response = proxy.deleteCA(aidString);
        client.getEntity(response, Void.class);
    }

}
