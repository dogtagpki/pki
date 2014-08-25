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
package com.netscape.certsrv.tps.token;

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class TokenClient extends Client {

    public TokenResource resource;

    public TokenClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "token");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(TokenResource.class);
    }

    public TokenCollection findTokens(String filter, Integer start, Integer size) {
        Response response = resource.findTokens(filter, start, size);
        return client.getEntity(response, TokenCollection.class);
    }

    public TokenData getToken(String tokenID) {
        Response response = resource.getToken(tokenID);
        return client.getEntity(response, TokenData.class);
    }

    public TokenData addToken(TokenData tokenData) {
        Response response = resource.addToken(tokenData);
        return client.getEntity(response, TokenData.class);
    }

    public TokenData modifyToken(String tokenID, TokenData tokenData) {
        Response response = resource.modifyToken(tokenID, tokenData);
        return client.getEntity(response, TokenData.class);
    }

    public void removeToken(String tokenID) {
        Response response = resource.removeToken(tokenID);
        client.getEntity(response, Void.class);
    }
}
