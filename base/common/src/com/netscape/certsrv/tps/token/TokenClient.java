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

import org.jboss.resteasy.client.ClientResponse;

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

    public TokenCollection findTokens(Integer start, Integer size) {
        return resource.findTokens(start, size);
    }

    public TokenData getToken(String tokenID) {
        return resource.getToken(tokenID);
    }

    public TokenData addToken(TokenData tokenData) {
        @SuppressWarnings("unchecked")
        ClientResponse<TokenData> response = (ClientResponse<TokenData>)resource.addToken(tokenData);
        return client.getEntity(response);
    }

    public TokenData updateToken(String tokenID, TokenData tokenData) {
        @SuppressWarnings("unchecked")
        ClientResponse<TokenData> response = (ClientResponse<TokenData>)resource.updateToken(tokenID, tokenData);
        return client.getEntity(response);
    }

    public void removeToken(String tokenID) {
        resource.removeToken(tokenID);
    }
}
