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

import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpEntity;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class TokenClient extends Client {

    public TokenClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "tokens");
    }

    public TokenCollection findTokens(
            String filter,
            String tokenID,
            String userID,
            String type,
            TokenStatus status,
            Integer start,
            Integer size) throws Exception {

        Map<String, Object> params = new HashMap<>();
        if (filter != null) params.put("filter", filter);
        if (tokenID != null) params.put("tokenID", tokenID);
        if (userID != null) params.put("userID", userID);
        if (type != null) params.put("type", type);
        if (status != null) params.put("status", status);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);

        return get(null, params, TokenCollection.class);
    }

    public TokenData getToken(String tokenID) throws Exception {
        return get(tokenID, TokenData.class);
    }

    public TokenData addToken(TokenData tokenData) throws Exception {
        HttpEntity entity = client.entity(tokenData);
        return post(null, null, entity, TokenData.class);
    }

    public TokenData modifyToken(String tokenID, TokenData tokenData) throws Exception {
        HttpEntity entity = client.entity(tokenData);
        return patch(tokenID, null, entity, TokenData.class);
    }

    public TokenData changeTokenStatus(String tokenID, TokenStatus tokenStatus) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (tokenStatus != null) params.put("status", tokenStatus);
        return post(tokenID, params, null, TokenData.class);
    }

    public void removeToken(String tokenID) throws Exception {
        delete(tokenID, Void.class);
    }
}
