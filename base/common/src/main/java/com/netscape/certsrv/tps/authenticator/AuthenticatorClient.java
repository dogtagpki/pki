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
package com.netscape.certsrv.tps.authenticator;

import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.client.Entity;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class AuthenticatorClient extends Client {

    public AuthenticatorClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "authenticators");
    }

    public AuthenticatorCollection findAuthenticators(String filter, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (filter != null) params.put("filter", filter);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(null, params, AuthenticatorCollection.class);
    }

    public AuthenticatorData getAuthenticator(String authenticatorID) throws Exception {
        return get(authenticatorID, AuthenticatorData.class);
    }

    public AuthenticatorData addAuthenticator(AuthenticatorData authenticatorData) throws Exception {
        Entity<AuthenticatorData> entity = client.entity(authenticatorData);
        return post(null, null, entity, AuthenticatorData.class);
    }

    public AuthenticatorData updateAuthenticator(String authenticatorID, AuthenticatorData authenticatorData) throws Exception {
        Entity<AuthenticatorData> entity = client.entity(authenticatorData);
        return patch(authenticatorID, null, entity, AuthenticatorData.class);
    }

    public AuthenticatorData changeAuthenticatorStatus(String authenticatorID, String action) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (action != null) params.put("action", action);
        return post(authenticatorID, params, null, AuthenticatorData.class);
    }

    public void removeAuthenticator(String authenticatorID) throws Exception {
        delete(authenticatorID, Void.class);
    }
}
