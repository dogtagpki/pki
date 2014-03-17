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

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class AuthenticatorClient extends Client {

    public AuthenticatorResource resource;

    public AuthenticatorClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "authenticator");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(AuthenticatorResource.class);
    }

    public AuthenticatorCollection findAuthenticators(String filter, Integer start, Integer size) {
        Response response = resource.findAuthenticators(filter, start, size);
        return client.getEntity(response, AuthenticatorCollection.class);
    }

    public AuthenticatorData getAuthenticator(String authenticatorID) {
        Response response = resource.getAuthenticator(authenticatorID);
        return client.getEntity(response, AuthenticatorData.class);
    }

    public AuthenticatorData addAuthenticator(AuthenticatorData authenticatorData) {
        Response response = resource.addAuthenticator(authenticatorData);
        return client.getEntity(response, AuthenticatorData.class);
    }

    public AuthenticatorData updateAuthenticator(String authenticatorID, AuthenticatorData authenticatorData) {
        Response response = resource.updateAuthenticator(authenticatorID, authenticatorData);
        return client.getEntity(response, AuthenticatorData.class);
    }

    public AuthenticatorData changeAuthenticatorStatus(String authenticatorID, String action) {
        Response response = resource.changeAuthenticatorStatus(authenticatorID, action);
        return client.getEntity(response, AuthenticatorData.class);
    }

    public void removeAuthenticator(String authenticatorID) {
        Response response = resource.removeAuthenticator(authenticatorID);
        client.getEntity(response, Void.class);
    }
}
