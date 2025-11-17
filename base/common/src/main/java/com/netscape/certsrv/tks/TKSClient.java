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
package com.netscape.certsrv.tks;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

import com.fasterxml.jackson.databind.JsonNode;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.system.TPSConnectorClient;
import com.netscape.certsrv.user.UserClient;
import com.netscape.cmsutil.json.JSONObject;

public class TKSClient extends SubsystemClient {

    public TKSClient(PKIClient client) throws Exception {
        super(client, "tks");
        init();
    }

    public void init() throws Exception {
        addClient(new TPSConnectorClient(client, name));
        addClient(new UserClient(this));
    }

    public void importTransportCert(
            URI secdomainURI,
            String transportNickname,
            String transportCert,
            String sessionID) throws Exception {

        List<NameValuePair> content = new ArrayList<>();
        content.add(new BasicNameValuePair("name", transportNickname));
        content.add(new BasicNameValuePair("xmlOutput", "true"));
        content.add(new BasicNameValuePair("sessionID", sessionID));
        content.add(new BasicNameValuePair("auth_hostname", secdomainURI.getHost()));
        content.add(new BasicNameValuePair("auth_port", secdomainURI.getPort() + ""));
        content.add(new BasicNameValuePair("certificate", transportCert));

        String path = "tks/admin/tks/importTransportCert";
        String response = client.post(path, content, String.class);
        logger.debug("TKSClient: Response: " + response);

        if (response == null || response.equals("")) {
            logger.error("TKSClient: No response");
            throw new IOException("No response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        JSONObject jsonObj = new JSONObject(bis);
        JsonNode responseNode = jsonObj.getJsonNode().get("Response");
        String status = responseNode.get("Status").asText();

        logger.debug("TKSClient: Status: " + status);

        if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);
        }

        if (!status.equals(SUCCESS)) {
            String error = jsonObj.getJsonNode().get("Error").asText();
            throw new IOException(error);
        }

        logger.debug("TKSClient: Installed transport cert");
    }
}
