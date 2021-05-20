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

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.system.TPSConnectorClient;
import com.netscape.certsrv.user.UserClient;
import com.netscape.cmsutil.xml.XMLObject;

public class TKSClient extends SubsystemClient {

    public TKSClient(PKIClient client) throws Exception {
        super(client, "tks");
        init();
    }

    public void init() throws Exception {
        addClient(new GroupClient(this));
        addClient(new SelfTestClient(client, name));
        addClient(new TPSConnectorClient(client, name));
        addClient(new UserClient(this));
    }

    public void importTransportCert(
            URI secdomainURI,
            String transportNickname,
            String transportCert,
            String sessionID) throws Exception {

        MultivaluedMap<String, String> content = new MultivaluedHashMap<>();
        content.putSingle("name", transportNickname);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionID);
        content.putSingle("auth_hostname", secdomainURI.getHost());
        content.putSingle("auth_port", secdomainURI.getPort() + "");
        content.putSingle("certificate", transportCert);

        String path = "/tks/admin/tks/importTransportCert";
        String response = client.post(path, content, String.class);
        logger.debug("TKSClient: Response: " + response);

        if (response == null || response.equals("")) {
            logger.error("TKSClient: No response");
            throw new IOException("No response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        logger.debug("TKSClient: Status: " + status);

        if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);
        }

        if (!status.equals(SUCCESS)) {
            String error = parser.getValue("Error");
            throw new IOException(error);
        }

        logger.debug("TKSClient: Installed transport cert");
    }
}
