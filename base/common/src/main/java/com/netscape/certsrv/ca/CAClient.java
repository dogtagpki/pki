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
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.ca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.system.FeatureClient;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.certsrv.user.UserClient;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.json.JSONObject;

public class CAClient extends SubsystemClient {

    public final static Logger logger = LoggerFactory.getLogger(CAClient.class);

    public CAClient(PKIClient client) throws Exception {
        super(client, "ca");
        init();
    }

    public void init() throws Exception {
        addClient(new AuthorityClient(client, name));
        addClient(new CACertClient(client, name));
        addClient(new FeatureClient(client, name));
        addClient(new GroupClient(this));
        addClient(new ProfileClient(client, name));
        addClient(new SelfTestClient(client, name));
        addClient(new UserClient(this));
    }

    public PKCS7 getCertChain() throws Exception {

        ClientConfig config = client.getConfig();
        URL serverURL = config.getServerURL();
        logger.info("Getting certificate chain from " + serverURL);

        String c = client.get("ca/admin/ca/getCertChain", String.class);
        logger.debug("Response: " + c);

        if (c == null) {
            throw new IOException("Unable to get certificate chain from " + serverURL);
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        JSONObject jsonObj = new JSONObject(bis);
        JsonNode responseNode = jsonObj.getJsonNode().get("Response");
        String chain = responseNode.get("ChainBase64").asText();

        if (chain == null || chain.length() <= 0) {
            throw new IOException("Missing certificate chain");
        }

        byte[] bytes = CryptoUtil.base64Decode(CryptoUtil.normalizeCertStr(chain));

        return new PKCS7(bytes);
    }

    public void addKRAConnector(KRAConnectorInfo info, String sessionID) throws Exception {

        MultivaluedMap<String, String> content = new MultivaluedHashMap<>();
        content.putSingle("ca.connector.KRA.enable", info.getEnable());
        content.putSingle("ca.connector.KRA.local", info.getLocal());
        content.putSingle("ca.connector.KRA.timeout", info.getTimeout());
        content.putSingle("ca.connector.KRA.uri", info.getUri());
        content.putSingle("ca.connector.KRA.host", info.getHost());
        content.putSingle("ca.connector.KRA.port", info.getPort());
        content.putSingle("ca.connector.KRA.subsystemCert", info.getSubsystemCert());
        content.putSingle("ca.connector.KRA.transportCert", info.getTransportCert());
        content.putSingle("ca.connector.KRA.transportCertNickname", info.getTransportCertNickname());
        content.putSingle("sessionID", sessionID);
        logger.debug("CAClient: content: " + content);

        String response = client.post("ca/admin/ca/updateConnector", content, String.class);
        logger.debug("CAClient: Response: " + response);

        if (response == null || response.equals("")) {
            logger.error("CAClient: Unable to update connector: No response");
            throw new IOException("Unable to update connector: No response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        JSONObject jsonObj = new JSONObject(bis);
        JsonNode responseNode = jsonObj.getJsonNode().get("Response");
        String status = responseNode.get("Status").asText();
        logger.debug("CAClient: status: " + status);

        if (status.equals("0")) {
            logger.debug("CAClient: Connector updated");

        } else if (status.equals("2")) {
            logger.error("CAClient: Unable to update connector: Authentication failure");
            throw new EAuthException("Unable to update connector: Authentication failure");

        } else {
            String error = jsonObj.getJsonNode().get("Error").asText();
            logger.error("CAClient: Unable to update connector: " + error);
            throw new IOException("Unable to update connector: " + error);
        }
    }

    public void addOCSPPublisher(URL url, String subsystemCert, String sessionID) throws Exception {

        MultivaluedMap<String, String> content = new MultivaluedHashMap<>();
        content.putSingle("xmlOutput", "true");
        content.putSingle("ocsp_host", url.getHost());
        content.putSingle("ocsp_port", url.getPort() + "");
        content.putSingle("subsystemCert", subsystemCert);
        content.putSingle("sessionID", sessionID);
        logger.debug("CAClient: content: " + content);

        String response = client.post("ca/ee/ca/updateOCSPConfig", content, String.class);
        logger.debug("CAClient: Response: " + response);

        if (response == null || response.equals("")) {
            logger.error("CAClient: Unable to update publisher: No response");
            throw new IOException("Unable to update publisher: No response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        JSONObject jsonObj = new JSONObject(bis);
        JsonNode responseNode = jsonObj.getJsonNode().get("Response");
        String status = responseNode.get("Status").asText();
        logger.debug("CAClient: status: " + status);

        if (status.equals("0")) {
            logger.debug("CAClient: Publisher updated");

        } else if (status.equals("2")) {
            logger.error("CAClient: Unable to update publisher: Authentication failure");
            throw new EAuthException("Unable to update publisher: Authentication failure");

        } else {
            String error = responseNode.get("Error").asText();
            logger.error("CAClient: Unable to update publisher: " + error);
            throw new IOException("Unable to update publisher: " + error);
        }
    }
}
