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
package org.dogtagpki.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * @author Endi S. Dewata
 */
public class ConfigClient extends Client {

    public final static Logger logger = LoggerFactory.getLogger(ConfigClient.class);

    public ConfigResource resource;

    public ConfigClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "config");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(ConfigResource.class);
    }

    public ConfigData getConfig() throws Exception {
        Response response = resource.getConfig();
        return client.getEntity(response, ConfigData.class);
    }

    public ConfigData getConfig(
            String names,
            String substores,
            String sessionID)
            throws Exception {

        logger.info("Getting configuration properties");

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("op", "get");
        content.putSingle("names", names);
        content.putSingle("substores", substores);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionID);

        String response = client.post("/" + subsystem + "/admin/" + subsystem + "/getConfigEntries", content);

        if (response == null) {
            throw new IOException("Unable to get configuration properties");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        logger.debug("Status: " + status);

        if (status.equals(ConfigResource.AUTH_FAILURE)) {
            throw new EAuthException(ConfigResource.AUTH_FAILURE);
        }

        if (!status.equals(ConfigResource.SUCCESS)) {
            String error = parser.getValue("Error");
            throw new IOException(error);
        }

        logger.info("Properties:");
        Map<String, String> properties = new HashMap<>();

        Document doc = parser.getDocument();
        NodeList nameNodes = doc.getElementsByTagName("name");
        int nameCount = nameNodes.getLength();

        for (int i = 0; i < nameCount; i++) {
            Node nameNode = nameNodes.item(i);
            NodeList nameChildNodes = nameNode.getChildNodes();
            String name = nameChildNodes.item(0).getNodeValue();
            logger.info("- " + name);

            Node parentNode = nameNode.getParentNode();
            NodeList siblingNodes = parentNode.getChildNodes();
            int siblingCount = siblingNodes.getLength();

            String value = "";
            for (int j = 0; j < siblingCount; j++) {
                Node siblingNode = siblingNodes.item(j);
                String siblingNodeName = siblingNode.getNodeName();
                if (!siblingNodeName.equals("value")) continue;

                NodeList valueNodes = siblingNode.getChildNodes();
                if (valueNodes.getLength() > 0) {
                    value = valueNodes.item(0).getNodeValue();
                }

                break;
            }

            properties.put(name, value);
        }

        ConfigData config = new ConfigData();
        config.setProperties(properties);

        return config;
    }

    public ConfigData updateConfig(ConfigData configData) throws Exception {
        Response response = resource.updateConfig(configData);
        return client.getEntity(response, ConfigData.class);
    }
}
