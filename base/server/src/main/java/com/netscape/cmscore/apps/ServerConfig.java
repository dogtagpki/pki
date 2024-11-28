// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.apps;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class ServerConfig {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServerConfig.class);

    String unsecurePort;
    String securePort;

    public static ServerConfig load(String filename) throws Exception {

        logger.debug("ServerConfig: Parsing " + filename);

        ServerConfig serverConfig = new ServerConfig();

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(filename);

        XPathFactory xpathFactory = XPathFactory.newInstance();
        XPath xpath = xpathFactory.newXPath();

        NodeList connectors = (NodeList) xpath.evaluate(
                "/Server/Service[@name='Catalina']/Connector",
                document,
                XPathConstants.NODESET);

        int length = connectors.getLength();
        for (int i = 0; i < length; i++) {
            Element connector = (Element) connectors.item(i);

            String protocol = connector.getAttribute("protocol");
            if (protocol.startsWith("AJP/")) {
                continue;
            }

            // HTTP/1.1 connector

            String scheme = connector.getAttribute("scheme");
            String port = connector.getAttribute("port");

            if (scheme != null && scheme.equals("https")) {
                logger.debug("ServerConfig: - secure port: " + port);
                serverConfig.setSecurePort(port);

            } else {
                logger.debug("ServerConfig: - unsecure port: " + port);
                serverConfig.setUnsecurePort(port);
            }
        }

        return serverConfig;
    }

    public String getUnsecurePort() {
        return unsecurePort;
    }

    public void setUnsecurePort(String unsecurePort) {
        this.unsecurePort = unsecurePort;
    }

    public String getSecurePort() {
        return securePort;
    }

    public void setSecurePort(String securePort) {
        this.securePort = securePort;
    }
}