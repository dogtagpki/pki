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

public class ServerXml {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServerXml.class);

    String unsecurePort;
    String securePort;

    public static ServerXml load(String filename) throws Exception {

        logger.info("ServerXml: Parsing " + filename);

        ServerXml serverXml = new ServerXml();

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(filename);

        XPathFactory xpathFactory = XPathFactory.newInstance();
        XPath xpath = xpathFactory.newXPath();

        Element unsecureConnector = (Element) xpath.evaluate(
                "/Server/Service[@name='Catalina']/Connector[@name='Unsecure']",
                document,
                XPathConstants.NODE);

        String unsecurePort = unsecureConnector.getAttribute("port");
        logger.info("ServerXml: Unsecure port: " + unsecurePort);
        serverXml.setUnsecurePort(unsecurePort);

        Element secureConnector = (Element) xpath.evaluate(
                "/Server/Service[@name='Catalina']/Connector[@name='Secure']",
                document,
                XPathConstants.NODE);

        String securePort = secureConnector.getAttribute("port");
        logger.info("ServerXml: Secure port: " + securePort);
        serverXml.setSecurePort(securePort);

        return serverXml;
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
