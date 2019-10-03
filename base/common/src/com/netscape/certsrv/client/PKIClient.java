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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.client;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collection;
import java.util.HashSet;

import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.Response;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.dogtagpki.common.InfoClient;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Utils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.util.CryptoProvider;


public class PKIClient {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIClient.class);

    public final static String[] MESSAGE_FORMATS = { "xml", "json" };

    public ClientConfig config;
    public PKIConnection connection;
    public CryptoProvider crypto;
    public InfoClient infoClient;

    Collection<Integer> rejectedCertStatuses = new HashSet<Integer>();
    Collection<Integer> ignoredCertStatuses = new HashSet<Integer>();

    // List to prevent displaying the same warnings/errors again.
    Collection<Integer> statuses = new HashSet<Integer>();

    public PKIClient(ClientConfig config) throws URISyntaxException {
        this(config, null);
    }

    public PKIClient(ClientConfig config, CryptoProvider crypto) throws URISyntaxException {
        this.config = config;
        this.crypto = crypto;

        connection = new PKIConnection(config);
        connection.setCallback(new PKICertificateApprovalCallback(this));

        infoClient = new InfoClient(this);
    }

    public <T> T createProxy(String subsystem, Class<T> clazz) throws URISyntaxException {

        if (subsystem == null) {
            // by default use the subsystem specified in server URL
            subsystem = getSubsystem();
        }

        if (subsystem == null) {
            throw new PKIException("Missing subsystem name.");
        }

        URI serverURI = config.getServerURL().toURI();
        URI resourceURI = new URI(
            serverURI.getScheme(),
            serverURI.getUserInfo(),
            serverURI.getHost(),
            serverURI.getPort(),
            "/" + subsystem + "/rest",
            serverURI.getQuery(),
            serverURI.getFragment());

        return connection.createProxy(resourceURI, clazz);
    }

    public String getSubsystem() {
        return config.getSubsystem();
    }

    public <T> T getEntity(Response response, Class<T> clazz) {
        return connection.getEntity(response, clazz);
    }

    public <T> T getEntity(Response response, GenericType<T> clazz) {
        return connection.getEntity(response, clazz);
    }

    public ClientConfig getConfig() {
        return config;
    }

    public CryptoProvider getCrypto() {
        return crypto;
    }

    public void setCrypto(CryptoProvider crypto) {
        this.crypto = crypto;
    }

    public PKIConnection getConnection() {
        return connection;
    }

    public byte[] downloadCACertChain(String serverURI) throws ParserConfigurationException, SAXException, IOException {
        return downloadCACertChain(serverURI, "/ee/ca/getCertChain");
    }

    public byte[] downloadCACertChain(String uri, String servletPath)
            throws ParserConfigurationException, SAXException, IOException {

        URL url = new URL(uri + servletPath);

        logger.info("Retrieving CA certificate chain from " + url);

        DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();

        Document document = documentBuilder.parse(url.openStream());
        NodeList list = document.getElementsByTagName("ChainBase64");
        Element element = (Element)list.item(0);

        String encodedChain = element.getTextContent();
        byte[] bytes = Utils.base64decode(encodedChain);

        if (logger.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder(PKCS7.HEADER);
            sb.append(Utils.base64encode(bytes, true));
            sb.append(PKCS7.FOOTER);
            logger.info(sb.toString());
        }

        return bytes;
    }

    public void addRejectedCertStatus(Integer rejectedCertStatus) {
        rejectedCertStatuses.add(rejectedCertStatus);
    }

    public void setRejectedCertStatuses(Collection<Integer> rejectedCertStatuses) {
        this.rejectedCertStatuses.clear();
        if (rejectedCertStatuses == null) return;
        this.rejectedCertStatuses.addAll(rejectedCertStatuses);
    }

    public boolean isRejected(Integer certStatus) {
        return rejectedCertStatuses.contains(certStatus);
    }

    public void addIgnoredCertStatus(Integer ignoredCertStatus) {
        ignoredCertStatuses.add(ignoredCertStatus);
    }

    public void setIgnoredCertStatuses(Collection<Integer> ignoredCertStatuses) {
        this.ignoredCertStatuses.clear();
        if (ignoredCertStatuses == null) return;
        this.ignoredCertStatuses.addAll(ignoredCertStatuses);
    }

    public boolean isIgnored(Integer certStatus) {
        return ignoredCertStatuses.contains(certStatus);
    }
}
