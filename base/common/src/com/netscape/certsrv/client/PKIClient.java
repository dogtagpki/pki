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
import java.security.cert.CertificateEncodingException;
import java.util.Collection;
import java.util.HashSet;

import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.Response;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Base64;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NicknameConflictException;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.CryptoManager.UserCertConflictException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.TokenCertificate;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.util.CryptoProvider;
import com.netscape.cmsutil.util.Utils;


public class PKIClient {

    public final static String[] MESSAGE_FORMATS = { "xml", "json" };

    public ClientConfig config;
    public PKIConnection connection;
    public CryptoProvider crypto;

    public boolean verbose;

    Collection<Integer> rejectedCertStatuses = new HashSet<Integer>();
    Collection<Integer> ignoredCertStatuses = new HashSet<Integer>();

    // List to prevent displaying the same warnings/errors again.
    Collection<Integer> statuses = new HashSet<Integer>();

    public PKIClient(ClientConfig config) {
        this(config, null);
    }

    public PKIClient(ClientConfig config, CryptoProvider crypto) {
        this.config = config;
        this.crypto = crypto;

        connection = new PKIConnection(config);
        connection.setCallback(new PKICertificateApprovalCallback(this));
    }

    public <T> T createProxy(String subsystem, Class<T> clazz) throws URISyntaxException {

        if (subsystem == null) {
            // by default use the subsystem specified in server URI
            subsystem = getSubsystem();
        }

        if (subsystem == null) {
            throw new PKIException("Missing subsystem name.");
        }

        URI serverURI = config.getServerURI();
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

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
        connection.setVerbose(verbose);
    }

    public X509Certificate getCert(String nickname)
            throws NotInitializedException, ObjectNotFoundException, TokenException {
        CryptoManager manager = CryptoManager.getInstance();
        return manager.findCertByNickname(nickname);
    }

    public X509Certificate[] getCerts() throws NotInitializedException {
        CryptoManager manager = CryptoManager.getInstance();
        return manager.getPermCerts();
    }

    public X509Certificate[] getCACerts() throws NotInitializedException {
        CryptoManager manager = CryptoManager.getInstance();
        return manager.getCACerts();
    }

    public byte[] downloadCACertChain(String serverURI) throws ParserConfigurationException, SAXException, IOException {
        return downloadCACertChain(serverURI, "/ee/ca/getCertChain");
    }

    public byte[] downloadCACertChain(String uri, String servletPath)
            throws ParserConfigurationException, SAXException, IOException {

        URL url = new URL(uri + servletPath);

        if (verbose) System.out.println("Retrieving CA certificate chain from " + url + ".");

        DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();

        Document document = documentBuilder.parse(url.openStream());
        NodeList list = document.getElementsByTagName("ChainBase64");
        Element element = (Element)list.item(0);

        String encodedChain = element.getTextContent();
        byte[] bytes = Utils.base64decode(encodedChain);

        if (verbose) {
            System.out.println("-----BEGIN PKCS7-----");
            System.out.print(new Base64(64).encodeToString(bytes));
            System.out.println("-----END PKCS7-----");
        }

        return bytes;
    }

    public X509Certificate importCertPackage(byte[] bytes, String nickname)
            throws NotInitializedException, CertificateEncodingException,
            NicknameConflictException, UserCertConflictException,
            NoSuchItemOnTokenException, TokenException {

        CryptoManager manager = CryptoManager.getInstance();
        return manager.importCertPackage(bytes, nickname);
    }

    public X509Certificate importCACertPackage(byte[] bytes)
            throws NotInitializedException, CertificateEncodingException, TokenException {

        CryptoManager manager = CryptoManager.getInstance();
        InternalCertificate cert = (InternalCertificate)manager.importCACertPackage(bytes);

        cert.setSSLTrust(
                InternalCertificate.VALID_CA |
                InternalCertificate.TRUSTED_CA |
                InternalCertificate.TRUSTED_CLIENT_CA);

        return cert;
    }

    public void removeCert(String nickname)
            throws TokenException, ObjectNotFoundException,
            NoSuchItemOnTokenException, NotInitializedException {

        CryptoManager manager = CryptoManager.getInstance();
        X509Certificate cert = manager.findCertByNickname(nickname);

        CryptoToken cryptoToken;
        if (cert instanceof TokenCertificate) {
            TokenCertificate tokenCert = (TokenCertificate) cert;
            cryptoToken = tokenCert.getOwningToken();

        } else {
            cryptoToken = manager.getInternalKeyStorageToken();
        }

        cryptoToken.getCryptoStore().deleteCert(cert);
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
