package com.netscape.certsrv.client;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.jboss.resteasy.client.ClientResponse;
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
import com.netscape.cmsutil.util.Utils;


public class PKIClient {

    public ClientConfig config;
    public PKIConnection connection;

    public boolean verbose;

    public PKIClient(ClientConfig config) {
        this.config = config;

        connection = new PKIConnection(this);
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

    public <T> T getEntity(ClientResponse<T> response) {
        return connection.getEntity(response);
    }

    public ClientConfig getConfig() {
        return config;
    }

    public PKIConnection getConnection() {
        return connection;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
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
        return Utils.base64decode(encodedChain);
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
}
