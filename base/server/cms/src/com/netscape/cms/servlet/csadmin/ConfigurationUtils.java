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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
 package com.netscape.cms.servlet.csadmin;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import javax.xml.parsers.ParserConfigurationException;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;
import netscape.security.pkcs.ContentInfo;
import netscape.security.pkcs.PKCS10;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.SignerInfo;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509Key;

import org.apache.velocity.context.Context;
import org.jboss.resteasy.client.ClientResponse;
import org.jboss.resteasy.client.ClientResponseFailure;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NicknameConflictException;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.CryptoManager.UserCertConflictException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.BadPaddingException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Store;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.CertBag;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.Attribute;
import org.mozilla.jss.pkix.primitive.EncryptedPrivateKeyInfo;
import org.mozilla.jss.pkix.primitive.PrivateKeyInfo;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.netscape.certsrv.account.AccountClient;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.PKIConnection;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.certsrv.system.TPSConnectorClient;
import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.admin.UserService;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.http.HttpClient;
import com.netscape.cmsutil.http.HttpRequest;
import com.netscape.cmsutil.http.HttpResponse;
import com.netscape.cmsutil.http.JssSSLSocketFactory;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * Utility class for functions to be used both by the RESTful installer
 * and the UI Panels.
 *
 * @author alee
 *
 */
public class ConfigurationUtils {

    private static final String PCERT_PREFIX = "preop.cert.";
    public static String SUCCESS = "0";
    public static String FAILURE = "1";
    public static String AUTH_FAILURE = "2";
    public static final BigInteger BIG_ZERO = new BigInteger("0");
    public static final Long MINUS_ONE = Long.valueOf(-1);
    public static final String DBUSER = "pkidbuser";

    public static boolean loginToken(CryptoToken token, String tokPwd) throws TokenException,
            IncorrectPasswordException {
        boolean rv = true;
        Password password = null;
        password = new Password(tokPwd.toCharArray());

        if (token.passwordIsInitialized()) {
            CMS.debug("loginToken():token password is initialized");
            if (!token.isLoggedIn()) {
                CMS.debug("loginToken():Token is not logged in, try it");
                token.login(password);
            } else {
                CMS.debug("loginToken():Token has already logged on");
            }
        } else {
            CMS.debug("loginToken():Token password not initialized");
            rv = false;
        }
        return rv;
    }

    public static String getHttpResponse(String hostname, int port, boolean secure,
            String uri, String content, String clientnickname) throws IOException {
        return getHttpResponse(hostname, port, secure, uri, content, clientnickname, null);
    }

    public static ClientResponse<String> getClientResponse(String hostname, int port, boolean secure,
            String path, String content, String clientnickname,
            SSLCertificateApprovalCallback certApprovalCallback)
            throws Exception {

        String protocol = secure ? "https" : "http";
        ClientConfig config = new ClientConfig();
        config.setServerURI(protocol + "://" + hostname + ":" + port + path);
        config.setCertNickname(clientnickname);

        PKIClient client = new PKIClient(config);
        PKIConnection connection = client.getConnection();
        ClientResponse<String> response = connection.post(content);

        return response;
    }

    //TODO - replace with Jack's connector code
    // or as we replace calls with restful calls,  remove altogether
    public static String getHttpResponse(String hostname, int port, boolean secure,
            String uri, String content, String clientnickname,
            SSLCertificateApprovalCallback certApprovalCallback)
            throws IOException {
        HttpClient httpclient = null;
        String c = null;

        try {
            if (secure) {
                JssSSLSocketFactory factory = null;
                if (clientnickname != null && clientnickname.length() > 0)
                    factory = new JssSSLSocketFactory(clientnickname);
                else
                    factory = new JssSSLSocketFactory();

                httpclient = new HttpClient(factory, certApprovalCallback);
            } else {
                httpclient = new HttpClient();
            }
            httpclient.connect(hostname, port);
            HttpRequest httprequest = new HttpRequest();

            httprequest.setMethod(HttpRequest.POST);
            httprequest.setURI(uri);
            httprequest.setHeader("user-agent", "HTTPTool/1.0");
            httprequest.setHeader("content-type",
                    "application/x-www-form-urlencoded");
            if (content != null && content.length() > 0) {
                String content_c = content;
                httprequest.setHeader("content-length", "" + content_c.length());
                httprequest.setContent(content_c);
            }
            HttpResponse httpresponse = httpclient.send(httprequest);

            c = httpresponse.getContent();
        } catch (ConnectException e) {
            CMS.debug("getHttpResponse: " + e.toString());
            throw new IOException("The server you tried to contact is not running.");
        } catch (Exception e) {
            CMS.debug("getHttpResponse: " + e.toString());
            throw new IOException(e.toString());
        } finally {
            if (httpclient.connected()) {
                httpclient.disconnect();
            }
        }

        return c;
    }

    public static void importCertChain(String host, int port, String serverPath, String tag)
            throws IOException, SAXException, ParserConfigurationException, CertificateEncodingException,
            CertificateException, NotInitializedException, TokenException, EBaseException {
        IConfigStore cs = CMS.getConfigStore();
        ConfigCertApprovalCallback certApprovalCallback = new ConfigCertApprovalCallback();
        XMLObject parser = null;
        String c = ConfigurationUtils.getHttpResponse(host, port, true, serverPath, null, null,
                certApprovalCallback);
        if (c != null) {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            parser = new XMLObject(bis);
            String certchain = parser.getValue("ChainBase64");
            if ((certchain != null) && (certchain.length() > 0)) {
                certchain = CryptoUtil.normalizeCertStr(certchain);
                cs.putString("preop." + tag + ".pkcs7", certchain);

                // separate individual certs in chain for display
                byte[] decoded = CryptoUtil.base64Decode(certchain);
                java.security.cert.X509Certificate[] b_certchain = CryptoUtil.getX509CertificateFromPKCS7(decoded);
                int size = 0;

                if (b_certchain != null) {
                    size = b_certchain.length;
                }
                cs.putInteger("preop." + tag + ".certchain.size", size);
                for (int i = 0; i < size; i++) {
                    byte[] bb = b_certchain[i].getEncoded();
                    cs.putString("preop." + tag + ".certchain." + i,
                            CryptoUtil.normalizeCertStr(CryptoUtil.base64Encode(bb)));
                }

                cs.commit(false);
                CryptoUtil.importCertificateChain(certchain);
            } else {
                throw new IOException("importCertChain: Security Domain response does not contain certificate chain");
            }
        } else {
            throw new IOException("importCertChain: Failed to get response from security domain");
        }
    }

    public static String getInstallToken(String sdhost, int sdport, String user, String passwd) throws Exception {
        IConfigStore cs = CMS.getConfigStore();
        boolean oldtoken = cs.getBoolean("cs.useOldTokenInterface", false);

        if (oldtoken) {
            return ConfigurationUtils.getOldToken(sdhost, sdport, user, passwd);
        }

        String csType = cs.getString("cs.type");

        ClientConfig config = new ClientConfig();
        config.setServerURI("https://" + sdhost + ":" + sdport);
        config.setUsername(user);
        config.setPassword(passwd);

        PKIClient client = new PKIClient(config);
        PKIConnection connection = client.getConnection();

        // Ignore the "UNTRUSTED_ISSUER" validity status
        // during PKI instance creation since we are
        // utilizing an untrusted temporary CA cert.
        connection.addIgnoredCertStatus(SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER);

        // Ignore the "CA_CERT_INVALID" validity status
        // during PKI instance creation since we are
        // utilizing an untrusted temporary CA cert.
        connection.addIgnoredCertStatus(SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID);

        AccountClient accountClient = new AccountClient(client, "ca");
        SecurityDomainClient sdClient = new SecurityDomainClient(client, "ca");

        try {
            accountClient.login();
            InstallToken token = sdClient.getInstallToken(sdhost, csType);
            accountClient.logout();
            return token.getToken();

        } catch (ClientResponseFailure e) {
            if (e.getResponse().getResponseStatus() == Response.Status.NOT_FOUND) {
                // try the old servlet
                String tokenString = getOldCookie(sdhost, sdport, user, passwd);
                return tokenString;
            }

            throw e;
        }
    }

    public static String getOldCookie(String sdhost, int sdport, String user, String passwd) throws Exception {
        IConfigStore cs = CMS.getConfigStore();

        String subca_url = "https://" + CMS.getEEHost() + ":"
                + CMS.getAdminPort() + "/ca/admin/console/config/wizard" +
                "?p=5&subsystem=" + cs.getString("cs.type");

        String content = "uid=" + URLEncoder.encode(user, "UTF-8") + "&pwd=" + URLEncoder.encode(passwd, "UTF-8") +
                "&url=" + URLEncoder.encode(subca_url, "UTF-8");

        ClientResponse<String> response = getClientResponse(sdhost, sdport, true, "/ca/admin/ca/getCookie",
                content, null, null);
        String body = response.getEntity();
        return getContentValue(body, "header.session_id");
    }

    public static String getOldToken(String sdhost, int sdport, String user, String passwd) throws IOException,
            EPropertyNotFound, EBaseException, URISyntaxException {
        IConfigStore cs = CMS.getConfigStore();

        String subca_url = "https://" + CMS.getEEHost() + ":"
                + CMS.getAdminPort() + "/ca/admin/console/config/wizard" +
                "?p=5&subsystem=" + cs.getString("cs.type");

        String content = "uid=" + URLEncoder.encode(user, "UTF-8") + "&pwd=" + URLEncoder.encode(passwd, "UTF-8") +
                "&url=" + URLEncoder.encode(subca_url, "UTF-8");

        String response = ConfigurationUtils.getHttpResponse(sdhost, sdport, true,
                "/ca/admin/ca/getCookie", content, null);

        return getContentValue(response, "header.session_id");
    }

    public static String getContentValue(String body, String header) {
        StringTokenizer st = new StringTokenizer(body, "\n");

        while (st.hasMoreTokens()) {
            String line = st.nextToken();
            // format for line assumed to be name="value";

            int eqPos = line.indexOf('=');
            if (eqPos != -1) {
                String name = line.substring(0, eqPos).trim();
                String tempval = line.substring(eqPos + 1).trim();
                String value = tempval.replaceAll("(^\")|(\";$)","");

                if (name.equals(header)) {
                    return value;
                }
            }
        }
        return null;
    }

    public static String getGroupName(String uid, String subsystemname) {
        IUGSubsystem subsystem = (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));
        if (subsystem.isMemberOf(uid, "Enterprise CA Administrators") && subsystemname.equals("CA")) {
            return "Enterprise CA Administrators";
        } else if (subsystem.isMemberOf(uid, "Enterprise KRA Administrators") && subsystemname.equals("KRA")) {
            return "Enterprise KRA Administrators";
        } else if (subsystem.isMemberOf(uid, "Enterprise OCSP Administrators") && subsystemname.equals("OCSP")) {
            return "Enterprise OCSP Administrators";
        } else if (subsystem.isMemberOf(uid, "Enterprise TKS Administrators") && subsystemname.equals("TKS")) {
            return "Enterprise TKS Administrators";
        } else if (subsystem.isMemberOf(uid, "Enterprise RA Administrators") && subsystemname.equals("RA")) {
            return "Enterprise RA Administrators";
        } else if (subsystem.isMemberOf(uid, "Enterprise TPS Administrators") && subsystemname.equals("TPS")) {
            return "Enterprise TPS Administrators";
        }
        return null;
    }

    public static String getDomainXML(String hostname, int https_admin_port, boolean https)
            throws IOException, SAXException, ParserConfigurationException {
        CMS.debug("getDomainXML start");
        String c = getHttpResponse(hostname, https_admin_port, https, "/ca/admin/ca/getDomainXML", null, null, null);
        if (c != null) {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser = null;

            parser = new XMLObject(bis);
            String status = parser.getValue("Status");
            CMS.debug("getDomainXML: status=" + status);

            if (status.equals(SUCCESS)) {
                String domainInfo = parser.getValue("DomainInfo");
                CMS.debug("getDomainXML: domainInfo=" + domainInfo);
                return domainInfo;
            } else {
                String error = parser.getValue("Error");
                throw new IOException(error);
            }

        }
        return null;
    }

    public static void getSecurityDomainPorts(String domainXML, String host, int port) throws SAXException,
            IOException, ParserConfigurationException {
        ByteArrayInputStream bis = new ByteArrayInputStream(domainXML.getBytes());
        IConfigStore cs = CMS.getConfigStore();

        XMLObject parser = new XMLObject(bis);
        Document doc = parser.getDocument();
        NodeList nodeList = doc.getElementsByTagName("CA");

        int len = nodeList.getLength();
        CMS.debug("len is " + len);
        for (int i = 0; i < len; i++) {
            String hostname = parser.getValuesFromContainer(nodeList.item(i), "Host").elementAt(0);
            String admin_port = parser.getValuesFromContainer(nodeList.item(i), "SecureAdminPort").elementAt(0);
            CMS.debug("hostname: <" + hostname + ">");
            CMS.debug("admin_port: <" + admin_port + ">");

            if (hostname.equals(host) && admin_port.equals(port + "")) {
                cs.putString("securitydomain.httpport",
                        parser.getValuesFromContainer(nodeList.item(i), "UnSecurePort").elementAt(0));
                cs.putString("securitydomain.httpsagentport",
                        parser.getValuesFromContainer(nodeList.item(i), "SecureAgentPort").elementAt(0));
                cs.putString("securitydomain.httpseeport",
                        parser.getValuesFromContainer(nodeList.item(i), "SecurePort").elementAt(0));

                break;
            }
        }
    }

    public static Vector<String> getUrlListFromSecurityDomain(IConfigStore config,
            String type, String portType)
            throws EPropertyNotFound, EBaseException, IOException, SAXException, ParserConfigurationException {
        Vector<String> v = new Vector<String>();

        String hostname = config.getString("securitydomain.host");
        int httpsadminport = config.getInteger("securitydomain.httpsadminport");

        CMS.debug("getUrlListFromSecurityDomain(): Getting domain.xml from CA...");
        String c = getDomainXML(hostname, httpsadminport, true);

        CMS.debug("getUrlListFromSecurityDomain: Getting " + portType + " from Security Domain ...");
        if (!portType.equals("UnSecurePort") &&
                !portType.equals("SecureAgentPort") &&
                !portType.equals("SecurePort") &&
                !portType.equals("SecureAdminPort")) {
            CMS.debug("getUrlListFromSecurityDomain:  " +
                    "unknown port type " + portType);
            return v;
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser = new XMLObject(bis);
        Document doc = parser.getDocument();
        NodeList nodeList = doc.getElementsByTagName(type);

        // save domain name in cfg
        config.putString("securitydomain.name", parser.getValue("Name"));

        int len = nodeList.getLength();

        CMS.debug("Len " + len);
        for (int i = 0; i < len; i++) {
            Vector<String> v_name = parser.getValuesFromContainer(nodeList.item(i), "SubsystemName");
            Vector<String> v_host = parser.getValuesFromContainer(nodeList.item(i), "Host");
            Vector<String> v_port = parser.getValuesFromContainer(nodeList.item(i), portType);
            Vector<String> v_admin_port = parser.getValuesFromContainer(nodeList.item(i), "SecureAdminPort");

            if (v_host.elementAt(0).equals(hostname)
                    && v_admin_port.elementAt(0).equals(new Integer(httpsadminport).toString())) {
                // add security domain CA to the beginning of list
                v.add(0, v_name.elementAt(0) + " - https://" + v_host.elementAt(0) + ":" + v_port.elementAt(0));
            } else {
                v.addElement(v_name.elementAt(0) + " - https://" + v_host.elementAt(0) + ":" + v_port.elementAt(0));
            }
        }

        return v;
    }

    public static boolean isValidCloneURI(String domainXML, String cloneHost, int clonePort) throws EPropertyNotFound,
            EBaseException, SAXException, IOException, ParserConfigurationException {
        IConfigStore cs = CMS.getConfigStore();
        String csType = cs.getString("cs.type");
        ByteArrayInputStream bis = new ByteArrayInputStream(domainXML.getBytes());

        XMLObject parser = new XMLObject(bis);
        Document doc = parser.getDocument();
        NodeList nodeList = doc.getElementsByTagName(csType.toUpperCase());

        int len = nodeList.getLength();
        for (int i = 0; i < len; i++) {
            String hostname = parser.getValuesFromContainer(nodeList.item(i), "Host").elementAt(0);
            String secure_port = parser.getValuesFromContainer(nodeList.item(i), "SecurePort").elementAt(0);

            if (hostname.equals(cloneHost) && secure_port.equals(clonePort + "")) {
                cs.putString("preop.master.hostname", cloneHost);
                cs.putInteger("preop.master.httpsport", clonePort);
                cs.putString("preop.master.httpsadminport",
                        parser.getValuesFromContainer(nodeList.item(i), "SecureAdminPort").elementAt(0));
                return true;
            }
        }

        return false;
    }

    public static void getConfigEntriesFromMaster()
            throws IOException, EBaseException, SAXException, ParserConfigurationException {

        IConfigStore config = CMS.getConfigStore();
        String cstype = "";

        cstype = config.getString("cs.type", "");

        cstype = cstype.toLowerCase();

        String session_id = CMS.getConfigSDSessionId();
        String master_hostname = config.getString("preop.master.hostname", "");
        int master_port = config.getInteger("preop.master.httpsadminport", -1);
        int master_ee_port = config.getInteger("preop.master.httpsport", -1);

        String content = "";
        if (cstype.equals("ca") || cstype.equals("kra")) {
            content = "type=request&xmlOutput=true&sessionID=" + session_id;
            CMS.debug("http content=" + content);
            updateNumberRange(master_hostname, master_ee_port, master_port, true, content, "request");

            content = "type=serialNo&xmlOutput=true&sessionID=" + session_id;
            updateNumberRange(master_hostname, master_ee_port, master_port, true, content, "serialNo");

            content = "type=replicaId&xmlOutput=true&sessionID=" + session_id;
            updateNumberRange(master_hostname, master_ee_port, master_port, true, content, "replicaId");
        }

        String list = "";

        list = config.getString("preop.cert.list", "");

        StringBuffer c1 = new StringBuffer();
        StringBuffer s1 = new StringBuffer();
        StringTokenizer tok = new StringTokenizer(list, ",");
        while (tok.hasMoreTokens()) {
            String t1 = tok.nextToken();
            if (t1.equals("sslserver"))
                continue;
            c1.append(",cloning." + t1 + ".nickname");
            c1.append(",cloning." + t1 + ".dn");
            c1.append(",cloning." + t1 + ".keytype");
            c1.append(",cloning." + t1 + ".keyalgorithm");
            c1.append(",cloning." + t1 + ".privkey.id");
            c1.append(",cloning." + t1 + ".pubkey.exponent");
            c1.append(",cloning." + t1 + ".pubkey.modulus");
            c1.append(",cloning." + t1 + ".pubkey.encoded");

            if (s1.length() != 0)
                s1.append(",");
            s1.append(cstype + "." + t1);
        }

        if (!cstype.equals("ca")) {
            c1.append(",cloning.ca.hostname,cloning.ca.httpport,cloning.ca.httpsport,cloning.ca.list,cloning.ca.pkcs7,cloning.ca.type");
        }

        if (cstype.equals("ca")) {
            /* get ca connector details */
            if (s1.length() != 0)
                s1.append(",");
            s1.append("ca.connector.KRA");
        }

        s1.append(",internaldb,internaldb.ldapauth,internaldb.ldapconn");

        content =
                "op=get&names=cloning.module.token,cloning.token,instanceId,internaldb.basedn,internaldb.ldapauth.password,"
                        + "internaldb.replication.password" + c1.toString()
                        + "&substores=" + s1.toString()
                        + "&xmlOutput=true&sessionID="
                        + session_id;
        boolean success = updateConfigEntries(master_hostname, master_port, true,
                "/" + cstype + "/admin/" + cstype + "/getConfigEntries", content, config);
        if (!success) {
            throw new IOException("Failed to get configuration entries from the master");
        }
        config.putString("preop.clone.configuration", "true");

        config.commit(false);

    }

    public static void updateNumberRange(String hostname, int eePort, int adminPort, boolean https, String content,
            String type) throws IOException, EBaseException, SAXException, ParserConfigurationException {
        CMS.debug("updateNumberRange start host=" + hostname + " adminPort=" + adminPort + " eePort=" + eePort);
        IConfigStore cs = CMS.getConfigStore();

        String cstype = cs.getString("cs.type", "");
        cstype = cstype.toLowerCase();

        String serverPath = "/" + cstype + "/admin/" + cstype + "/updateNumberRange";
        String c = null;
        XMLObject parser = null;
        try {
            c = getHttpResponse(hostname, adminPort, https, serverPath, content, null, null);
            if (c == null || c.equals("")) {
                CMS.debug("updateNumberRange: content is null.");
                throw new IOException("The server you want to contact is not available");
            }

            CMS.debug("content from admin interface ="+ c);
            // when the admin servlet is unavailable, we return a badly formatted error page
            // in that case, this will throw an exception and be passed into the catch block.
            parser = new XMLObject(new ByteArrayInputStream(c.getBytes()));
        } catch (Exception e) {
            // for backward compatibility, try the old ee interface too
            CMS.debug("updateNumberRange: Failed to contact master using admin port" + e);
            CMS.debug("updateNumberRange: Attempting to contact master using EE port");
            serverPath = "/" + cstype + "/ee/" + cstype + "/updateNumberRange";
            c = getHttpResponse(hostname, eePort, https, serverPath, content, null, null);
            if (c == null || c.equals("")) {
                CMS.debug("updateNumberRange: content is null.");
                throw new IOException("The server you want to contact is not available");
            }
            CMS.debug("content from ee interface =" + c);
            parser = new XMLObject(new ByteArrayInputStream(c.getBytes()));
        }

        String status = parser.getValue("Status");

        CMS.debug("updateNumberRange(): status=" + status);
        if (status.equals(SUCCESS)) {
            String beginNum = parser.getValue("beginNumber");
            String endNum = parser.getValue("endNumber");
            if (type.equals("request")) {
                cs.putString("dbs.beginRequestNumber", beginNum);
                cs.putString("dbs.endRequestNumber", endNum);
            } else if (type.equals("serialNo")) {
                cs.putString("dbs.beginSerialNumber", beginNum);
                cs.putString("dbs.endSerialNumber", endNum);
            } else if (type.equals("replicaId")) {
                cs.putString("dbs.beginReplicaNumber", beginNum);
                cs.putString("dbs.endReplicaNumber", endNum);
            }
            // enable serial number management in clone
            cs.putString("dbs.enableSerialManagement", "true");
            cs.commit(false);
            return;
        } else if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);
        } else {
            String error = parser.getValue("Error");
            throw new IOException(error);
        }
    }

    public static boolean updateConfigEntries(String hostname, int port, boolean https,
            String servlet, String uri, IConfigStore config)
                    throws IOException, EBaseException, SAXException, ParserConfigurationException {
        CMS.debug("updateConfigEntries start");
        String c = getHttpResponse(hostname, port, https, servlet, uri, null, null);

        if (c != null) {

            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser = null;

            parser = new XMLObject(bis);

            String status = parser.getValue("Status");
            CMS.debug("updateConfigEntries: status=" + status);

            if (status.equals(SUCCESS)) {
                String cstype = "";

                cstype = config.getString("cs.type", "");

                Document doc = parser.getDocument();
                NodeList list = doc.getElementsByTagName("name");
                int len = list.getLength();
                for (int i = 0; i < len; i++) {
                    Node n = list.item(i);
                    NodeList nn = n.getChildNodes();
                    String name = nn.item(0).getNodeValue();
                    Node parent = n.getParentNode();
                    nn = parent.getChildNodes();
                    int len1 = nn.getLength();
                    String v = "";
                    for (int j = 0; j < len1; j++) {
                        Node nv = nn.item(j);
                        String val = nv.getNodeName();
                        if (val.equals("value")) {
                            NodeList n2 = nv.getChildNodes();
                            if (n2.getLength() > 0)
                                v = n2.item(0).getNodeValue();
                            break;
                        }
                    }

                    if (name.equals("internaldb.basedn")) {
                        config.putString(name, v);
                        config.putString("preop.internaldb.master.basedn", v);
                    } else if (name.startsWith("internaldb")) {
                        config.putString(name.replaceFirst("internaldb", "preop.internaldb.master"), v);
                    } else if (name.equals("instanceId")) {
                        config.putString("preop.master.instanceId", v);
                    } else if (name.equals("cloning.signing.nickname")) {
                        config.putString("preop.master.signing.nickname", v);
                        config.putString("preop.cert.signing.nickname", v);
                    } else if (name.equals("cloning.ocsp_signing.nickname")) {
                        config.putString("preop.master.ocsp_signing.nickname", v);
                        config.putString("preop.cert.ocsp_signing.nickname", v);
                    } else if (name.equals("cloning.subsystem.nickname")) {
                        config.putString("preop.master.subsystem.nickname", v);
                        config.putString("preop.cert.subsystem.nickname", v);
                    } else if (name.equals("cloning.transport.nickname")) {
                        config.putString("preop.master.transport.nickname", v);
                        config.putString("kra.transportUnit.nickName", v);
                        config.putString("preop.cert.transport.nickname", v);
                    } else if (name.equals("cloning.storage.nickname")) {
                        config.putString("preop.master.storage.nickname", v);
                        config.putString("kra.storageUnit.nickName", v);
                        config.putString("preop.cert.storage.nickname", v);
                    } else if (name.equals("cloning.audit_signing.nickname")) {
                        config.putString("preop.master.audit_signing.nickname", v);
                        config.putString("preop.cert.audit_signing.nickname", v);
                        config.putString(name, v);
                    } else if (name.startsWith("cloning.ca")) {
                        config.putString(name.replaceFirst("cloning", "preop"), v);
                    } else if (name.equals("cloning.signing.keyalgorithm")) {
                        config.putString(name.replaceFirst("cloning", "preop.cert"), v);
                        if (cstype.equals("CA")) {
                            config.putString("ca.crl.MasterCRL.signingAlgorithm", v);
                            config.putString("ca.signing.defaultSigningAlgorithm", v);
                        } else if (cstype.equals("OCSP")) {
                            config.putString("ocsp.signing.defaultSigningAlgorithm", v);
                        }
                    } else if (name.equals("cloning.transport.keyalgorithm")) {
                        config.putString(name.replaceFirst("cloning", "preop.cert"), v);
                        config.putString("kra.transportUnit.signingAlgorithm", v);
                    } else if (name.equals("cloning.ocsp_signing.keyalgorithm")) {
                        config.putString(name.replaceFirst("cloning", "preop.cert"), v);
                        if (cstype.equals("CA")) {
                            config.putString("ca.ocsp_signing.defaultSigningAlgorithm", v);
                        }
                    } else if (name.startsWith("cloning")) {
                        config.putString(name.replaceFirst("cloning", "preop.cert"), v);
                    } else {
                        config.putString(name, v);
                    }
                }

                // set master ldap password (if it exists) temporarily in password store
                // in case it is needed for replication.  Not stored in password.conf.

                String master_pwd = config.getString("preop.internaldb.master.ldapauth.password", "");
                if (!master_pwd.equals("")) {
                    config.putString("preop.internaldb.master.ldapauth.bindPWPrompt", "master_internaldb");
                    String passwordFile = config.getString("passwordFile");
                    IConfigStore psStore = CMS.createFileConfigStore(passwordFile);
                    psStore.putString("master_internaldb", master_pwd);
                    psStore.commit(false);
                }

                return true;
            } else if (status.equals(AUTH_FAILURE)) {
                throw new EAuthException(AUTH_FAILURE);
            } else {
                String error = parser.getValue("Error");
                throw new IOException(error);
            }
        }

        return false;
    }

    public static void restoreCertsFromP12(String p12File, String p12Pass) throws EPropertyNotFound, EBaseException,
            InvalidKeyException, CertificateException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, IllegalStateException, TokenException, IllegalBlockSizeException,
            BadPaddingException, NotInitializedException, NicknameConflictException, UserCertConflictException,
            NoSuchItemOnTokenException, InvalidBERException, IOException {
        byte b[] = new byte[1000000];

        FileInputStream fis = new FileInputStream(p12File);
        while (fis.available() > 0)
            fis.read(b);
        fis.close();

        ByteArrayInputStream bis = new ByteArrayInputStream(b);
        StringBuffer reason = new StringBuffer();
        Password password = new Password(p12Pass.toCharArray());
        PFX pfx = null;
        boolean verifypfx = false;

        pfx = (PFX) (new PFX.Template()).decode(bis);
        verifypfx = pfx.verifyAuthSafes(password, reason);

        if (verifypfx) {
            AuthenticatedSafes safes = pfx.getAuthSafes();
            Vector<Vector<Object>> pkeyinfo_collection = new Vector<Vector<Object>>();
            Vector<Vector<Object>> cert_collection = new Vector<Vector<Object>>();
            for (int i = 0; i < safes.getSize(); i++) {
                SEQUENCE scontent = safes.getSafeContentsAt(null, i);
                for (int j = 0; j < scontent.size(); j++) {
                    SafeBag bag = (SafeBag) scontent.elementAt(j);
                    OBJECT_IDENTIFIER oid = bag.getBagType();
                    if (oid.equals(SafeBag.PKCS8_SHROUDED_KEY_BAG)) {
                        EncryptedPrivateKeyInfo privkeyinfo =
                                (EncryptedPrivateKeyInfo) bag.getInterpretedBagContent();
                        PrivateKeyInfo pkeyinfo = privkeyinfo.decrypt(password, new PasswordConverter());
                        Vector<Object> pkeyinfo_v = new Vector<Object>();
                        pkeyinfo_v.addElement(pkeyinfo);
                        SET bagAttrs = bag.getBagAttributes();
                        for (int k = 0; k < bagAttrs.size(); k++) {
                            Attribute attrs = (Attribute) bagAttrs.elementAt(k);
                            OBJECT_IDENTIFIER aoid = attrs.getType();
                            if (aoid.equals(SafeBag.FRIENDLY_NAME)) {
                                SET val = attrs.getValues();
                                ANY ss = (ANY) val.elementAt(0);
                                ByteArrayInputStream bbis = new ByteArrayInputStream(ss.getEncoded());
                                BMPString sss = (BMPString) new BMPString.Template().decode(bbis);
                                String s = sss.toString();
                                pkeyinfo_v.addElement(s);
                            }
                        }
                        pkeyinfo_collection.addElement(pkeyinfo_v);
                    } else if (oid.equals(SafeBag.CERT_BAG)) {
                        CertBag cbag = (CertBag) bag.getInterpretedBagContent();
                        OCTET_STRING str = (OCTET_STRING) cbag.getInterpretedCert();
                        byte[] x509cert = str.toByteArray();
                        Vector<Object> cert_v = new Vector<Object>();
                        cert_v.addElement(x509cert);
                        SET bagAttrs = bag.getBagAttributes();

                        if (bagAttrs != null) {
                            for (int k = 0; k < bagAttrs.size(); k++) {
                                Attribute attrs = (Attribute) bagAttrs.elementAt(k);
                                OBJECT_IDENTIFIER aoid = attrs.getType();
                                if (aoid.equals(SafeBag.FRIENDLY_NAME)) {
                                    SET val = attrs.getValues();
                                    ANY ss = (ANY) val.elementAt(0);
                                    ByteArrayInputStream bbis = new ByteArrayInputStream(ss.getEncoded());
                                    BMPString sss = (BMPString) (new BMPString.Template()).decode(bbis);
                                    String s = sss.toString();
                                    cert_v.addElement(s);
                                }
                            }
                        }

                        cert_collection.addElement(cert_v);
                    }
                }
            }

            importkeycert(pkeyinfo_collection, cert_collection);
        } else {
            throw new IOException("P12 File is incorrect");
        }

    }

    public static boolean isCertdbCloned() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            CryptoManager cm = CryptoManager.getInstance();
            String certList = cs.getString("preop.cert.list");
            String cstype = cs.getString("cs.type").toLowerCase();
            StringTokenizer st = new StringTokenizer(certList, ",");
            while (st.hasMoreTokens()) {
                String tag = st.nextToken();
                if (tag.equals("sslserver"))
                    continue;
                String tokenname = cs.getString("preop.module.token", "");
                cm.getTokenByName(tokenname); // throw exception if token doesn't exist
                String name1 = "preop.master." + tag + ".nickname";
                String nickname = cs.getString(name1, "");
                if (!tokenname.equals("Internal Key Storage Token") &&
                        !tokenname.equals("internal"))
                    nickname = tokenname + ":" + nickname;

                CMS.debug("isCertdbCloned: " + nickname);

                // TODO : remove this when we eliminate the extraneous nicknames
                // needed for self tests
                cs.putString(cstype + ".cert." + tag + ".nickname", nickname);

                X509Certificate cert = cm.findCertByNickname(nickname);
                if (cert == null)
                    return false;
            }
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public static void importkeycert(Vector<Vector<Object>> pkeyinfo_collection,
            Vector<Vector<Object>> cert_collection) throws IOException, CertificateException, TokenException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalStateException,
            IllegalBlockSizeException, BadPaddingException, NotInitializedException, NicknameConflictException,
            UserCertConflictException, NoSuchItemOnTokenException, EPropertyNotFound, EBaseException {
        CryptoManager cm = CryptoManager.getInstance();

        // delete all existing certificates first
        deleteExistingCerts();

        ArrayList<String> masterList = getMasterCertKeyList();

        for (int i = 0; i < pkeyinfo_collection.size(); i++) {
            Vector<Object> pkeyinfo_v = pkeyinfo_collection.elementAt(i);
            PrivateKeyInfo pkeyinfo = (PrivateKeyInfo) pkeyinfo_v.elementAt(0);
            String nickname = (String) pkeyinfo_v.elementAt(1);

            if (! importRequired(masterList,nickname)) {
                CMS.debug("Ignoring key " + nickname);
                continue;
            }

            byte[] x509cert = getX509Cert(nickname, cert_collection);
            X509Certificate cert = cm.importCACertPackage(x509cert);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            pkeyinfo.encode(bos);
            byte[] pkey = bos.toByteArray();

            PublicKey publickey = cert.getPublicKey();
            CryptoToken token = cm.getInternalKeyStorageToken();
            CryptoStore store = token.getCryptoStore();

            try {
                store.deleteCert(cert);
            } catch (NoSuchItemOnTokenException e) {
                // this is OK
            }

            KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);
            SymmetricKey sk = kg.generate();
            byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            IVParameterSpec param = new IVParameterSpec(iv);
            Cipher c = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
            c.initEncrypt(sk, param);
            byte[] encpkey = c.doFinal(pkey);

            KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
            wrapper.initUnwrap(sk, param);
            wrapper.unwrapPrivate(encpkey, getPrivateKeyType(publickey), publickey);

        }

        for (int i = 0; i < cert_collection.size(); i++) {

            Vector<Object> cert_v = cert_collection.elementAt(i);
            byte[] cert = (byte[]) cert_v.elementAt(0);
            if (cert_v.size() > 1) {
                String name = (String) cert_v.elementAt(1);
                if (! masterList.contains(name)) {
                    CMS.debug("Not importing " + name);
                    // only import the master's system certs
                    continue;
                }
                // we need to delete the trusted CA certificate if it is
                // the same as the ca signing certificate
                if (isCASigningCert(name)) {
                    X509Certificate certchain = getX509CertFromToken(cert);
                    if (certchain != null) {
                        CryptoToken token = cm.getInternalKeyStorageToken();
                        CryptoStore store = token.getCryptoStore();
                        if (store instanceof PK11Store) {
                            try {
                                PK11Store pk11store = (PK11Store) store;
                                pk11store.deleteCertOnly(certchain);
                            } catch (Exception ee) {
                                CMS.debug("importKeyCert: Exception=" + ee.toString());
                            }
                        }
                    }
                }

                X509Certificate xcert = cm.importUserCACertPackage(cert, name);
                if (isCASigningCert(name)) {
                    // we need to change the trust attribute to CT
                    InternalCertificate icert = (InternalCertificate) xcert;
                    icert.setSSLTrust(InternalCertificate.TRUSTED_CA
                            | InternalCertificate.TRUSTED_CLIENT_CA
                            | InternalCertificate.VALID_CA);
                } else if (isAuditSigningCert(name)) {
                    InternalCertificate icert = (InternalCertificate) xcert;
                    icert.setObjectSigningTrust(InternalCertificate.USER
                            | InternalCertificate.VALID_PEER | InternalCertificate.TRUSTED_PEER);
                }
            } else {
                cm.importCACertPackage(cert);
            }
        }
    }

    private static boolean importRequired(ArrayList<String> masterList, String nickname) {
        if (masterList.contains(nickname))
            return true;
        try {
            X500Name xname = new X500Name(nickname);
            for (String key: masterList) {
                try {
                    X500Name xkey = new X500Name(key);
                    if (xkey.equals(xname)) return true;
                } catch (IOException e) {
                    // xkey not an X500Name
                }
            }

        } catch (IOException e) {
            // nickname is not a x500Name
            return false;
        }
        return false;
    }

    public static X509Certificate getX509CertFromToken(byte[] cert)
            throws IOException, CertificateException, NotInitializedException {

        X509CertImpl impl = new X509CertImpl(cert);
        String issuer_impl = impl.getIssuerDN().toString();
        BigInteger serial_impl = impl.getSerialNumber();
        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate[] permcerts = cm.getPermCerts();
        for (int i = 0; i < permcerts.length; i++) {
            String issuer_p = permcerts[i].getSubjectDN().toString();
            BigInteger serial_p = permcerts[i].getSerialNumber();
            if (issuer_p.equals(issuer_impl) && serial_p.compareTo(serial_impl) == 0) {
                return permcerts[i];
            }
        }
        return null;
    }

    public static org.mozilla.jss.crypto.PrivateKey.Type getPrivateKeyType(PublicKey pubkey) {
        CMS.debug("Key Algorithm '" + pubkey.getAlgorithm() + "'");
        if (pubkey.getAlgorithm().equals("EC")) {
            return org.mozilla.jss.crypto.PrivateKey.Type.EC;
        }
        return org.mozilla.jss.crypto.PrivateKey.Type.RSA;
    }

    public static boolean isCASigningCert(String name) {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String nickname = cs.getString("preop.master.signing.nickname");
            if (nickname.equals(name)) return true;
        } catch(Exception e) {
            // nickname may not exist if this is not cloning a CA
        };

        return false;
    }

    public static boolean isAuditSigningCert(String name) throws EPropertyNotFound, EBaseException {
        IConfigStore cs = CMS.getConfigStore();
        String nickname = cs.getString("preop.master.audit_signing.nickname");
        if (nickname.equals(name)) return true;
        return false;
    }

    public static void deleteExistingCerts() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String list = cs.getString("preop.cert.list", "");
            StringTokenizer st = new StringTokenizer(list, ",");
            while (st.hasMoreTokens()) {
                String s = st.nextToken();
                if (s.equals("sslserver"))
                    continue;
                String name = "preop.master." + s + ".nickname";
                String nickname = cs.getString(name, "");
                CryptoManager cm = CryptoManager.getInstance();
                X509Certificate xcert = null;
                try {
                    xcert = cm.findCertByNickname(nickname);
                } catch (Exception ee) {
                    CMS.debug("deleteExistingCerts: Exception=" + ee.toString());
                }
                CryptoToken ct = cm.getInternalKeyStorageToken();
                CryptoStore store = ct.getCryptoStore();
                try {
                    store.deleteCert(xcert);
                } catch (Exception ee) {
                    CMS.debug("deleteExistingCerts: Exception=" + ee.toString());
                }
            }
        } catch (Exception e) {
            CMS.debug("deleteExistingCerts: Exception=" + e.toString());
        }
    }

    public static ArrayList<String> getMasterCertKeyList() throws EBaseException {
        ArrayList<String> list = new ArrayList<String>();
        IConfigStore cs = CMS.getConfigStore();
        String certList = cs.getString("preop.cert.list", "");
        StringTokenizer st = new StringTokenizer(certList, ",");
        while (st.hasMoreTokens()) {
            String s = st.nextToken();
            if (s.equals("sslserver"))
                    continue;
            String name = "preop.master." + s + ".nickname";
            String nickname = cs.getString(name);
            list.add(nickname);

            name = "preop.cert." + s + ".dn";
            String dn = cs.getString(name);
            list.add(dn);
        }
        return list;
    }

    public static byte[] getX509Cert(String nickname, Vector<Vector<Object>> cert_collection)
            throws CertificateException {
        for (int i = 0; i < cert_collection.size(); i++) {
            Vector<Object> v = cert_collection.elementAt(i);
            byte[] b = (byte[]) v.elementAt(0);
            X509CertImpl impl = null;
            impl = new X509CertImpl(b);
            Principal subjectdn = impl.getSubjectDN();
            if (LDAPDN.equals(subjectdn.toString(), nickname)) return b;
        }
        return null;
    }

    public static void releaseConnection(LDAPConnection conn) {
        try {
            if (conn != null) conn.disconnect();
        } catch (LDAPException e) {
            e.printStackTrace();
            CMS.debug("releaseConnection: " + e);
        }
    }

    public static void populateDB() throws IOException, EBaseException {

        IConfigStore cs = CMS.getConfigStore();
        String baseDN = cs.getString("internaldb.basedn");
        String database = cs.getString("internaldb.database", "");
        String remove = cs.getString("preop.database.removeData", "false");

        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = CMS.getLdapBoundConnFactory();
        dbFactory.init(dbCfg);
        LDAPConnection conn = dbFactory.getConn();

        try {
            // check if base entry already exists
            LDAPEntry baseEntry = null;
            try {
                CMS.debug("populateDB: Checking subtree " + baseDN + ".");
                baseEntry = conn.read(baseDN);
                CMS.debug("populateDB: Subtree " + baseDN + " already exists.");

                if (remove.equals("false")) {
                    throw new EBaseException("The base DN (" + baseDN + ") has already been used. " +
                            "Please confirm to remove and reuse this base DN.");
                }

            } catch (LDAPException e) {
                if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                    CMS.debug("populateDB: Subtree " + baseDN + " does not exist.");
                } else {
                    CMS.debug("populateDB: " + e);
                    throw new EBaseException("Failed to determine if base DN exists: " + e);
                }
            }

            // check if mapping entry already exists
            String mappingDN = "cn=\"" + baseDN + "\",cn=mapping tree, cn=config";
            LDAPEntry mappingEntry = null;
            try {
                CMS.debug("populateDB: Checking subtree " + baseDN + " mapping.");
                mappingEntry = conn.read(mappingDN);
                CMS.debug("populateDB: Mapping for subtree " + baseDN + " already exists.");

                if (remove.equals("false")) {
                    throw new EBaseException("The base DN (" + baseDN + ") has already been used. " +
                            "Please confirm to remove and reuse this base DN.");
                }

            } catch (LDAPException e) {
                if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                    CMS.debug("populateDB: Mapping for subtree " + baseDN + " does not exist.");
                } else {
                    CMS.debug("populateDB: " + e);
                    throw new EBaseException("Failed to determine if mapping entry exists: " + e);
                }
            }

            // check if the database already exists
            String databaseDN = "cn=" + LDAPUtil.escapeRDNValue(database) + ",cn=ldbm database, cn=plugins, cn=config";
            LDAPEntry databaseEntry = null;
            try {
                CMS.debug("populateDB: Checking database " + database + ".");
                databaseEntry = conn.read(databaseDN);
                CMS.debug("populateDB: Database " + database + " already exists.");

                if (remove.equals("false")) {
                    throw new EBaseException("The database (" + database + ") already exists. " +
                            "Please confirm to remove and reuse this database.");
                }

            } catch (LDAPException e) {
                if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                    CMS.debug("populateDB: Database " + database + " does not exist.");
                } else {
                    CMS.debug("populateDB: " + e);
                    throw new EBaseException("Failed to determine if database exists: " + e);
                }
            }

            // check if database is used by another subtree
            try {
                CMS.debug("populateDB: Checking other subtrees using database " + database + ".");
                LDAPSearchResults res = conn.search(
                        "cn=mapping tree, cn=config", LDAPConnection.SCOPE_ONE,
                        "nsslapd-backend=" + LDAPUtil.escapeFilter(database),
                        null, false, (LDAPSearchConstraints)null);

                while (res.hasMoreElements()) {
                    LDAPEntry entry = res.next();

                    LDAPAttribute cn = entry.getAttribute("cn");
                    String dn = cn.getStringValueArray()[0];
                    if (LDAPDN.equals(baseDN, dn)) continue;

                    CMS.debug("populateDB: Database " + database + " is used by " + dn + ".");
                    throw new EBaseException("The database (" + database + ") is used by another base DN. " +
                            "Please use a different database name.");
                }

                CMS.debug("populateDB: Database " + database + " is not used by another subtree.");

            } catch (LDAPException e) {
                CMS.debug("populateDB: " + e);
                throw new EBaseException("Failed to check database mapping: " + e);
            }

            // delete mapping entry
            if (mappingEntry != null) {
                CMS.debug("populateDB: Deleting mapping " + mappingDN);
                deleteSubtree(conn, mappingDN);
            }

            // delete the database including the subtree data
            if (databaseEntry != null) {
                CMS.debug("populateDB: Deleting database " + database);
                deleteSubtree(conn, databaseDN);
            }

            // delete subtree data in case it's stored by another database
            if (baseEntry != null) {
                CMS.debug("populateDB: Deleting subtree " + baseDN);
                deleteSubtree(conn, baseDN);
            }

            // create database
            try {
                LDAPAttributeSet attrs = new LDAPAttributeSet();
                String oc[] = { "top", "extensibleObject", "nsBackendInstance" };
                attrs.add(new LDAPAttribute("objectClass", oc));
                attrs.add(new LDAPAttribute("cn", database));
                attrs.add(new LDAPAttribute("nsslapd-suffix", baseDN));
                LDAPEntry entry = new LDAPEntry(databaseDN, attrs);
                conn.add(entry);
            } catch (LDAPException e) {
                CMS.debug("populateDB: Unable to add " + databaseDN + ": " + e);
                throw new EBaseException("Failed to create the database: " + e, e);
            }

            // define subtree
            try {
                LDAPAttributeSet attrs = new LDAPAttributeSet();
                String oc2[] = { "top", "extensibleObject", "nsMappingTree" };
                attrs.add(new LDAPAttribute("objectClass", oc2));
                attrs.add(new LDAPAttribute("cn", baseDN));
                attrs.add(new LDAPAttribute("nsslapd-backend", database));
                attrs.add(new LDAPAttribute("nsslapd-state", "Backend"));
                LDAPEntry entry = new LDAPEntry(mappingDN, attrs);
                conn.add(entry);
            } catch (LDAPException e) {
                CMS.debug("populateDB: Unable to add " + mappingDN + ": " + e);
                throw new EBaseException("Failed to create subtree: " + e, e);
            }

            // create root entry
            try {
                CMS.debug("Creating base DN: " + baseDN);
                String dns3[] = LDAPDN.explodeDN(baseDN, false);
                StringTokenizer st = new StringTokenizer(dns3[0], "=");
                String n = st.nextToken();
                String v = st.nextToken();
                LDAPAttributeSet attrs = new LDAPAttributeSet();
                String oc3[] = { "top", "domain" };
                if (n.equals("o")) {
                    oc3[1] = "organization";
                } else if (n.equals("ou")) {
                    oc3[1] = "organizationalUnit";
                }
                attrs.add(new LDAPAttribute("objectClass", oc3));
                attrs.add(new LDAPAttribute(n, v));

                LDAPEntry entry = new LDAPEntry(baseDN, attrs);
                conn.add(entry);
            } catch (LDAPException e) {
                CMS.debug("populateDB: Unable to add " + baseDN + ": " + e);
                throw new EBaseException("Failed to create root entry: " + e, e);
            }

            try {
                String select = cs.getString("preop.subsystem.select", "");
                if (select.equals("clone")) {
                    // in most cases, we want to replicate the schema and therefore
                    // NOT add it here.  We provide this option though in case the
                    // clone already has schema and we want to replicate back to the
                    // master.
                    boolean replicateSchema = cs.getBoolean("preop.internaldb.replicateSchema", true);
                    if (! replicateSchema) {
                        importLDIFS("preop.internaldb.schema.ldif", conn);
                    }
                    importLDIFS("preop.internaldb.ldif", conn);

                    // add the index before replication, add VLV indexes afterwards
                    importLDIFS("preop.internaldb.index_ldif", conn);
                } else {
                    // data will be replicated from the master to the clone
                    // so clone does not need the data
                    importLDIFS("preop.internaldb.schema.ldif", conn);
                    importLDIFS("preop.internaldb.ldif", conn);
                    importLDIFS("preop.internaldb.data_ldif", conn);
                    importLDIFS("preop.internaldb.index_ldif", conn);
                }
            } catch (Exception e) {
                CMS.debug("Failed to import ldif files: " + e);
                throw new EBaseException("Failed to import ldif files: " + e, e);
            }

        } finally {
            releaseConnection(conn);
        }
    }

    public static void importLDIFS(String param, LDAPConnection conn) throws IOException, EPropertyNotFound,
            EBaseException {
        IConfigStore cs = CMS.getConfigStore();

        CMS.debug("importLDIFS: param=" + param);
        String v = cs.getString(param);

        String baseDN = cs.getString("internaldb.basedn");
        String database = cs.getString("internaldb.database");
        String instancePath = cs.getString("instanceRoot");
        String instanceId = cs.getString("instanceId");
        String cstype = cs.getString("cs.type");

        String dbuser = "uid=" + DBUSER + ",ou= people," + baseDN;

        String configDir = instancePath + File.separator + cstype.toLowerCase() + File.separator + "conf";

        StringTokenizer tokenizer = new StringTokenizer(v, ",");
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken().trim();
            int index = token.lastIndexOf("/");
            String name = token;

            if (index != -1) {
                name = token.substring(index + 1);
            }

            CMS.debug("importLDIFS(): ldif file = " + token);
            String filename = configDir + File.separator + name;

            CMS.debug("importLDIFS(): ldif file copy to " + filename);
            PrintStream ps = null;
            BufferedReader in = null;

            in = new BufferedReader(new FileReader(token));
            ps = new PrintStream(new FileOutputStream(filename, false));
            while (in.ready()) {
                String s = in.readLine();
                int n = s.indexOf("{");

                if (n == -1) {
                    ps.println(s);
                } else {
                    boolean endOfline = false;

                    while (n != -1) {
                        ps.print(s.substring(0, n));
                        int n1 = s.indexOf("}");
                        String tok = s.substring(n + 1, n1);

                        if (tok.equals("instanceId")) {
                            ps.print(instanceId);
                        } else if (tok.equals("rootSuffix")) {
                            ps.print(baseDN);
                        } else if (tok.equals("database")) {
                            ps.print(database);
                        } else if (tok.equals("dbuser")) {
                            ps.print(dbuser);
                        }
                        if ((s.length() + 1) == n1) {
                            endOfline = true;
                            break;
                        }
                        s = s.substring(n1 + 1);
                        n = s.indexOf("{");
                    }

                    if (!endOfline) {
                        ps.println(s);
                    }
                }
            }
            in.close();
            ps.close();

            ArrayList<String> errors = new ArrayList<String>();
            LDAPUtil.importLDIF(conn, filename, errors);
            if (!errors.isEmpty()) {
                CMS.debug("importLDIFS(): LDAP Errors in importing " + filename);
                for (String error : errors) {
                    CMS.debug(error);
                }
            }
        }
    }

    public static void deleteSubtree(LDAPConnection conn, String dn) throws EBaseException {
        String[] excludedDNs = {};
        try {
            LDAPSearchResults res = conn.search(
                    dn, LDAPConnection.SCOPE_BASE, "objectclass=*",
                    null, true, (LDAPSearchConstraints)null);
            deleteEntries(res, conn, excludedDNs);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                CMS.debug("deleteSubtree: Subtree " + dn + " does not exist.");
            } else {
                CMS.debug("deleteSubtree: Unable to delete subtree " + dn + ": " + e);
                throw new EBaseException("Unable to delete subtree " + dn, e);
            }
        }
    }

    public static void deleteEntries(LDAPSearchResults res, LDAPConnection conn, String[] excludedDNs) throws LDAPException {
        while (res.hasMoreElements()) {
            LDAPEntry entry = res.next();
            String dn = entry.getDN();

            LDAPSearchResults res1 = conn.search(
                    dn, 1, "objectclass=*",
                    null, true, (LDAPSearchConstraints)null);
            deleteEntries(res1, conn, excludedDNs);
            deleteEntry(conn, dn, excludedDNs);
        }
    }

    public static void deleteEntry(LDAPConnection conn, String dn, String[] excludedDNs) throws LDAPException {
        for (String excludedDN : excludedDNs) {
            if (!LDAPDN.equals(dn, excludedDN)) continue;

            CMS.debug("deleteEntry: entry with this dn " + dn + " is not deleted.");
            return;
        }

        conn.delete(dn);
    }

    public static String getInstanceDir(LDAPConnection conn) throws LDAPException {
        String instancedir = "";

        String filter = "(objectclass=*)";
        String[] attrs = { "nsslapd-directory" };
        LDAPSearchResults results = conn.search("cn=config,cn=ldbm database,cn=plugins,cn=config",
                LDAPv3.SCOPE_SUB, filter, attrs, false);

        while (results.hasMoreElements()) {
            LDAPEntry entry = results.next();
            String dn = entry.getDN();
            CMS.debug("getInstanceDir: DN for storing nsslapd-directory: " + dn);
            LDAPAttributeSet entryAttrs = entry.getAttributeSet();

            @SuppressWarnings("unchecked")
            Enumeration<LDAPAttribute> attrsInSet = entryAttrs.getAttributes();
            while (attrsInSet.hasMoreElements()) {
                LDAPAttribute nextAttr = attrsInSet.nextElement();
                String attrName = nextAttr.getName();
                CMS.debug("getInstanceDir: attribute name: " + attrName);
                @SuppressWarnings("unchecked")
                Enumeration<String> valsInAttr = nextAttr.getStringValues();
                while (valsInAttr.hasMoreElements()) {
                    String nextValue = valsInAttr.nextElement();
                    if (attrName.equalsIgnoreCase("nsslapd-directory")) {
                        CMS.debug("getInstanceDir: instanceDir=" + nextValue);
                        return nextValue.substring(0, nextValue.lastIndexOf("/db"));
                    }
                }
            }
        }

        return instancedir;
    }

    public static boolean deleteDir(File dir) {
        if (dir.isDirectory()) {
            String[] children = dir.list();
            for (int i = 0; i < children.length; i++) {
                boolean success = deleteDir(new File(dir, children[i]));
                if (!success) {
                    return false;
                }
            }
        }
        return dir.delete();
    }

    public static void populateDBManager() throws Exception {
        CMS.debug("populateDBManager(): start");
        IConfigStore cs = CMS.getConfigStore();

        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = CMS.getLdapBoundConnFactory();
        dbFactory.init(dbCfg);
        LDAPConnection conn = dbFactory.getConn();

        try {
            importLDIFS("preop.internaldb.manager_ldif", conn);
        } catch (Exception e) {
            CMS.debug("populateDBManager(): Exception thrown: " + e);
            throw e;
        } finally {
            releaseConnection(conn);
        }
    }

    public static void populateVLVIndexes() throws Exception {
        CMS.debug("populateVLVIndexes(): start");
        IConfigStore cs = CMS.getConfigStore();

        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = CMS.getLdapBoundConnFactory();
        dbFactory.init(dbCfg);
        LDAPConnection conn = dbFactory.getConn();

        try {
            importLDIFS("preop.internaldb.post_ldif", conn);

            /* For vlvtask, we need to check if the task has
               been completed or not.  Presence of nsTaskExitCode means task is complete
             */
            String wait_dn = cs.getString("preop.internaldb.wait_dn", "");
            if (!wait_dn.equals("")) {
                LDAPEntry task = null;
                boolean taskComplete = false;
                CMS.debug("Checking wait_dn " + wait_dn);
                do {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        // restore the interrupted status
                        Thread.currentThread().interrupt();
                    }

                    try {
                        task = conn.read(wait_dn, (String[]) null);
                        if (task != null) {
                            LDAPAttribute attr = task.getAttribute("nsTaskExitCode");
                            if (attr != null) {
                                taskComplete = true;
                                String val = (String) attr.getStringValues().nextElement();
                                if (val.compareTo("0") != 0) {
                                    CMS.debug("Error in populating local VLV indexes: nsTaskExitCode=" + val);
                                }
                            }
                        }
                    } catch (Exception le) {
                        CMS.debug("Still checking wait_dn '" + wait_dn + "' (" + le.toString() + ")");
                    }
                } while (!taskComplete);
            }
        } catch (Exception e) {
            CMS.debug("populateVLVIndexes(): Exception thrown: " + e);
            throw e;
        } finally {
            releaseConnection(conn);
        }
    }

    public static void setupReplication() throws EBaseException, IOException {
        IConfigStore cs = CMS.getConfigStore();

        String machinename = cs.getString("machineName", "");
        String instanceId = cs.getString("instanceId", "");
        String secure = cs.getString("internaldb.ldapconn.secureConn");
        String replicationSecurity = cs.getString("internaldb.ldapconn.replicationSecurity");
        int masterReplicationPort = cs.getInteger("internaldb.ldapconn.masterReplicationPort");
        int cloneReplicationPort = cs.getInteger("internaldb.ldapconn.cloneReplicationPort");

        //setup replication agreement
        String masterAgreementName = "masterAgreement1-" + machinename + "-" + instanceId;
        cs.putString("internaldb.replication.master", masterAgreementName);
        String cloneAgreementName = "cloneAgreement1-" + machinename + "-" + instanceId;
        cs.putString("internaldb.replication.consumer", cloneAgreementName);

        cs.commit(false);

        // get connection to master
        LDAPConnection masterConn = null;
        ILdapConnFactory masterFactory = null;
        try {
            IConfigStore masterCfg = cs.getSubStore("preop.internaldb.master");
            masterFactory = CMS.getLdapBoundConnFactory();
            masterFactory.init(masterCfg);
            masterConn = masterFactory.getConn();
        } catch (Exception e) {
            CMS.debug("setupEeplication: Failed to set up connection to master:" + e.toString());
            e.printStackTrace();
            releaseConnection(masterConn);
            throw new IOException("Failed to set up replication: No connection to master");
        }

        // get connection to replica
        LDAPConnection replicaConn = null;
        ILdapConnFactory replicaFactory = null;
        try {
            IConfigStore replicaCfg = cs.getSubStore("internaldb");
            replicaFactory = CMS.getLdapBoundConnFactory();
            replicaFactory.init(replicaCfg);
            replicaConn = replicaFactory.getConn();
        } catch (Exception e) {
            CMS.debug("SetupReplication: Failed to set up connection to replica:" + e.toString());
            e.printStackTrace();
            releaseConnection(masterConn);
            releaseConnection(replicaConn);
            throw new IOException("Failed to set up replication: No connection to replica");
        }

        try {
            String master_hostname = cs.getString("preop.internaldb.master.ldapconn.host", "");
            String master_replicationpwd = cs.getString("preop.internaldb.master.replication.password", "");
            String replica_hostname = cs.getString("internaldb.ldapconn.host", "");
            String replica_replicationpwd = cs.getString("preop.internaldb.replicationpwd", "");
            String basedn = cs.getString("internaldb.basedn");
            String suffix = cs.getString("internaldb.basedn", "");

            String replicadn = "cn=replica,cn=\"" + suffix + "\",cn=mapping tree,cn=config";
            CMS.debug("DatabasePanel setupReplication: replicadn=" + replicadn);

            String masterBindUser = "Replication Manager " + masterAgreementName;
            String cloneBindUser = "Replication Manager " + cloneAgreementName;

            createReplicationManager(masterConn, masterBindUser, master_replicationpwd);
            createReplicationManager(replicaConn, cloneBindUser, replica_replicationpwd);

            String dir1 = getInstanceDir(masterConn);
            createChangeLog(masterConn, dir1 + "/changelogs");

            String dir2 = getInstanceDir(replicaConn);
            createChangeLog(replicaConn, dir2 + "/changelogs");

            int replicaId = cs.getInteger("dbs.beginReplicaNumber", 1);

            replicaId = enableReplication(replicadn, masterConn, masterBindUser, basedn, replicaId);
            replicaId = enableReplication(replicadn, replicaConn, cloneBindUser, basedn, replicaId);
            cs.putString("dbs.beginReplicaNumber", Integer.toString(replicaId));

            CMS.debug("setupReplication: Finished enabling replication");

            createReplicationAgreement(replicadn, masterConn, masterAgreementName,
                    replica_hostname, cloneReplicationPort, replica_replicationpwd, basedn,
                    cloneBindUser, secure, replicationSecurity);

            createReplicationAgreement(replicadn, replicaConn, cloneAgreementName,
                    master_hostname, masterReplicationPort, master_replicationpwd, basedn,
                    masterBindUser, secure, replicationSecurity);

            // initialize consumer
            initializeConsumer(replicadn, masterConn, masterAgreementName);

            while (!replicationDone(replicadn, masterConn, masterAgreementName)) {
                CMS.debug("setupReplication: Waiting for replication to complete");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            String status = replicationStatus(replicadn, masterConn, masterAgreementName);
            if (!status.startsWith("0 ")) {
                CMS.debug("setupReplication: consumer initialization failed. " +status);
                throw new IOException("consumer initialization failed. " + status);
            }

            // remove master ldap password from password.conf (if present)
            String passwordFile = cs.getString("passwordFile");
            IConfigStore psStore = CMS.createFileConfigStore(passwordFile);
            psStore.remove("master_internaldb");
            psStore.commit(false);

        } catch (Exception e) {
            e.printStackTrace();
            CMS.debug("setupReplication: " + e.toString());
            throw new IOException("Failed to setup the replication for cloning.");
        } finally {
            releaseConnection(masterConn);
            releaseConnection(replicaConn);
        }
}

    public static void createReplicationManager(LDAPConnection conn, String bindUser, String pwd)
            throws LDAPException {
        LDAPAttributeSet attrs = null;
        LDAPEntry entry = null;

        // for older subsystems, the container ou=csusers, cn=config may not yet exist
        String dn = "ou=csusers, cn=config";
        try {
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "organizationalUnit"));
            attrs.add(new LDAPAttribute("ou", "csusers"));
            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                CMS.debug("createReplicationManager: containing ou already exists");
            } else {
                CMS.debug("createReplicationManager: Failed to create containing ou. Exception: "
                        + e.toString());
                throw e;
            }
        }

        dn = "cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config";
        try {
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "person"));
            attrs.add(new LDAPAttribute("userpassword", pwd));
            attrs.add(new LDAPAttribute("cn", bindUser));
            attrs.add(new LDAPAttribute("sn", "manager"));
            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                CMS.debug("createReplicationManager: Replication Manager has already used");
                try {
                    conn.delete(dn);
                    conn.add(entry);
                } catch (LDAPException ee) {
                    CMS.debug("createReplicationManager: " + ee.toString());
                }
                return;
            } else {
                CMS.debug("createReplicationManager: Failed to create replication manager. Exception: "
                        + e.toString());
                throw e;
            }
        }

        CMS.debug("createReplicationManager: Successfully created Replication Manager");
    }

    public static void createChangeLog(LDAPConnection conn, String dir)
            throws LDAPException {
        LDAPAttributeSet attrs = null;
        LDAPEntry entry = null;
        String dn = "cn=changelog5,cn=config";
        try {
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "extensibleObject"));
            attrs.add(new LDAPAttribute("cn", "changelog5"));
            attrs.add(new LDAPAttribute("nsslapd-changelogdir", dir));
            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                CMS.debug("createChangeLog: Changelog entry has already used");
                /* leave it, dont delete it because it will have operation error */
                return;
            } else {
                CMS.debug("createChangeLog: Failed to create changelog entry. Exception: " + e.toString());
                throw e;
            }
        }

        CMS.debug("createChangeLog: Successfully create change log entry");
    }

    public static int enableReplication(String replicadn, LDAPConnection conn, String bindUser, String basedn, int id)
            throws LDAPException {
        CMS.debug("enableReplication: replicadn: " + replicadn);
        LDAPAttributeSet attrs = null;
        LDAPEntry entry = null;
        try {
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "nsDS5Replica"));
            attrs.add(new LDAPAttribute("objectclass", "extensibleobject"));
            attrs.add(new LDAPAttribute("nsDS5ReplicaRoot", basedn));
            attrs.add(new LDAPAttribute("nsDS5ReplicaType", "3"));
            attrs.add(new LDAPAttribute("nsDS5ReplicaBindDN",
                    "cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config"));
            attrs.add(new LDAPAttribute("cn", "replica"));
            attrs.add(new LDAPAttribute("nsDS5ReplicaId", Integer.toString(id)));
            attrs.add(new LDAPAttribute("nsds5flags", "1"));
            entry = new LDAPEntry(replicadn, attrs);
            conn.add(entry);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                /* BZ 470918 -we cant just add the new dn.  We need to do a replace instead
                 * until the DS code is fixed */
                CMS.debug("enableReplication: " + replicadn + " has already been used");

                try {
                    entry = conn.read(replicadn);
                    LDAPAttribute attr = entry.getAttribute("nsDS5ReplicaBindDN");
                    attr.addValue("cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config");
                    LDAPModification mod = new LDAPModification(LDAPModification.REPLACE, attr);
                    conn.modify(replicadn, mod);
                } catch (LDAPException ee) {
                    CMS.debug("enableReplication: Failed to modify "
                            + replicadn + " entry. Exception: " + e.toString());
                }
                return id;
            } else {
                CMS.debug("enableReplication: Failed to create "
                        + replicadn + " entry. Exception: " + e.toString());
                return id;
            }
        }

        CMS.debug("enableReplication: Successfully create " + replicadn + " entry.");
        return id + 1;
    }

    public static void createReplicationAgreement(String replicadn, LDAPConnection conn, String name,
            String replicahost, int replicaport, String replicapwd, String basedn, String bindUser,
            String secure, String replicationSecurity) throws LDAPException {
        String dn = "cn=" + LDAPUtil.escapeRDNValue(name) + "," + replicadn;
        CMS.debug("createReplicationAgreement: dn: " + dn);
        LDAPEntry entry = null;
        LDAPAttributeSet attrs = null;
        try {
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass",
                    "nsds5replicationagreement"));
            attrs.add(new LDAPAttribute("cn", name));
            attrs.add(new LDAPAttribute("nsDS5ReplicaRoot", basedn));
            attrs.add(new LDAPAttribute("nsDS5ReplicaHost", replicahost));

            attrs.add(new LDAPAttribute("nsDS5ReplicaPort", "" + replicaport));
            attrs.add(new LDAPAttribute("nsDS5ReplicaBindDN",
                    "cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config"));
            attrs.add(new LDAPAttribute("nsDS5ReplicaBindMethod", "Simple"));
            attrs.add(new LDAPAttribute("nsds5replicacredentials", replicapwd));

            if (replicationSecurity.equals("SSL")) {
                attrs.add(new LDAPAttribute("nsDS5ReplicaTransportInfo", "SSL"));
            } else if (replicationSecurity.equals("TLS")) {
                attrs.add(new LDAPAttribute("nsDS5ReplicaTransportInfo", "TLS"));
            }

            CMS.debug("About to set description attr to " + name);
            attrs.add(new LDAPAttribute("description", name));

            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                CMS.debug("createReplicationAgreement: " + dn + " has already used");
                try {
                    conn.delete(dn);
                } catch (LDAPException ee) {
                    CMS.debug("createReplicationAgreement: " + ee.toString());
                    throw ee;
                }

                try {
                    conn.add(entry);
                } catch (LDAPException ee) {
                    CMS.debug("createReplicationAgreement: " + ee.toString());
                    throw ee;
                }
            } else {
                CMS.debug("createReplicationAgreement: Failed to create "
                        + dn + " entry. Exception: " + e.toString());
                throw e;
            }
        }

        CMS.debug("createReplicationAgreement: Successfully create replication agreement " + name);
    }

    public static void initializeConsumer(String replicadn, LDAPConnection conn, String name) throws LDAPException {
        String dn = "cn=" + LDAPUtil.escapeRDNValue(name) + "," + replicadn;
        CMS.debug("initializeConsumer: initializeConsumer dn: " + dn);
        CMS.debug("initializeConsumer: initializeConsumer host: " + conn.getHost() + " port: " + conn.getPort());

        LDAPAttribute attr = new LDAPAttribute("nsds5beginreplicarefresh", "start");
        LDAPModification mod = new LDAPModification(LDAPModification.REPLACE, attr);
        conn.modify(dn, mod);

        CMS.debug("initializeConsumer: Successfully initialized consumer");
    }

    public static boolean replicationDone(String replicadn, LDAPConnection conn, String name)
            throws LDAPException, IOException {
        String dn = "cn=" + LDAPUtil.escapeRDNValue(name) + "," + replicadn;
        String filter = "(objectclass=*)";
        String[] attrs = { "nsds5beginreplicarefresh" };

        CMS.debug("replicationDone: dn: " + dn);

        LDAPSearchResults results = conn.search(dn, LDAPConnection.SCOPE_BASE, filter, attrs, true);
        int count = results.getCount();
        if (count < 1) {
            throw new IOException("Replication entry not found");
        }

        LDAPEntry entry = results.next();
        LDAPAttribute refresh = entry.getAttribute("nsds5beginreplicarefresh");
        if (refresh == null) {
            return true;
        }
        return false;
    }

    public static String replicationStatus(String replicadn, LDAPConnection conn, String name)
            throws IOException, LDAPException {
        String dn = "cn=" + LDAPUtil.escapeRDNValue(name) + "," + replicadn;
        String filter = "(objectclass=*)";
        String[] attrs = { "nsds5replicalastinitstatus" };

        CMS.debug("replicationStatus: dn: " + dn);

        LDAPSearchResults results = conn.search(dn, LDAPConnection.SCOPE_BASE, filter, attrs, false);

        int count = results.getCount();
        if (count < 1) {
            throw new IOException("Replication entry not found");
        }

        LDAPEntry entry = results.next();
        LDAPAttribute attr = entry.getAttribute("nsds5replicalastinitstatus");
        if (attr != null) {
            @SuppressWarnings("unchecked")
            Enumeration<String> valsInAttr = attr.getStringValues();
            if (valsInAttr.hasMoreElements()) {
                return valsInAttr.nextElement();
            } else {
                throw new IOException("No value returned for nsds5replicalastinitstatus");
            }
        } else {
            throw new IOException("nsDS5ReplicaLastInitStatus is null.");
        }
    }

    public static void reInitSubsystem(String csType) throws EBaseException {
        CMS.reinit(IDBSubsystem.SUB_ID);
        if (csType.equals("CA"))
            CMS.reinit(ICertificateAuthority.ID);
        CMS.reinit(IAuthSubsystem.ID);
        CMS.reinit(IAuthzSubsystem.ID);
        CMS.reinit(IUGSubsystem.ID);
    }

    public static void setExternalCACert(String certStr, String subsystem, IConfigStore config, Cert certObj) throws Exception {
        certStr = CryptoUtil.stripCertBrackets(certStr.trim());
        certStr = CryptoUtil.normalizeCertStr(certStr);
        config.putString(subsystem + ".external_ca.cert", certStr);
        certObj.setSubsystem(subsystem);
        certObj.setType(config.getString("preop.ca.type", "otherca"));
        certObj.setCert(certStr);
    }

    public static void setExternalCACertChain(String certChainStr, String subsystem, IConfigStore config, Cert certObj) {
        certChainStr = CryptoUtil.normalizeCertAndReq(certChainStr);
        config.putString(subsystem + ".external_ca_chain.cert", certChainStr);
        certObj.setCertChain(certChainStr);
    }

    public static void createECCKeyPair(String token, String curveName, IConfigStore config, String ct)
            throws NoSuchAlgorithmException, NoSuchTokenException, TokenException,
            CryptoManager.NotInitializedException, EPropertyNotFound, EBaseException {
        CMS.debug("createECCKeyPair: Generating ECC key pair with curvename=" + curveName + ", token=" + token);
        KeyPair pair = null;
        /*
         * default ssl server cert to ECDHE unless stated otherwise
         * note: IE only supports "ECDHE", but "ECDH" is more efficient
         *
         * for "ECDHE", server.xml should have the following for ciphers:
         * +TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
         * -TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
         *
         * for "ECDH", server.xml should have the following for ciphers:
         * -TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
         * +TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
         */
        String sslType = "ECDHE";
        try {
            sslType = config.getString(PCERT_PREFIX + ct + "ec.type", "ECDHE");
        } catch (Exception e) {}

        // ECDHE needs "SIGN" but no "DERIVE"
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage usages_mask[] = {
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DERIVE
        };

        // ECDH needs "DERIVE" but no any kind of "SIGN"
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage ECDH_usages_mask[] = {
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN,
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN_RECOVER,
        };

        do {
            if (ct.equals("sslserver") && sslType.equalsIgnoreCase("ECDH")) {
                CMS.debug("SizePanel: createECCKeypair: sslserver cert for ECDH. Make sure server.xml is set " +
                          "properly with -TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,+TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
                pair = CryptoUtil.generateECCKeyPair(token, curveName, null, ECDH_usages_mask);
            } else {
                if (ct.equals("sslserver")) {
                    CMS.debug("SizePanel: createECCKeypair: sslserver cert for ECDHE. Make sure server.xml is set " +
                              "properly with +TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,-TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
                }
                pair = CryptoUtil.generateECCKeyPair(token, curveName, null, usages_mask);
            }

            // XXX - store curve , w
            byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();
            String kid = CryptoUtil.byte2string(id);
            config.putString(PCERT_PREFIX + ct + ".privkey.id", kid);

            // try to locate the private key
            org.mozilla.jss.crypto.PrivateKey privk = CryptoUtil.findPrivateKeyFromID(CryptoUtil.string2byte(kid));
            if (privk == null) {
                CMS.debug("Found bad ECC key id " + kid);
                pair = null;
            }
        } while (pair == null);

        CMS.debug("Public key class " + pair.getPublic().getClass().getName());
        byte encoded[] = pair.getPublic().getEncoded();
        config.putString(PCERT_PREFIX + ct + ".pubkey.encoded", CryptoUtil.byte2string(encoded));

        String keyAlgo = config.getString(PCERT_PREFIX + ct + ".signingalgorithm");
        setSigningAlgorithm(ct, keyAlgo, config);
    }

    public static void createRSAKeyPair(String token, int keysize, IConfigStore config, String ct)
            throws NoSuchAlgorithmException, NoSuchTokenException, TokenException,
            CryptoManager.NotInitializedException, EPropertyNotFound, EBaseException {
        /* generate key pair */
        KeyPair pair = null;
        do {
            pair = CryptoUtil.generateRSAKeyPair(token, keysize);
            byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();
            String kid = CryptoUtil.byte2string(id);
            config.putString(PCERT_PREFIX + ct + ".privkey.id", kid);
            // try to locate the private key
            org.mozilla.jss.crypto.PrivateKey privk =
                    CryptoUtil.findPrivateKeyFromID(CryptoUtil.string2byte(kid));
            if (privk == null) {
                CMS.debug("Found bad RSA key id " + kid);
                pair = null;
            }
        } while (pair == null);

        byte modulus[] = ((RSAPublicKey) pair.getPublic()).getModulus().toByteArray();
        byte exponent[] = ((RSAPublicKey) pair.getPublic()).getPublicExponent().toByteArray();

        config.putString(PCERT_PREFIX + ct + ".pubkey.modulus",
                CryptoUtil.byte2string(modulus));
        config.putString(PCERT_PREFIX + ct + ".pubkey.exponent",
                CryptoUtil.byte2string(exponent));

        String keyAlgo = config.getString(PCERT_PREFIX + ct + ".signingalgorithm");
        setSigningAlgorithm(ct, keyAlgo, config);
    }

    public static void setSigningAlgorithm(String ct, String keyAlgo, IConfigStore config) throws EPropertyNotFound, EBaseException {
        String systemType = config.getString("cs.type");
        if (systemType.equalsIgnoreCase("CA")) {
            if (ct.equals("signing")) {
                config.putString("ca.signing.defaultSigningAlgorithm", keyAlgo);
                config.putString("ca.crl.MasterCRL.signingAlgorithm", keyAlgo);
            } else if (ct.equals("ocsp_signing")) {
                config.putString("ca.ocsp_signing.defaultSigningAlgorithm", keyAlgo);
            }
        } else if (systemType.equalsIgnoreCase("OCSP")) {
            if (ct.equals("signing")) {
                config.putString("ocsp.signing.defaultSigningAlgorithm", keyAlgo);
            }
        } else if (systemType.equalsIgnoreCase("KRA") || systemType.equalsIgnoreCase("DRM")) {
            if (ct.equals("transport")) {
                config.putString("kra.transportUnit.signingAlgorithm", keyAlgo);
            }
        }
    }

    public static int getSubsystemCount(String hostname, int https_admin_port,
            boolean https, String type) throws IOException, SAXException, ParserConfigurationException {
        CMS.debug("getSubsystemCount start");
        String c = getDomainXML(hostname, https_admin_port, true);
        if (c != null) {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject obj = new XMLObject(bis);
            String containerName = type + "List";
            Node n = obj.getContainer(containerName);
            NodeList nlist = n.getChildNodes();
            String countS = "";
            for (int i = 0; i < nlist.getLength(); i++) {
                Element nn = (Element) nlist.item(i);
                String tagname = nn.getTagName();
                if (tagname.equals("SubsystemCount")) {
                    NodeList nlist1 = nn.getChildNodes();
                    Node nn1 = nlist1.item(0);
                    countS = nn1.getNodeValue();
                    break;
                }
            }
            CMS.debug("getSubsystemCount: SubsystemCount=" + countS);
            int num = 0;

            if (countS != null && !countS.equals("")) {
                try {
                    num = Integer.parseInt(countS);
                } catch (Exception ee) {
                }
            }

            return num;
        }
        return -1;
    }

    public static void configCert(HttpServletRequest request, HttpServletResponse response,
            Context context, Cert certObj, WizardPanelBase panel) throws IOException {

        IConfigStore config = CMS.getConfigStore();
        String caType = certObj.getType();
        CMS.debug("configCert: caType is " + caType);
        X509CertImpl cert = null;
        String certTag = certObj.getCertTag();

        try {
            updateConfig(config, certTag);
            if (caType.equals("remote")) {
                String v = config.getString("preop.ca.type", "");

                CMS.debug("configCert: remote CA");
                String pkcs10 = CertUtil.getPKCS10(config, PCERT_PREFIX, certObj, context);
                certObj.setRequest(pkcs10);
                String subsystem = config.getString(PCERT_PREFIX + certTag + ".subsystem");
                config.putString(subsystem + "." + certTag + ".certreq", pkcs10);
                String profileId = config.getString(PCERT_PREFIX + certTag + ".profile");
                String session_id = CMS.getConfigSDSessionId();
                String sd_hostname = "";
                int sd_ee_port = -1;
                try {
                    sd_hostname = config.getString("securitydomain.host", "");
                    sd_ee_port = config.getInteger("securitydomain.httpseeport", -1);
                } catch (Exception ee) {
                    CMS.debug("configCert(): exception caught:" + ee.toString());
                }
                String sysType = config.getString("cs.type", "");
                String machineName = config.getString("machineName", "");
                String securePort = config.getString("service.securePort", "");
                if (certTag.equals("subsystem")) {
                    boolean standalone = config.getBoolean(sysType.toLowerCase() + ".standalone", false);
                    if (standalone) {
                        // Treat standalone subsystem the same as "otherca"
                        config.putString(subsystem + "." + certTag + ".cert",
                                         "...paste certificate here...");
                    } else {
                        String content =
                                "requestor_name="
                                        + sysType + "-" + machineName + "-" + securePort + "&profileId=" + profileId
                                        + "&cert_request_type=pkcs10&cert_request=" + URLEncoder.encode(pkcs10, "UTF-8")
                                        + "&xmlOutput=true&sessionID=" + session_id;
                        cert = CertUtil.createRemoteCert(sd_hostname, sd_ee_port,
                                content, response, panel);
                        if (cert == null) {
                            throw new IOException("Error: remote certificate is null");
                        }
                    }
                } else if (v.equals("sdca")) {
                    String ca_hostname = "";
                    int ca_port = -1;
                    try {
                        ca_hostname = config.getString("preop.ca.hostname", "");
                        ca_port = config.getInteger("preop.ca.httpsport", -1);
                    } catch (Exception ee) {
                    }

                    String content =
                            "requestor_name="
                                    + sysType + "-" + machineName + "-" + securePort + "&profileId=" + profileId
                                    + "&cert_request_type=pkcs10&cert_request=" + URLEncoder.encode(pkcs10, "UTF-8")
                                    + "&xmlOutput=true&sessionID=" + session_id;
                    cert = CertUtil.createRemoteCert(ca_hostname, ca_port,
                            content, response, panel);
                    if (cert == null) {
                        throw new IOException("Error: remote certificate is null");
                    }
                } else if (v.equals("otherca")) {
                    config.putString(subsystem + "." + certTag + ".cert",
                            "...paste certificate here...");
                } else {
                    CMS.debug("NamePanel: no preop.ca.type is provided");
                }
            } else { // not remote CA, ie, self-signed or local
                ISubsystem ca = CMS.getSubsystem(ICertificateAuthority.ID);

                if (ca == null) {
                    String s = PCERT_PREFIX + certTag + ".type";

                    CMS.debug(
                            "The value for " + s
                                    + " should be remote, nothing else.");
                    throw new IOException(
                            "The value for " + s + " should be remote");
                }

                String pubKeyType = config.getString(
                        PCERT_PREFIX + certTag + ".keytype");
                if (pubKeyType.equals("rsa")) {

                    String pubKeyModulus = config.getString(
                            PCERT_PREFIX + certTag + ".pubkey.modulus");
                    String pubKeyPublicExponent = config.getString(
                            PCERT_PREFIX + certTag + ".pubkey.exponent");
                    String subsystem = config.getString(
                            PCERT_PREFIX + certTag + ".subsystem");

                    if (certTag.equals("signing")) {
                        X509Key x509key = CryptoUtil.getPublicX509Key(
                                CryptoUtil.string2byte(pubKeyModulus),
                                CryptoUtil.string2byte(pubKeyPublicExponent));

                        cert = CertUtil.createLocalCert(config, x509key,
                                PCERT_PREFIX, certTag, caType, context);
                    } else {
                        String cacert = config.getString("ca.signing.cert", "");

                        if (cacert.equals("") || cacert.startsWith("...")) {
                            certObj.setCert(
                                    "...certificate be generated internally...");
                            config.putString(subsystem + "." + certTag + ".cert",
                                    "...certificate be generated internally...");
                        } else {
                            X509Key x509key = CryptoUtil.getPublicX509Key(
                                    CryptoUtil.string2byte(pubKeyModulus),
                                    CryptoUtil.string2byte(pubKeyPublicExponent));

                            cert = CertUtil.createLocalCert(config, x509key,
                                    PCERT_PREFIX, certTag, caType, context);
                        }
                    }
                } else if (pubKeyType.equals("ecc")) {
                    String pubKeyEncoded = config.getString(
                            PCERT_PREFIX + certTag + ".pubkey.encoded");
                    String subsystem = config.getString(
                            PCERT_PREFIX + certTag + ".subsystem");

                    if (certTag.equals("signing")) {

                        X509Key x509key = CryptoUtil.getPublicX509ECCKey(CryptoUtil.string2byte(pubKeyEncoded));
                        cert = CertUtil.createLocalCert(config, x509key,
                                PCERT_PREFIX, certTag, caType, context);
                    } else {
                        String cacert = config.getString("ca.signing.cert", "");

                        if (cacert.equals("") || cacert.startsWith("...")) {
                            certObj.setCert(
                                    "...certificate be generated internally...");
                            config.putString(subsystem + "." + certTag + ".cert",
                                    "...certificate be generated internally...");
                        } else {
                            X509Key x509key = CryptoUtil.getPublicX509ECCKey(
                                    CryptoUtil.string2byte(pubKeyEncoded));

                            cert = CertUtil.createLocalCert(config, x509key,
                                    PCERT_PREFIX, certTag, caType, context);
                        }
                    }
                } else {
                    // invalid key type
                    CMS.debug("Invalid key type " + pubKeyType);
                }
                if (cert != null) {
                    if (certTag.equals("subsystem"))
                        CertUtil.addUserCertificate(cert);
                }
            } // done self-signed or local

            if (cert != null) {
                byte[] certb = cert.getEncoded();
                String certs = CryptoUtil.base64Encode(certb);

                certObj.setCert(certs);
                String subsystem = config.getString(
                        PCERT_PREFIX + certTag + ".subsystem");
                config.putString(subsystem + "." + certTag + ".cert", certs);
            }
            config.commit(false);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            CMS.debug("configCert() exception caught:" + e.toString());
        }
    }

    public static void updateConfig(IConfigStore config, String certTag)
            throws EBaseException, IOException {
        String token = config.getString("preop.module.token");
        String subsystem = config.getString(PCERT_PREFIX + certTag + ".subsystem");
        String nickname = getNickname(config, certTag);

        CMS.debug("NamePanel: updateConfig() for certTag " + certTag);
        if (certTag.equals("signing") || certTag.equals("ocsp_signing")) {
            CMS.debug("NamePanel: setting signing nickname=" + nickname);
            config.putString(subsystem + "." + certTag + ".cacertnickname", nickname);
            config.putString(subsystem + "." + certTag + ".certnickname", nickname);
        }

        // if KRA, hardware token needs param "kra.storageUnit.hardware" in CS.cfg
        String cstype = config.getString("cs.type", null);
        cstype = cstype.toLowerCase();
        if (cstype.equals("kra")) {
            if (!token.equals("Internal Key Storage Token")) {
                if (certTag.equals("storage")) {
                    config.putString(subsystem + ".storageUnit.hardware", token);
                    config.putString(subsystem + ".storageUnit.nickName", token + ":" + nickname);
                } else if (certTag.equals("transport")) {
                    config.putString(subsystem + ".transportUnit.nickName", token + ":" + nickname);
                }
            } else { // software token
                if (certTag.equals("storage")) {
                    config.putString(subsystem + ".storageUnit.nickName", nickname);
                } else if (certTag.equals("transport")) {
                    config.putString(subsystem + ".transportUnit.nickName", nickname);
                }
            }
        }

        String serverCertNickname = nickname;
        String path = CMS.getConfigStore().getString("instanceRoot", "");
        if (certTag.equals("sslserver")) {
            if (!token.equals("Internal Key Storage Token")) {
                serverCertNickname = token + ":" + nickname;
            }
            PrintStream ps = new PrintStream(new FileOutputStream(path + "/conf/serverCertNick.conf"));
            ps.println(serverCertNickname);
            ps.close();
        }

        config.putString(subsystem + "." + certTag + ".nickname", nickname);
        config.putString(subsystem + "." + certTag + ".tokenname", token);
        if (certTag.equals("audit_signing")) {
            if (!token.equals("Internal Key Storage Token") && !token.equals("")) {
                config.putString("log.instance.SignedAudit.signedAuditCertNickname",
                        token + ":" + nickname);
            } else {
                config.putString("log.instance.SignedAudit.signedAuditCertNickname",
                        nickname);
            }
        }

        // for system certs verification
        if (!token.equals("Internal Key Storage Token") && !token.equals("")) {
            config.putString(subsystem + ".cert." + certTag + ".nickname",
                    token + ":" + nickname);
        } else {
            config.putString(subsystem + ".cert." + certTag + ".nickname", nickname);
        }

        config.commit(false);
        CMS.debug("updateConfig() done");
    }

    public static String getNickname(IConfigStore config, String certTag) throws EBaseException {
        String instanceID = config.getString("instanceId", "");

        String nickname = certTag + "Cert cert-" + instanceID;
        String preferredNickname = null;
        try {
            preferredNickname = config.getString(PCERT_PREFIX + certTag + ".nickname", null);
        } catch (EBaseException e) {
        }

        if (preferredNickname != null) {
            return preferredNickname;
        }
        return nickname;
    }

    public static int getPortFromSecurityDomain(String domainXML, String host, int port, String csType,
            String givenTag, String wantedTag) throws SAXException, IOException, ParserConfigurationException {
        IConfigStore cs = CMS.getConfigStore();
        ByteArrayInputStream bis = new ByteArrayInputStream(domainXML.getBytes());
        XMLObject parser = new XMLObject(bis);
        Document doc = parser.getDocument();
        NodeList nodeList = doc.getElementsByTagName(csType);

        // save domain name in cfg
        cs.putString("securitydomain.name", parser.getValue("Name"));

        int len = nodeList.getLength();
        CMS.debug("len: "+ len);
        for (int i = 0; i < len; i++) {
            Node node = nodeList.item(i);
            String v_host = parser.getValuesFromContainer(node, "Host").elementAt(0);
            CMS.debug("v_host " + v_host);
            String v_given_port = parser.getValuesFromContainer(node, givenTag).elementAt(0);
            CMS.debug("v_port " + v_given_port);
            if (!(v_host.equals(host) && v_given_port.equals(port + "")))
                continue;
            String wanted_port = parser.getValuesFromContainer(node, wantedTag).elementAt(0);
            return Integer.parseInt(wanted_port);
        }

        return 0;
    }

    public static void updateCloneConfig()
            throws EBaseException, IOException {
        IConfigStore config = CMS.getConfigStore();
        String cstype = config.getString("cs.type", null);
        cstype = cstype.toLowerCase();
        if (cstype.equals("kra")) {
            String token = config.getString("preop.module.token");
            if (!token.equals("Internal Key Storage Token")) {
                CMS.debug("NamePanel: updating configuration for KRA clone with hardware token");
                String subsystem = config.getString(PCERT_PREFIX + "storage.subsystem");
                String storageNickname = getNickname(config, "storage");
                String transportNickname = getNickname(config, "transport");

                config.putString(subsystem + ".storageUnit.hardware", token);
                config.putString(subsystem + ".storageUnit.nickName", token + ":" + storageNickname);
                config.putString(subsystem + ".transportUnit.nickName", token + ":" + transportNickname);
                config.commit(false);
            } else { // software token
                // parameters already set
            }
        }

        // audit signing cert
        String audit_nn = config.getString(cstype + ".audit_signing" + ".nickname", "");
        String audit_tk = config.getString(cstype + ".audit_signing" + ".tokenname", "");
        if (!audit_tk.equals("Internal Key Storage Token") && !audit_tk.equals("")) {
            config.putString("log.instance.SignedAudit.signedAuditCertNickname",
                    audit_tk + ":" + audit_nn);
        } else {
            config.putString("log.instance.SignedAudit.signedAuditCertNickname",
                    audit_nn);
        }
    }

    public static void handleCertRequest(IConfigStore config, String certTag, Cert cert) throws EPropertyNotFound,
            EBaseException, InvalidKeyException, NotInitializedException, TokenException, NoSuchAlgorithmException,
            NoSuchProviderException, CertificateException, SignatureException, IOException {

        // get public key
        String pubKeyType = config.getString(PCERT_PREFIX + certTag + ".keytype");
        String algorithm = config.getString(PCERT_PREFIX + certTag + ".keyalgorithm");
        X509Key pubk = null;
        if (pubKeyType.equals("rsa")) {
            pubk = getRSAX509Key(config, certTag);
        } else if (pubKeyType.equals("ecc")) {
            pubk = getECCX509Key(config, certTag);
        } else {
            CMS.debug("handleCertRequest() - " + "pubKeyType " + pubKeyType + " is unsupported!");
            return;
        }

        CMS.debug("handleCertRequest: tag=" + certTag);
        if (pubk == null) {
            CMS.debug("handleCertRequest: error getting public key null");
            return;
        }

        // get private key
        String privKeyID = config.getString(PCERT_PREFIX + certTag + ".privkey.id");
        CMS.debug("privKeyID=" + privKeyID);
        byte[] keyIDb = CryptoUtil.string2byte(privKeyID);

        PrivateKey privk = CryptoUtil.findPrivateKeyFromID(keyIDb);
        if (privk == null) {
            CMS.debug("handleCertRequest: error getting private key");
        }

        // construct cert request
        String caDN = config.getString(PCERT_PREFIX + certTag + ".dn");

        cert.setDN(caDN);
        PKCS10 certReq = CryptoUtil.createCertificationRequest(caDN, pubk, privk, algorithm);

        CMS.debug("handleCertRequest: created cert request");
        byte[] certReqb = certReq.toByteArray();
        String certReqs = CryptoUtil.base64Encode(certReqb);
        String certReqf = CryptoUtil.reqFormat(certReqs);

        String subsystem = config.getString(PCERT_PREFIX + certTag + ".subsystem");
        config.putString(subsystem + "." + certTag + ".certreq", certReqs);
        config.commit(false);
        cert.setRequest(certReqf);

    }

    public static X509Key getECCX509Key(IConfigStore config, String certTag) throws EPropertyNotFound, EBaseException,
            InvalidKeyException {
        X509Key pubk = null;
        String pubKeyEncoded = config.getString(PCERT_PREFIX + certTag + ".pubkey.encoded");
        pubk = CryptoUtil.getPublicX509ECCKey(CryptoUtil.string2byte(pubKeyEncoded));
        return pubk;
    }

    public static X509Key getRSAX509Key(IConfigStore config, String certTag) throws EPropertyNotFound, EBaseException,
            InvalidKeyException {
        X509Key pubk = null;

        String pubKeyModulus = config.getString(PCERT_PREFIX + certTag + ".pubkey.modulus");
        String pubKeyPublicExponent = config.getString(PCERT_PREFIX + certTag + ".pubkey.exponent");
        pubk = CryptoUtil.getPublicX509Key(
                CryptoUtil.string2byte(pubKeyModulus),
                CryptoUtil.string2byte(pubKeyPublicExponent));
        return pubk;
    }

    public static int handleCerts(Cert cert) throws IOException, EBaseException, CertificateException,
            NotInitializedException, TokenException, InvalidKeyException {
        String certTag = cert.getCertTag();
        String subsystem = cert.getSubsystem();
        String nickname = cert.getNickname();
        IConfigStore config = CMS.getConfigStore();

        boolean enable = config.getBoolean(PCERT_PREFIX + certTag + ".enable", true);
        if (!enable) return 0;

        CMS.debug("handleCerts(): for cert tag '" + cert.getCertTag() + "' using cert type '" + cert.getType() + "'");
        String b64 = cert.getCert();
        String tokenname = config.getString("preop.module.token", "");

        if (cert.getType().equals("local") && b64.equals("...certificate be generated internally...")) {
            String pubKeyType = config.getString(PCERT_PREFIX + certTag + ".keytype");
            X509Key x509key = null;
            if (pubKeyType.equals("rsa")) {
                x509key = getRSAX509Key(config, certTag);
            } else if (pubKeyType.equals("ecc")) {
                x509key = getECCX509Key(config, certTag);
            }

            if (findCertificate(tokenname, nickname)) {
                if (!certTag.equals("sslserver")) return 0;
            }
            X509CertImpl impl = CertUtil.createLocalCert(config, x509key,
                    PCERT_PREFIX, certTag, cert.getType(), null);

            if (impl != null) {
                byte[] certb = impl.getEncoded();
                String certs = CryptoUtil.base64Encode(certb);

                cert.setCert(certs);
                config.putString(subsystem + "." + certTag + ".cert", certs);
                CMS.debug("handleCerts(): nickname=" + nickname);

                try {
                    if (certTag.equals("sslserver") && findBootstrapServerCert())
                        deleteBootstrapServerCert();
                    if (findCertificate(tokenname, nickname))
                        deleteCert(tokenname, nickname);
                    if (certTag.equals("signing") && subsystem.equals("ca"))
                        CryptoUtil.importUserCertificate(impl, nickname);
                    else
                        CryptoUtil.importUserCertificate(impl, nickname, false);
                    CMS.debug("handleCerts(): cert imported for certTag '" + certTag + "'");
                } catch (Exception ee) {
                    ee.printStackTrace();
                    CMS.debug("handleCerts(): import certificate for certTag=" + certTag + " Exception: " + ee.toString());
                }
            }
        } else if (cert.getType().equals("remote")) {
            if (b64 != null && b64.length() > 0 && !b64.startsWith("...")) {
                CMS.debug("handleCerts(): process remote...import cert");
                String b64chain = cert.getCertChain();

                try {
                    if (certTag.equals("sslserver") && findBootstrapServerCert())
                        deleteBootstrapServerCert();
                    if (findCertificate(tokenname, nickname)) {
                        deleteCert(tokenname, nickname);
                    }
                } catch (Exception e) {
                    CMS.debug("CertRequestPanel update (remote): deleteCert Exception=" + e.toString());
                }

                b64 = CryptoUtil.stripCertBrackets(b64.trim());
                String certs = CryptoUtil.normalizeCertStr(b64);
                byte[] certb = CryptoUtil.base64Decode(certs);

                config.putString(subsystem + "." + certTag + ".cert", certs);
                try {
                    CryptoManager cm = CryptoManager.getInstance();
                    X509Certificate x509cert = cm.importCertPackage(certb, nickname);
                    CryptoUtil.trustCertByNickname(nickname);

                    X509Certificate[] certchains = cm.buildCertificateChain(x509cert);
                    X509Certificate leaf = null;

                    if (certchains != null) {
                        CMS.debug("handleCerts(): certchains length=" + certchains.length);
                        leaf = certchains[certchains.length - 1];
                    }

                    if (leaf == null) {
                        CMS.debug("handleCerts(): leaf is null!");
                        throw new IOException("leaf is null");
                    }

                    if (b64chain != null && b64chain.length() != 0) {
                        CMS.debug("handlecerts: cert might not have contained chain...calling importCertificateChain: "
                                + b64chain);
                        try {
                            CryptoUtil.importCertificateChain(CryptoUtil.normalizeCertAndReq(b64chain));
                        } catch (Exception e) {
                            CMS.debug("handleCerts(): importCertChain: Exception: " + e.toString());
                        }
                    }

                    InternalCertificate icert = (InternalCertificate) leaf;

                    icert.setSSLTrust(
                            InternalCertificate.TRUSTED_CA
                                    | InternalCertificate.TRUSTED_CLIENT_CA
                                    | InternalCertificate.VALID_CA);
                    CMS.debug("handleCerts(): import certificate successfully, certTag=" + certTag);
                } catch (Exception ee) {
                    ee.printStackTrace();
                    CMS.debug("handleCerts: import certificate for certTag=" + certTag + " Exception: "+ ee.toString());
                }

            } else {
                CMS.debug("handleCerts(): b64 not set");
                return 1;
            }
        } else {
            b64 = CryptoUtil.stripCertBrackets(b64.trim());
            String certs = CryptoUtil.normalizeCertStr(b64);
            byte[] certb = CryptoUtil.base64Decode(certs);
            X509CertImpl impl = new X509CertImpl(certb);
            try {
                if (certTag.equals("sslserver") && findBootstrapServerCert())
                    deleteBootstrapServerCert();
                if (findCertificate(tokenname, nickname)) {
                    deleteCert(tokenname, nickname);
                }
            } catch (Exception ee) {
                CMS.debug("handleCerts(): deleteCert Exception=" + ee.toString());
            }

            try {
                if (certTag.equals("signing") && subsystem.equals("ca"))
                    CryptoUtil.importUserCertificate(impl, nickname);
                else
                    CryptoUtil.importUserCertificate(impl, nickname, false);
            } catch (Exception ee) {
                CMS.debug("handleCerts(): Failed to import user certificate." + ee.toString());
                return 1;
            }
        }

        //update requests in request queue for local certs to allow renewal
        if ((cert.getType().equals("local")) || (cert.getType().equals("selfsign"))) {
            CertUtil.updateLocalRequest(config, certTag, cert.getRequest(), "pkcs10", null);
        }

        if (certTag.equals("signing") && subsystem.equals("ca")) {
            String NickName = nickname;
            if (!tokenname.equals("internal") && !tokenname.equals("Internal Key Storage Token"))
                NickName = tokenname + ":" + nickname;

            CMS.debug("handleCerts(): set trust on CA signing cert " + NickName);
            CryptoUtil.trustCertByNickname(NickName);
            CMS.reinit(ICertificateAuthority.ID);
        }
        return 0;
    }

    public static void setCertPermissions(String tag) throws EBaseException, NotInitializedException,
            ObjectNotFoundException, TokenException {
        if (tag.equals("signing") || tag.equals("external_signing")) return;

        IConfigStore cs = CMS.getConfigStore();
        String nickname = cs.getString("preop.cert." + tag + ".nickname", "");
        String tokenname = cs.getString("preop.module.token", "");
        if (!tokenname.equals("Internal Key Storage Token"))
            nickname = tokenname + ":" + nickname;

        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate c = cm.findCertByNickname(nickname);

        if (c instanceof InternalCertificate) {
            InternalCertificate ic = (InternalCertificate) c;
            ic.setSSLTrust(InternalCertificate.USER);
            ic.setEmailTrust(InternalCertificate.USER);
            if (tag.equals("audit_signing")) {
                ic.setObjectSigningTrust(InternalCertificate.USER
                        | InternalCertificate.VALID_PEER | InternalCertificate.TRUSTED_PEER);
            } else {
                ic.setObjectSigningTrust(InternalCertificate.USER);
            }
        }
    }

    public static boolean findCertificate(String tokenname, String nickname) throws NotInitializedException,
            TokenException, IOException {
        IConfigStore cs = CMS.getConfigStore();
        CryptoManager cm = CryptoManager.getInstance();

        String fullnickname = nickname;
        boolean hardware = false;
        if (!tokenname.equals("internal") && !tokenname.equals("Internal Key Storage Token")) {
            hardware = true;
            fullnickname = tokenname + ":" + nickname;
        }

        X509Certificate cert = null;
        try {
            cert = cm.findCertByNickname(fullnickname);
        } catch (ObjectNotFoundException e) {
            return false;
        }

        if (cert == null)
            return false;
        try {
            @SuppressWarnings("unused")
            boolean done = cs.getBoolean("preop.CertRequestPanel.done"); // check for errors
        } catch (Exception ee) {
            if (hardware) {
                CMS.debug("CertRequestPanel findCertificate: The certificate with the same nickname: "
                        + fullnickname + " has been found on HSM. Please remove it before proceeding.");
                throw new IOException("The certificate with the same nickname: "
                        + fullnickname + " has been found on HSM. Please remove it before proceeding.");
            }
        }
        return true;
    }


    public static boolean findBootstrapServerCert() throws EBaseException, NotInitializedException, TokenException {
        IConfigStore cs = CMS.getConfigStore();

        String nickname = cs.getString("preop.cert.sslserver.nickname");

        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate cert;
        try {
            cert = cm.findCertByNickname(nickname);
        } catch (ObjectNotFoundException e) {
            return false;
        }
        Principal issuerDN = cert.getIssuerDN();
        Principal subjectDN = cert.getSubjectDN();
        if (issuerDN.equals(subjectDN)) return true;

        return false;
    }

    public static void deleteBootstrapServerCert() throws EBaseException, NotInitializedException,
            NoSuchTokenException, TokenException {
        IConfigStore cs = CMS.getConfigStore();
        String nickname = cs.getString("preop.cert.sslserver.nickname");
        deleteCert("Internal Key Storage Token", nickname);
    }

    public static void deleteCert(String tokenname, String nickname) throws NotInitializedException,
            NoSuchTokenException, TokenException {

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken tok = cm.getTokenByName(tokenname);
        CryptoStore store = tok.getCryptoStore();
        String fullnickname = nickname;
        if (!tokenname.equals("") &&
                !tokenname.equals("Internal Key Storage Token") &&
                !tokenname.equals("internal"))
            fullnickname = tokenname + ":" + nickname;

        CMS.debug("deleteCert: nickname=" + fullnickname);
        X509Certificate cert;
        try {
            cert = cm.findCertByNickname(fullnickname);
        } catch (ObjectNotFoundException e) {
            CMS.debug("deleteCert: cert not found");
            return;
        }

        if (store instanceof PK11Store) {
            PK11Store pk11store = (PK11Store) store;
            try {
                pk11store.deleteCertOnly(cert);
            } catch (NoSuchItemOnTokenException e) {
            }
            CMS.debug("deleteCert: cert deleted successfully");
        }
    }

    public static void backupKeys(String pwd, String fname) throws EPropertyNotFound, EBaseException,
            NotInitializedException, ObjectNotFoundException, TokenException, DigestException,
            InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidBERException,
            CertificateEncodingException, IllegalStateException, IllegalBlockSizeException, BadPaddingException,
            IOException {
        CMS.debug("backupKeys(): start");
        IConfigStore cs = CMS.getConfigStore();
        String certlist = cs.getString("preop.cert.list");

        StringTokenizer st = new StringTokenizer(certlist, ",");
        CryptoManager cm = CryptoManager.getInstance();

        Password pass = new org.mozilla.jss.util.Password(pwd.toCharArray());
        SEQUENCE encSafeContents = new SEQUENCE();
        SEQUENCE safeContents = new SEQUENCE();
        while (st.hasMoreTokens()) {
            String t = st.nextToken();
            if (t.equals("sslserver"))
                continue;
            String nickname = cs.getString("preop.cert." + t + ".nickname");
            String modname = cs.getString("preop.module.token");

            if (!modname.equals("Internal Key Storage Token"))
                nickname = modname + ":" + nickname;

            X509Certificate x509cert = cm.findCertByNickname(nickname);
            byte localKeyId[] = addCertBag(x509cert, nickname, safeContents);
            PrivateKey pkey = cm.findPrivKeyByCert(x509cert);
            addKeyBag(pkey, x509cert, pass, localKeyId, encSafeContents);
        }

        X509Certificate[] cacerts = cm.getCACerts();

        for (int i = 0; i < cacerts.length; i++) {
            String nickname = null;
            addCertBag(cacerts[i], nickname, safeContents);
        }

        AuthenticatedSafes authSafes = new AuthenticatedSafes();
        authSafes.addSafeContents(safeContents);
        authSafes.addSafeContents(encSafeContents);
        PFX pfx = new PFX(authSafes);
        pfx.computeMacData(pass, null, 5);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        pfx.encode(bos);
        byte[] output = bos.toByteArray();
        cs.putString("preop.pkcs12", CryptoUtil.byte2string(output));
        pass.clear();
        cs.commit(false);

        if (fname != null) {
            FileOutputStream fout = null;
            try {
                fout = new FileOutputStream(fname);
                fout.write(output);
            } catch (Exception e) {
                throw new IOException("Failed to store keys in backup file" + e);
            } finally {
                if (fout != null) {
                    fout.close();
                }
            }
        }
    }

    public static void addKeyBag(PrivateKey pkey, X509Certificate x509cert,
            Password pass, byte[] localKeyId, SEQUENCE safeContents)
            throws NoSuchAlgorithmException, InvalidBERException, InvalidKeyException,
            InvalidAlgorithmParameterException, NotInitializedException, TokenException, IllegalStateException,
            IllegalBlockSizeException, BadPaddingException, CharConversionException {

        PasswordConverter passConverter = new PasswordConverter();

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte salt[] = random.generateSeed(4); // 4 bytes salt
        byte[] priData = getEncodedKey(pkey);

        PrivateKeyInfo pki = (PrivateKeyInfo)
                ASN1Util.decode(PrivateKeyInfo.getTemplate(), priData);
        ASN1Value key = EncryptedPrivateKeyInfo.createPBE(
                PBEAlgorithm.PBE_SHA1_DES3_CBC,
                pass, salt, 1, passConverter, pki);
        SET keyAttrs = createBagAttrs(
                x509cert.getSubjectDN().toString(), localKeyId);
        SafeBag keyBag = new SafeBag(SafeBag.PKCS8_SHROUDED_KEY_BAG,
                key, keyAttrs);
        safeContents.addElement(keyBag);

    }

    public static byte[] addCertBag(X509Certificate x509cert, String nickname,
            SEQUENCE safeContents) throws CertificateEncodingException, NoSuchAlgorithmException, CharConversionException {
        byte[] localKeyId = null;

        ASN1Value cert = new OCTET_STRING(x509cert.getEncoded());
        localKeyId = createLocalKeyId(x509cert);
        SET certAttrs = null;
        if (nickname != null)
            certAttrs = createBagAttrs(nickname, localKeyId);
        SafeBag certBag = new SafeBag(SafeBag.CERT_BAG,
                new CertBag(CertBag.X509_CERT_TYPE, cert), certAttrs);
        safeContents.addElement(certBag);

        return localKeyId;
    }

    public static byte[] getEncodedKey(PrivateKey pkey) throws NotInitializedException, NoSuchAlgorithmException,
            TokenException, IllegalStateException, CharConversionException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);
        SymmetricKey sk = kg.generate();
        KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        IVParameterSpec param = new IVParameterSpec(iv);
        wrapper.initWrap(sk, param);
        byte[] enckey = wrapper.wrap(pkey);
        Cipher c = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
        c.initDecrypt(sk, param);
        byte[] recovered = c.doFinal(enckey);
        return recovered;
    }

    public static byte[] createLocalKeyId(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {

        // SHA1 hash of the X509Cert der encoding
        byte certDer[] = cert.getEncoded();

        MessageDigest md = MessageDigest.getInstance("SHA");

        md.update(certDer);
        return md.digest();

    }

    public static SET createBagAttrs(String nickName, byte localKeyId[]) throws CharConversionException {

        SET attrs = new SET();
        SEQUENCE nickNameAttr = new SEQUENCE();

        nickNameAttr.addElement(SafeBag.FRIENDLY_NAME);
        SET nickNameSet = new SET();

        nickNameSet.addElement(new BMPString(nickName));
        nickNameAttr.addElement(nickNameSet);
        attrs.addElement(nickNameAttr);
        SEQUENCE localKeyAttr = new SEQUENCE();

        localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);
        SET localKeySet = new SET();

        localKeySet.addElement(new OCTET_STRING(localKeyId));
        localKeyAttr.addElement(localKeySet);
        attrs.addElement(localKeyAttr);
        return attrs;

    }

    public static void createAdminCertificate(String certRequest, String certRequestType, String subject)
            throws InvalidBERException, IOException, InvalidKeyException, InvalidKeyFormatException,
            NoSuchAlgorithmException, SignatureException, NoSuchProviderException, EBaseException {
        IConfigStore cs = CMS.getConfigStore();
        X509Key x509key = null;
        if (certRequestType.equals("crmf")) {
            byte[] b = CMS.AtoB(certRequest);
            SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(b);
            subject = CryptoUtil.getSubjectName(crmfMsgs);
            x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);
        } else if (certRequestType.equals("pkcs10")) {
            byte[] b = CMS.AtoB(certRequest);
            PKCS10 pkcs10 = new PKCS10(b);
            x509key = pkcs10.getSubjectPublicKeyInfo();
        }

        if (x509key == null) {
            CMS.debug("createAdminCertificate() - x509key is null!");
            throw new IOException("x509key is null");
        }

        cs.putString(PCERT_PREFIX + "admin.dn", subject);
        String caType = cs.getString(PCERT_PREFIX + "admin.type", "local");
        X509CertImpl impl = CertUtil.createLocalCert(cs, x509key, PCERT_PREFIX, "admin", caType, null);

        // update the locally created request for renewal
        CertUtil.updateLocalRequest(cs, "admin", certRequest, certRequestType, subject);

        ISubsystem ca = CMS.getSubsystem("ca");
        if (ca != null) {
            createPKCS7(impl);
        }
        cs.putString("preop.admincert.serialno.0", impl.getSerialNumber().toString(16));
    }

    public static void createPKCS7(X509CertImpl cert) throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem("ca");
        CertificateChain cachain = ca.getCACertChain();
        java.security.cert.X509Certificate[] cacerts = cachain.getChain();
        X509CertImpl[] userChain = new X509CertImpl[cacerts.length + 1];
        int m = 1, n = 0;

        for (; n < cacerts.length; m++, n++) {
            userChain[m] = (X509CertImpl) cacerts[n];
        }

        userChain[0] = cert;
        PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                new ContentInfo(new byte[0]), userChain, new SignerInfo[0]);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        p7.encodeSignedData(bos);
        byte[] p7Bytes = bos.toByteArray();
        String p7Str = CMS.BtoA(p7Bytes);
        cs.putString("preop.admincert.pkcs7", CryptoUtil.normalizeCertStr(p7Str));
    }

    public static void createAdmin(String uid, String email, String name, String pwd) throws IOException,
            EBaseException, LDAPException {
        IUGSubsystem system = (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));
        IConfigStore config = CMS.getConfigStore();
        String groupNames = config.getString("preop.admin.group", "Certificate Manager Agents,Administrators");

        IUser user = null;

        try {
            user = system.createUser(uid);
            user.setEmail(email);
            user.setPassword(pwd);
            user.setFullName(name);
            user.setUserType("adminType");
            user.setState("1");
            user.setPhone("");
            system.addUser(user);

        } catch (ConflictingOperationException e) {
            CMS.debug("AdminPanel createAdmin: addUser " + e.toString());
            // ignore
        }

        IGroup group = null;
        for (String groupName : groupNames.split(",")) {
            groupName = groupName.trim();
            group = system.getGroupFromName(groupName);
            if (!group.isMember(uid)) {
                group.addMemberName(uid);
                system.modifyGroup(group);
            }
        }

        String select = config.getString("securitydomain.select", "");
        if (select.equals("new")) {
            group = system.getGroupFromName("Security Domain Administrators");
            if (group != null && !group.isMember(uid)) {
                CMS.debug("AdminPanel createAdmin:  add user '" + uid + "' to group 'Security Domain Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise CA Administrators");
            if (group != null && !group.isMember(uid)) {
                CMS.debug("AdminPanel createAdmin:  add user '" + uid + "' to group 'Enterprise CA Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise KRA Administrators");
            if (group != null && !group.isMember(uid)) {
                CMS.debug("AdminPanel createAdmin:  add user '" + uid + "' to group 'Enterprise KRA Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise RA Administrators");
            if (group != null && !group.isMember(uid)) {
                CMS.debug("AdminPanel createAdmin:  add user '" + uid + "' to group 'Enterprise RA Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise TKS Administrators");
            if (group != null && !group.isMember(uid)) {
                CMS.debug("AdminPanel createAdmin:  add user '" + uid + "' to group 'Enterprise TKS Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise OCSP Administrators");
            if (group != null && !group.isMember(uid)) {
                CMS.debug("AdminPanel createAdmin:  add user '" + uid + "' to group 'Enterprise OCSP Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise TPS Administrators");
            if (group != null && !group.isMember(uid)) {
                CMS.debug("AdminPanel createAdmin:  add user '" + uid + "' to group 'Enterprise TPS Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }
        }
    }

    public static String submitAdminCertRequest(String ca_hostname, int ca_port, String profileId,
            String certRequestType, String certRequest, String subjectDN) throws IOException, EBaseException,
            SAXException, ParserConfigurationException {
        IConfigStore config = CMS.getConfigStore();

        if (profileId == null) {
            profileId = config.getString("preop.admincert.profile", "caAdminCert");
        }
        certRequest = URLEncoder.encode(certRequest, "UTF-8");
        String session_id = CMS.getConfigSDSessionId();
        String content = "profileId=" + profileId + "&cert_request_type=" + certRequestType +
                "&cert_request=" + certRequest + "&xmlOutput=true&sessionID=" + session_id + "&subject=" + subjectDN;

        String c = getHttpResponse(ca_hostname, ca_port, true, "/ca/ee/ca/profileSubmit", content, null, null);

        // retrieve the request Id and admin certificate
        if (c != null) {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser = new XMLObject(bis);

            String status = parser.getValue("Status");
            CMS.debug("submitAdminXertRequest: status=" + status);
            if (status.equals(AUTH_FAILURE)) {
                throw new EAuthException(AUTH_FAILURE);
            } else if (!status.equals(SUCCESS)) {
                String error = parser.getValue("Error");
                throw new IOException(error);
            }

            IConfigStore cs = CMS.getConfigStore();
            String id = parser.getValue("Id");

            cs.putString("preop.admincert.requestId.0", id);
            String serial = parser.getValue("serialno");

            cs.putString("preop.admincert.serialno.0", serial);
            String b64 = parser.getValue("b64");

            // save in a file for access by ImportAdminCertPanel
            String instanceRoot = cs.getString("instanceRoot", "");
            String dir = instanceRoot + File.separator + "conf" + File.separator + "admin.b64";
            cs.putString("preop.admincert.b64", dir);

            PrintStream ps = new PrintStream(new FileOutputStream(dir));
            ps.println(b64);
            ps.flush();
            ps.close();

            return b64;
        } else {
            throw new IOException("submitAdminCertRequest: Failed to get response from ca");
        }
    }

    public static void createSecurityDomain() throws EBaseException, LDAPException, NumberFormatException, IOException,
            SAXException, ParserConfigurationException {
        IConfigStore cs = CMS.getConfigStore();
        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = CMS.getLdapBoundConnFactory();
        dbFactory.init(dbCfg);
        LDAPConnection conn = dbFactory.getConn();
        LDAPEntry entry = null;
        LDAPAttributeSet attrs = null;

        // Create security domain ldap entry
        String basedn = cs.getString("internaldb.basedn");
        String secdomain = cs.getString("securitydomain.name");

        String dn = "ou=Security Domain," + basedn;
        attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectclass", "top"));
        attrs.add(new LDAPAttribute("objectclass", "pkiSecurityDomain"));
        attrs.add(new LDAPAttribute("name", secdomain));
        attrs.add(new LDAPAttribute("ou", "Security Domain"));
        entry = new LDAPEntry(dn, attrs);
        conn.add(entry);

        // create list containers
        String clist[] = { "CAList", "OCSPList", "KRAList", "RAList", "TKSList", "TPSList" };
        for (int i = 0; i < clist.length; i++) {
            dn = "cn=" + LDAPUtil.escapeRDNValue(clist[i]) + ",ou=Security Domain," + basedn;
            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "pkiSecurityGroup"));
            attrs.add(new LDAPAttribute("cn", clist[i]));
            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);
        }

        // Add this host
        String cn = CMS.getEESSLHost() + ":" + CMS.getAdminPort();
        dn = "cn=" + LDAPUtil.escapeRDNValue(cn) + ",cn=CAList,ou=Security Domain," + basedn;
        String subsystemName = cs.getString("preop.subsystem.name");
        attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectclass", "top"));
        attrs.add(new LDAPAttribute("objectclass", "pkiSubsystem"));
        attrs.add(new LDAPAttribute("Host", CMS.getEESSLHost()));
        attrs.add(new LDAPAttribute("SecurePort", CMS.getEESSLPort()));
        attrs.add(new LDAPAttribute("SecureAgentPort", CMS.getAgentPort()));
        attrs.add(new LDAPAttribute("SecureAdminPort", CMS.getAdminPort()));
        if (CMS.getEEClientAuthSSLPort() != null) {
            attrs.add(new LDAPAttribute("SecureEEClientAuthPort", CMS.getEEClientAuthSSLPort()));
        }
        attrs.add(new LDAPAttribute("UnSecurePort", CMS.getEENonSSLPort()));
        attrs.add(new LDAPAttribute("Clone", "FALSE"));
        attrs.add(new LDAPAttribute("SubsystemName", subsystemName));
        attrs.add(new LDAPAttribute("cn", cn));
        attrs.add(new LDAPAttribute("DomainManager", "TRUE"));
        entry = new LDAPEntry(dn, attrs);
        conn.add(entry);

        CMS.debug("createSecurityDomain(): finish updating domain info");
        conn.disconnect();

        // Fetch the "new" security domain and display it
        // CMS.debug("createSecurityDomain(): Dump contents of new Security Domain . . .");
        // @SuppressWarnings("unused")
        // String c = getDomainXML(CMS.getEESSLHost(), Integer.parseInt(CMS.getAdminPort()), true);
    }

    public static void updateSecurityDomain() throws IOException, SAXException, ParserConfigurationException,
            EPropertyNotFound, EBaseException {
        IConfigStore cs = CMS.getConfigStore();

        int sd_agent_port = cs.getInteger("securitydomain.httpsagentport");
        int sd_admin_port = cs.getInteger("securitydomain.httpsadminport");
        String select = cs.getString("preop.subsystem.select");
        String type = cs.getString("cs.type");
        String sd_host = cs.getString("securitydomain.host");
        String subsystemName = cs.getString("preop.subsystem.name");

        boolean cloneMaster = false;

        if (select.equals("clone") && type.equalsIgnoreCase("CA") && isSDHostDomainMaster(cs)) {
            cloneMaster = true;
            CMS.debug("Cloning a domain master");
        }

        String cloneStr = select.equals("clone") ? "&clone=true" : "&clone=false";
        String domainMasterStr = cloneMaster ? "&dm=true" : "&dm=false";
        String eecaStr = (CMS.getEEClientAuthSSLPort() != null) ? "&eeclientauthsport=" + CMS.getEEClientAuthSSLPort()
                : "";

        String url =  "/ca/admin/ca/updateDomainXML";
        String content = "list=" + type + "List"
                + "&type=" + type
                + "&host=" + CMS.getEESSLHost()
                + "&name=" + subsystemName
                + "&sport=" + CMS.getEESSLPort()
                + domainMasterStr
                + cloneStr
                + "&agentsport=" + CMS.getAgentPort()
                + "&adminsport=" + CMS.getAdminPort()
                + eecaStr
                + "&httpport=" + CMS.getEENonSSLPort();

        try {
            String session_id = CMS.getConfigSDSessionId();
            content += "&sessionID="+ session_id;
            updateDomainXML(sd_host, sd_admin_port, true, url, content, false);
        } catch (Exception e) {
            CMS.debug("updateSecurityDomain: failed to update security domain using admin port "
                      + sd_admin_port + ": " + e);
            CMS.debug("updateSecurityDomain: now trying agent port with client auth");
            url =  "/ca/agent/ca/updateDomainXML";
            updateDomainXML(sd_host, sd_agent_port, true, url, content, true);
        }

        // Fetch the "updated" security domain and display it
        CMS.debug("updateSecurityDomain(): Dump contents of updated Security Domain . . .");
        @SuppressWarnings("unused")
        String c = getDomainXML(sd_host, sd_admin_port, true);
    }

    public static boolean isSDHostDomainMaster(IConfigStore config) throws EPropertyNotFound, EBaseException,
            IOException, SAXException, ParserConfigurationException {
        String dm = "false";

        String hostname = config.getString("securitydomain.host");
        int httpsadminport = config.getInteger("securitydomain.httpsadminport");

        CMS.debug("isSDHostDomainMaster(): Getting domain.xml from CA...");
        String c = getDomainXML(hostname, httpsadminport, true);

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser = new XMLObject(bis);
        Document doc = parser.getDocument();
        NodeList nodeList = doc.getElementsByTagName("CA");

        int len = nodeList.getLength();
        for (int i = 0; i < len; i++) {
            Vector<String> v_hostname = parser.getValuesFromContainer(nodeList.item(i), "Host");
            Vector<String> v_https_admin_port = parser.getValuesFromContainer(nodeList.item(i), "SecureAdminPort");
            Vector<String> v_domain_mgr = parser.getValuesFromContainer(nodeList.item(i), "DomainManager");

            if (v_hostname.elementAt(0).equals(hostname) &&
                    v_https_admin_port.elementAt(0).equals(Integer.toString(httpsadminport))) {
                dm = v_domain_mgr.elementAt(0).toString();
                break;
            }
        }
        return dm.equalsIgnoreCase("true");
    }

    public static void updateDomainXML(String hostname, int port, boolean https,
            String servlet, String uri, boolean useClientAuth) throws IOException, EBaseException, SAXException,
            ParserConfigurationException {
        CMS.debug("WizardPanelBase updateDomainXML start hostname=" + hostname + " port=" + port);
        String c = null;
        if (useClientAuth) {
            IConfigStore cs = CMS.getConfigStore();
            String nickname = cs.getString("preop.cert.subsystem.nickname", "");
            String tokenname = cs.getString("preop.module.token", "");

            if (!tokenname.equals("") &&
                    !tokenname.equals("Internal Key Storage Token") &&
                    !tokenname.equals("internal")) {
                nickname = tokenname + ":" + nickname;
            }
            CMS.debug("updateDomainXML() nickname=" + nickname);

            c = getHttpResponse(hostname, port, https, servlet, uri, nickname, null);
        } else {
            c = getHttpResponse(hostname, port, https, servlet, uri, null, null);
        }
        if (c != null && !c.equals("")) {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject obj = new XMLObject(bis);
            String status = obj.getValue("Status");
            CMS.debug("WizardPanelBase updateDomainXML: status=" + status);

            if (status.equals(SUCCESS)) {
                return;
            } else {
                String error = obj.getValue("Error");
                throw new IOException(error);
            }
        } else {
            throw new IOException("Failed to get response when updating security domain");
        }
    }

    public static void updateConnectorInfo(String ownagenthost, String ownagentsport)
            throws IOException, EBaseException, SAXException, ParserConfigurationException {
        IConfigStore cs = CMS.getConfigStore();
        int port = -1;
        String url = "";
        String host = null;
        String transportCert = "";

        url = cs.getString("preop.ca.url", "");
        if (!url.equals("")) {
            host = cs.getString("preop.ca.hostname", "");
            port = cs.getInteger("preop.ca.httpsadminport", -1);
            transportCert = cs.getString("kra.transport.cert", "");
        }

        if (host == null) {
            CMS.debug("updateConnectorInfo(): preop.ca.url is not defined. External CA selected. No transport certificate setup is required");
        } else {
            CMS.debug("updateConnectorInfo(): Transport certificate is being setup in " + url);
            String session_id = CMS.getConfigSDSessionId();
            String content = "ca.connector.KRA.enable=true&ca.connector.KRA.local=false&ca.connector.KRA.timeout=30"
                    + "&ca.connector.KRA.uri=/kra/agent/kra/connector&ca.connector.KRA.host=" + ownagenthost
                    + "&ca.connector.KRA.port=" + ownagentsport
                    + "&ca.connector.KRA.transportCert=" + URLEncoder.encode(transportCert, "UTF-8")
                    + "&sessionID=" + session_id;

            updateConnectorInfo(host, port, true, content);
        }
    }

    public static void updateConnectorInfo(String host, int port, boolean https,
            String content) throws IOException, SAXException, ParserConfigurationException {
        CMS.debug("updateConnectorInfo start");
        String c = getHttpResponse(host, port, https, "/ca/admin/ca/updateConnector", content, null, null);
        if (c != null) {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser = null;
            parser = new XMLObject(bis);
            String status = parser.getValue("Status");
            CMS.debug("updateConnectorInfo: status=" + status);
            if (!status.equals(SUCCESS)) {
                String error = parser.getValue("Error");
                throw new IOException(error);
            }
        }
    }

    public static void setupClientAuthUser() throws EBaseException, CertificateException, IOException, SAXException,
            ParserConfigurationException, LDAPException {
        IConfigStore cs = CMS.getConfigStore();
        String host = cs.getString("preop.ca.hostname", "");
        int port = cs.getInteger("preop.ca.httpsadminport", -1);

        // retrieve CA subsystem certificate from the CA
        IUGSubsystem system =
                (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));
        String id = "";

        String b64 = getSubsystemCert(host, port, true);
        if (b64 != null) {
            int num = cs.getInteger("preop.subsystem.count", 0);
            id = "CA-" + host + "-" + port;
            num++;
            cs.putInteger("preop.subsystem.count", num);
            cs.putInteger("subsystem.count", num);
            IUser user = system.createUser(id);
            user.setFullName(id);
            user.setEmail("");
            user.setPassword("");
            user.setUserType("agentType");
            user.setState("1");
            user.setPhone("");
            X509CertImpl[] certs = new X509CertImpl[1];
            certs[0] = new X509CertImpl(CMS.AtoB(b64));
            user.setX509Certificates(certs);
            try {
                system.addUser(user);
            } catch (ConflictingOperationException e) {
                // ignore if
            }
            CMS.debug("DonePanel display: successfully add the user");
            system.addUserCert(user);
            CMS.debug("DonePanel display: successfully add the user certificate");
            cs.commit(false);
        }

        String groupName = "Trusted Managers";
        IGroup group = system.getGroupFromName(groupName);
        if (!group.isMember(id)) {
            group.addMemberName(id);
            system.modifyGroup(group);
            CMS.debug("DonePanel display: successfully added the user to the group.");
        }

    }

    public static String getSubsystemCert(String host, int port, boolean https)
            throws IOException, SAXException, ParserConfigurationException {
        CMS.debug("getSubsystemCert() start");
        String c = getHttpResponse(host, port, https, "/ca/admin/ca/getSubsystemCert", null, null, null);
        if (c != null) {
            ByteArrayInputStream bis =
                    new ByteArrayInputStream(c.getBytes());
            XMLObject parser = new XMLObject(bis);
            String status = parser.getValue("Status");
            if (status.equals(SUCCESS)) {
                String s = parser.getValue("Cert");
                return s;
            } else {
                return null;
            }
        }
        return null;
    }

    public static String getTransportCert(URI secdomainURI, URI kraUri)
            throws IOException, SAXException, ParserConfigurationException {
        CMS.debug("getTransportCert() start");
        String sessionId = CMS.getConfigSDSessionId();

        String content = "&xmlOutput=true" +
                "&sessionID=" + sessionId +
                "&auth_hostname=" + secdomainURI.getHost() +
                "&auth_port=" + secdomainURI.getPort();

        String c = getHttpResponse(
                kraUri.getHost(),
                kraUri.getPort(),
                true,
                "/kra/admin/kra/getTransportCert",
                content, null, null);

        if (c != null) {
            ByteArrayInputStream bis =
                    new ByteArrayInputStream(c.getBytes());
            XMLObject parser = new XMLObject(bis);
            String status = parser.getValue("Status");
            if (status.equals(SUCCESS)) {
                String s = parser.getValue("TransportCert");
                return s;
            } else {
                return null;
            }
        }
        return null;
    }

    public static void getSharedSecret(String tksHost, int tksPort, boolean importKey) throws EPropertyNotFound,
            EBaseException, URISyntaxException {
        IConfigStore cs = CMS.getConfigStore();
        String host = cs.getString("service.machineName");
        String port = cs.getString("service.securePort");
        String dbDir = cs.getString("instanceRoot") + "/alias";
        String dbNick = cs.getString("tps.cert.subsystem.nickname");

        String passwordFile = cs.getString("passwordFile");
        IConfigStore psStore = CMS.createFileConfigStore(passwordFile);
        String dbPass = psStore.getString("internal");

        ClientConfig config = new ClientConfig();
        config.setServerURI("https://" + tksHost + ":" + tksPort);
        config.setCertDatabase(dbDir);
        config.setCertNickname(dbNick);
        config.setCertPassword(dbPass);

        PKIClient client = new PKIClient(config);
        PKIConnection connection = client.getConnection();

        // Ignore the "UNTRUSTED_ISSUER" and "CA_CERT_INVALID" validity status
        // during PKI instance creation since we are using an untrusted temporary CA cert.
        connection.addIgnoredCertStatus(SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER);
        connection.addIgnoredCertStatus(SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID);

        AccountClient accountClient = new AccountClient(client, "tks");
        TPSConnectorClient tpsConnectorClient = new TPSConnectorClient(client, "tks");

        accountClient.login();
        TPSConnectorData data = null;
        try {
            data = tpsConnectorClient.getConnector(host, port);
        } catch (ResourceNotFoundException e) {
            // no connector exists
            data = null;
        }
        KeyData keyData = null;
        if (data == null) {
            data = tpsConnectorClient.createConnector(host, port);
            keyData = tpsConnectorClient.createSharedSecret(data.getID());
        } else {
            String connId = data.getID();
            keyData = tpsConnectorClient.getSharedSecret(connId);
            if (keyData != null) {
                keyData = tpsConnectorClient.replaceSharedSecret(connId);
            } else {
                keyData = tpsConnectorClient.createSharedSecret(connId);
            }
        }
        accountClient.logout();

        if (importKey) {
            // TODO - we need code here to import the key into the tps certdb
            // this is not needed if we are using a shared database with
            // the tks.
        }

        // store the new nick in CS.cfg
        String nick = "TPS-" + host + "-" + port + " sharedSecret";
        cs.putString("conn.tks1.tksSharedSymKeyName", nick);
        cs.commit(false);
    }

    public static void importCACertToOCSP() throws IOException, EBaseException, CertificateEncodingException {
        IConfigStore config = CMS.getConfigStore();

        // get certificate chain from CA
        String b64 = config.getString("preop.ca.pkcs7", "");
        if (b64.equals("")) {
            throw new IOException("Failed to get certificate chain.");
        }

        // this could be a chain
        java.security.cert.X509Certificate[] certs = com.netscape.cmsutil.util.Cert.mapCertFromPKCS7(b64);
        java.security.cert.X509Certificate leafCert = null;
        if (certs != null && certs.length > 0) {
            if (certs[0].getSubjectDN().getName().equals(certs[0].getIssuerDN().getName())) {
                leafCert = certs[certs.length - 1];
            } else {
                leafCert = certs[0];
            }

            IOCSPAuthority ocsp = (IOCSPAuthority) CMS.getSubsystem(IOCSPAuthority.ID);
            IDefStore defStore = ocsp.getDefaultStore();

            // (1) need to normalize (sort) the chain
            // (2) store certificate (and certificate chain) into
            // database
            ICRLIssuingPointRecord rec = defStore.createCRLIssuingPointRecord(
                    leafCert.getSubjectDN().getName(),
                    BIG_ZERO,
                    MINUS_ONE, null, null);

            rec.set(ICRLIssuingPointRecord.ATTR_CA_CERT, leafCert.getEncoded());
            defStore.addCRLIssuingPoint(leafCert.getSubjectDN().getName(), rec);

            CMS.debug("importCACertToOCSP(): Added CA certificate.");
        }
    }

    public static void updateOCSPConfig()
            throws IOException, EBaseException, SAXException, ParserConfigurationException {
        IConfigStore config = CMS.getConfigStore();
        String cahost = config.getString("preop.ca.hostname", "");
        int caport = config.getInteger("preop.ca.httpsport", -1);
        String ocsphost = CMS.getAgentHost();
        int ocspport = Integer.parseInt(CMS.getAgentPort());
        String session_id = CMS.getConfigSDSessionId();
        String content = "xmlOutput=true&sessionID=" + session_id + "&ocsp_host=" + ocsphost + "&ocsp_port=" + ocspport;

        String c = getHttpResponse(cahost, caport, true, "/ca/ee/ca/updateOCSPConfig", content, null, null);
        if (c == null || c.equals("")) {
            CMS.debug("WizardPanelBase updateOCSPConfig: content is null.");
            throw new IOException("The server you want to contact is not available");
        } else {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser = new XMLObject(bis);

            String status = parser.getValue("Status");
            CMS.debug("WizardPanelBase updateOCSPConfig: status=" + status);

            if (status.equals(SUCCESS)) {
                CMS.debug("WizardPanelBase updateOCSPConfig: Successfully update the OCSP configuration in the CA.");
            } else if (status.equals(AUTH_FAILURE)) {
                throw new EAuthException(AUTH_FAILURE);
            } else {
                String error = parser.getValue("Error");
                throw new IOException(error);
            }
        }
    }

    public static void setupDBUser() throws CertificateException, LDAPException, EBaseException,
            NotInitializedException, ObjectNotFoundException, TokenException, IOException {
        IUGSubsystem system =
                (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));

        try {
            @SuppressWarnings("unused")
            Enumeration<IUser> dbusers = system.findUsers(DBUSER);
            CMS.debug("DB User already exists: " + DBUSER);
            return;
        } catch (EUsrGrpException e) {
            CMS.debug("Creating DB User: " + DBUSER);
        }

        String b64 = getSubsystemCert();
        if (b64 == null) {
            CMS.debug("setupDBUser(): failed to fetch subsystem cert");
            throw new EBaseException("setupDBUser(): failed to fetch subsystem cert");
        }

        IUser user = system.createUser(DBUSER);
        user.setFullName(DBUSER);
        user.setEmail("");
        user.setPassword("");
        user.setUserType("agentType");
        user.setState("1");
        user.setPhone("");
        X509CertImpl[] certs = new X509CertImpl[1];
        certs[0] = new X509CertImpl(CMS.AtoB(b64));
        user.setX509Certificates(certs);
        system.addUser(user);
        CMS.debug("setupDBUser(): successfully added the user");
        system.addUserCert(user);
        CMS.debug("setupDBUser(): successfully add the user certificate");

        // set subject dn
        system.addCertSubjectDN(user);

        // remove old db users
        CMS.debug("Removing seeAlso from old dbusers");
        removeOldDBUsers(certs[0].getSubjectDN().toString());
    }

    public static void addProfilesToTPSUser(String adminID) throws EUsrGrpException, LDAPException {
        CMS.debug("Adding all profiles to TPS admin user");
        IUGSubsystem system = (IUGSubsystem) CMS.getSubsystem(IUGSubsystem.ID);
        IUser user = system.getUser(adminID);

        List<String> profiles = new ArrayList<String>();
        profiles.add(UserService.ALL_PROFILES);

        user.setTpsProfiles(profiles);
        system.modifyUser(user);
    }

    public static void registerUser(URI secdomainURI, URI targetURI, String targetType) throws Exception {
        IConfigStore cs = CMS.getConfigStore();
        String csType = cs.getString("cs.type");
        String uid = csType.toUpperCase() + "-" + cs.getString("machineName", "")
                + "-" + cs.getString("service.securePort", "");
        String sessionId = CMS.getConfigSDSessionId();
        String subsystemName = cs.getString("preop.subsystem.name");

        String content = "uid=" + uid +
                "&xmlOutput=true" +
                "&sessionID=" + sessionId +
                "&auth_hostname=" + secdomainURI.getHost() +
                "&auth_port=" + secdomainURI.getPort() +
                "&certificate=" + URLEncoder.encode(getSubsystemCert(), "UTF-8") +
                "&name=" + subsystemName;

        String targetURL = "/" + targetType + "/admin/" + targetType + "/registerUser";

        String response = getHttpResponse(
                targetURI.getHost(),
                targetURI.getPort(),
                true,
                targetURL,
                content, null, null);

        if (response == null || response.equals("")) {
            CMS.debug("registerUser: response is empty or null.");
            throw new IOException("The server " + targetURI + "is not available");
        } else {
            ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
            XMLObject parser = new XMLObject(bis);

            String status = parser.getValue("Status");
            CMS.debug("registerUser: status=" + status);

            if (status.equals(SUCCESS)) {
                CMS.debug("registerUser: Successfully added user " + uid + " to " + targetURI +
                          " using " + targetURL);
            } else if (status.equals(AUTH_FAILURE)) {
                throw new EAuthException(AUTH_FAILURE);
            } else {
                String error = parser.getValue("Error");
                throw new IOException(error);
            }
        }
    }

    public static void exportTransportCert(URI secdomainURI, URI targetURI, String transportCert) throws Exception {
        IConfigStore cs = CMS.getConfigStore();
        String name = "transportCert-" + cs.getString("machineName", "")
                + "-" + cs.getString("service.securePort", "");
        String sessionId = CMS.getConfigSDSessionId();

        String content = "name=" + name +
                "&xmlOutput=true" +
                "&sessionID=" + sessionId +
                "&auth_hostname=" + secdomainURI.getHost() +
                "&auth_port=" + secdomainURI.getPort() +
                "&certificate=" + URLEncoder.encode(transportCert, "UTF-8");

        String targetURL = "/tks/admin/tks/importTransportCert";

        String response = getHttpResponse(
                targetURI.getHost(),
                targetURI.getPort(),
                true,
                targetURL,
                content, null, null);

        if (response == null || response.equals("")) {
            CMS.debug("exportTransportCert: response is empty or null.");
            throw new IOException("The server " + targetURI + "is not available");
        } else {
            ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
            XMLObject parser = new XMLObject(bis);

            String status = parser.getValue("Status");
            CMS.debug("exportTransportCert: status=" + status);

            if (status.equals(SUCCESS)) {
                CMS.debug("exportTransportCert: Successfully added transport cert to " + targetURI);
            } else if (status.equals(AUTH_FAILURE)) {
                throw new EAuthException(AUTH_FAILURE);
            } else {
                String error = parser.getValue("Error");
                throw new IOException(error);
            }
        }
    }

    public static void removeOldDBUsers(String subjectDN) throws EBaseException, LDAPException {
        IUGSubsystem system = (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));
        IConfigStore cs = CMS.getConfigStore();
        String userbasedn = "ou=people, " + cs.getString("internaldb.basedn");
        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = CMS.getLdapBoundConnFactory();
        dbFactory.init(dbCfg);
        LDAPConnection conn = dbFactory.getConn();

        String filter = "(&(seeAlso=" + LDAPUtil.escapeFilter(subjectDN) + ")(!(uid=" + DBUSER + ")))";
        String[] attrs = null;
        LDAPSearchResults res = conn.search(userbasedn, LDAPConnection.SCOPE_SUB, filter,
                attrs, false);
        if (res != null) {
            while (res.hasMoreElements()) {
                String uid = (String) res.next().getAttribute("uid").getStringValues().nextElement();
                IUser user = system.getUser(uid);
                CMS.debug("removeOldDUsers: Removing seeAlso from " + uid);
                system.removeCertSubjectDN(user);
            }
        }
    }

    public static String getSubsystemCert() throws EBaseException, NotInitializedException, ObjectNotFoundException,
            TokenException, CertificateEncodingException, IOException {
        IConfigStore cs = CMS.getConfigStore();
        String nickname = cs.getString("preop.cert.subsystem.nickname", "");
        String tokenname = cs.getString("preop.module.token", "");

        if (!tokenname.equals("internal") && !tokenname.equals("Internal Key Storage Token")
                && !tokenname.equals("")) {
            nickname = tokenname + ":" + nickname;
        }

        CMS.debug("DonePanel getSubsystemCert: nickname=" + nickname);

        CryptoManager cm = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate cert = cm.findCertByNickname(nickname);
        if (cert == null) {
            CMS.debug("DonePanel getSubsystemCert: subsystem cert is null");
            return null;
        }
        byte[] bytes = cert.getEncoded();
        String s = CryptoUtil.normalizeCertStr(CryptoUtil.base64Encode(bytes));
        return s;
    }

    public static void updateCAConnInfo(URI caUri, String subsystemNick) {
        IConfigStore cs = CMS.getConfigStore();

        cs.putString("preop.cainfo.select", caUri.toString());
        cs.putString("conn.ca1.clientNickname", subsystemNick);
        cs.putString("conn.ca1.hostport", caUri.getHost() + ":" + caUri.getPort());
        cs.putString("conn.ca1.hostagentport", caUri.getHost() + ":" + caUri.getPort());
        cs.putString("conn.ca1.hostadminport", caUri.getHost() + ":" + caUri.getPort());
    }

    public static void updateKRAConnInfo(boolean enableServerSideKeyGen, URI kraUri, String subsystemNick) {
        IConfigStore cs = CMS.getConfigStore();
        if (enableServerSideKeyGen) {
            cs.putString("preop.krainfo.select", kraUri.toString());
            cs.putString("conn.drm1.clientNickname", subsystemNick);
            cs.putString("conn.drm1.hostport", kraUri.getHost() + ":" + kraUri.getPort());
            cs.putString("conn.tks1.serverKeygen", "true");
            cs.putString("op.enroll.userKey.keyGen.encryption.serverKeygen.enable", "true");
            cs.putString("op.enroll.userKeyTemporary.keyGen.encryption.serverKeygen.enable", "true");
            cs.putString("op.enroll.soKey.keyGen.encryption.serverKeygen.enable", "true");
            cs.putString("op.enroll.soKeyTemporary.keyGen.encryption.serverKeygen.enable", "true");
        } else {
            // no keygen
            cs.putString("conn.tks1.serverKeygen", "false");
            cs.putString("op.enroll.userKey.keyGen.encryption.serverKeygen.enable", "false");
            cs.putString("op.enroll.userKeyTemporary.keyGen.encryption.serverKeygen.enable", "false");
            cs.putString("op.enroll.userKey.keyGen.encryption.recovery.destroyed.scheme", "GenerateNewKey");
            cs.putString("op.enroll.userKeyTemporary.keyGen.encryption.recovery.onHold.scheme", "GenerateNewKey");
            cs.putString("conn.drm1.clientNickname", "");
            cs.putString("conn.drm1.hostport", "");
            cs.putString("op.enroll.soKey.keyGen.encryption.serverKeygen.enable", "false");
            cs.putString("op.enroll.soKeyTemporary.keyGen.encryption.serverKeygen.enable", "false");
            cs.putString("op.enroll.soKey.keyGen.encryption.recovery.destroyed.scheme", "GenerateNewKey");
            cs.putString("op.enroll.soKeyTemporary.keyGen.encryption.recovery.onHold.scheme", "GenerateNewKey");
        }
    }

    public static void updateTKSConnInfo(URI tksUri, String subsystemNick) {
        IConfigStore cs = CMS.getConfigStore();

        cs.putString("preop.tksinfo.select", tksUri.toString());
        cs.putString("conn.tks1.clientNickname", subsystemNick);
        cs.putString("conn.tks1.hostport", tksUri.getHost() + ":" + tksUri.getPort());
    }

    public static void updateAuthdbInfo(String basedn, String host, String port, String secureConn) {
        IConfigStore cs = CMS.getConfigStore();

        cs.putString("auths.instance.ldap1.ldap.basedn", basedn);
        cs.putString("auths.instance.ldap1.ldap.ldapconn.host", host);
        cs.putString("auths.instance.ldap1.ldap.ldapconn.port", port);
        cs.putString("auths.instance.ldap1.ldap.ldapconn.secureConn", secureConn);
    }


    public static void updateNextRanges() throws EBaseException, LDAPException {
        IConfigStore cs = CMS.getConfigStore();

        String endRequestNumStr = cs.getString("dbs.endRequestNumber", "");
        String endSerialNumStr = cs.getString("dbs.endSerialNumber", "");
        String type = cs.getString("cs.type");
        String basedn = cs.getString("internaldb.basedn");

        BigInteger endRequestNum = new BigInteger(endRequestNumStr);
        BigInteger endSerialNum = new BigInteger(endSerialNumStr);
        BigInteger oneNum = new BigInteger("1");

        // update global next range entries
        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = CMS.getLdapBoundConnFactory();
        dbFactory.init(dbCfg);
        LDAPConnection conn = dbFactory.getConn();

        String serialdn = "";
        if (type.equals("CA")) {
            serialdn = "ou=certificateRepository,ou=" + LDAPUtil.escapeRDNValue(type.toLowerCase()) + "," + basedn;
        } else {
            serialdn = "ou=keyRepository,ou=" + LDAPUtil.escapeRDNValue(type.toLowerCase()) + "," + basedn;
        }
        LDAPAttribute attrSerialNextRange =
                new LDAPAttribute("nextRange", endSerialNum.add(oneNum).toString());
        LDAPModification serialmod = new LDAPModification(LDAPModification.REPLACE, attrSerialNextRange);
        conn.modify(serialdn, serialmod);

        String requestdn = "ou=" + LDAPUtil.escapeRDNValue(type.toLowerCase()) + ",ou=requests," + basedn;
        LDAPAttribute attrRequestNextRange =
                new LDAPAttribute("nextRange", endRequestNum.add(oneNum).toString());
        LDAPModification requestmod = new LDAPModification(LDAPModification.REPLACE, attrRequestNextRange);
        conn.modify(requestdn, requestmod);

        conn.disconnect();
    }

    /**
     * save variables needed for cloning and remove preops
     * @throws EBaseException
     */
    public static void removePreopConfigEntries() throws EBaseException {
        IConfigStore cs = CMS.getConfigStore();
        String type = cs.getString("cs.type");
        String list = cs.getString("preop.cert.list", "");
        StringTokenizer st = new StringTokenizer(list, ",");

        while (st.hasMoreTokens()) {
            String ss = st.nextToken();
            if (ss.equals("sslserver"))
                continue;
            cs.putString("cloning." + ss + ".nickname", cs.getString("preop.cert." + ss + ".nickname", ""));
            cs.putString("cloning." + ss + ".dn", cs.getString("preop.cert." + ss + ".dn", ""));
            cs.putString("cloning." + ss + ".keytype", cs.getString("preop.cert." + ss + ".keytype", ""));
            cs.putString("cloning." + ss + ".keyalgorithm", cs.getString("preop.cert." + ss + ".keyalgorithm", ""));
            cs.putString("cloning." + ss + ".privkey.id", cs.getString("preop.cert." + ss + ".privkey.id", ""));
            cs.putString("cloning." + ss + ".pubkey.exponent",
                    cs.getString("preop.cert." + ss + ".pubkey.exponent", ""));
            cs.putString("cloning." + ss + ".pubkey.modulus",
                    cs.getString("preop.cert." + ss + ".pubkey.modulus", ""));
            cs.putString("cloning." + ss + ".pubkey.encoded",
                    cs.getString("preop.cert." + ss + ".pubkey.encoded", ""));
        }
        cs.putString("cloning.module.token", cs.getString("preop.module.token", ""));
        cs.putString("cloning.list", list);

        // more cloning variables needed for non-ca clones

        if (!type.equals("CA")) {
            String val = cs.getString("preop.ca.hostname", "");
            if (val.length() > 0)
                cs.putString("cloning.ca.hostname", val);

            val = cs.getString("preop.ca.httpport", "");
            if (val.length() != 0)
                cs.putString("cloning.ca.httpport", val);

            val = cs.getString("preop.ca.httpsport", "");
            if (val.length() != 0)
                cs.putString("cloning.ca.httpsport", val);

            val = cs.getString("preop.ca.list", "");
            if (val.length() != 0)
                cs.putString("cloning.ca.list", val);

            val = cs.getString("preop.ca.pkcs7", "");
            if (val.length() != 0)
                cs.putString("cloning.ca.pkcs7", val);

            val = cs.getString("preop.ca.type", "");
            if (val.length() != 0)
                cs.putString("cloning.ca.type", val);
        }

        // save EC type for sslserver cert (if present)
        cs.putString("jss.ssl.sslserver.ectype", cs.getString("preop.cert.sslserver.ec.type", "ECDHE"));

        cs.removeSubStore("preop");
        cs.commit(false);
    }
}
