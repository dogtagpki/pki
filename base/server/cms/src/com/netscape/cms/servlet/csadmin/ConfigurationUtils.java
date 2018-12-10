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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.lang.StringUtils;
import org.apache.velocity.context.Context;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NicknameConflictException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.UserCertConflictException;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Store;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.CertBag;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.Attribute;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback.ValidityStatus;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import com.netscape.certsrv.account.AccountClient;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.PKIConnection;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.profile.CertInfoProfile;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.security.ISigningUnit;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.certsrv.system.TPSConnectorClient;
import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.certsrv.user.UserResource;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.password.IPasswordStore;
import org.mozilla.jss.netscape.security.util.Utils;
import com.netscape.cmsutil.xml.XMLObject;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS12;
import org.mozilla.jss.netscape.security.pkcs.PKCS12Util;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

/**
 * Utility class for functions to be used by the RESTful installer.
 *
 * @author alee
 *
 */
public class ConfigurationUtils {

    public final static Logger logger = LoggerFactory.getLogger(ConfigurationUtils.class);

    private static final String PCERT_PREFIX = "preop.cert.";
    public static String SUCCESS = "0";
    public static String FAILURE = "1";
    public static String AUTH_FAILURE = "2";
    public static final BigInteger BIG_ZERO = new BigInteger("0");
    public static final Long MINUS_ONE = Long.valueOf(-1);
    public static final String DBUSER = "pkidbuser";

    public static ConfigCertApprovalCallback certApprovalCallback = new ConfigCertApprovalCallback();

    public static String get(String hostname, int port, boolean secure,
            String path, String clientnickname,
            SSLCertificateApprovalCallback certApprovalCallback)
            throws Exception {

        String protocol = secure ? "https" : "http";
        ClientConfig config = new ClientConfig();
        config.setServerURL(protocol + "://" + hostname + ":" + port);
        config.setCertNickname(clientnickname);

        logger.info("ConfigurationUtils: GET " + config.getServerURL() + path);
        PKIConnection connection = new PKIConnection(config);
        if (certApprovalCallback == null) certApprovalCallback = ConfigurationUtils.certApprovalCallback;
        connection.setCallback(certApprovalCallback);
        return connection.get(path, String.class);
    }

    public static String post(String hostname, int port, boolean secure,
            String path, MultivaluedMap<String, String> content, String clientnickname,
            SSLCertificateApprovalCallback certApprovalCallback)
            throws Exception {

        String protocol = secure ? "https" : "http";
        ClientConfig config = new ClientConfig();
        config.setServerURL(protocol + "://" + hostname + ":" + port);
        config.setCertNickname(clientnickname);

        logger.info("ConfigurationUtils: POST " + config.getServerURL() + path);
        PKIConnection connection = new PKIConnection(config);
        if (certApprovalCallback == null) certApprovalCallback = ConfigurationUtils.certApprovalCallback;
        connection.setCallback(certApprovalCallback);
        return connection.post(path, content);
    }

    public static String getCertChain(String host, int port, String serverPath)
            throws Exception {

        String url = "https://" + host + ":" + port + serverPath;
        logger.debug("ConfigurationUtils: Getting cert chain from " + url);

        ConfigCertApprovalCallback certApprovalCallback = new ConfigCertApprovalCallback();
        // Ignore untrusted/unknown issuer to get cert chain.
        certApprovalCallback.ignoreError(ValidityStatus.UNTRUSTED_ISSUER);
        certApprovalCallback.ignoreError(ValidityStatus.UNKNOWN_ISSUER);

        String c = get(host, port, true, serverPath, null, certApprovalCallback);

        if (c == null) {
            throw new IOException("Unable to get cert chain from " + url);
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());

        XMLObject parser;
        try {
            parser = new XMLObject(bis);
        } catch (SAXException e) {
            logger.error("Response: " + c);
            logger.error("ConfigurationUtils: Unable to parse XML response: " + e, e);
            throw e;
        }

        return parser.getValue("ChainBase64");
    }

    public static void importCertChain(String certchain, String tag)
            throws Exception {

        logger.debug("ConfigurationUtils: Importing cert chain for " + tag);

        if (certchain == null || certchain.length() <= 0) {
            throw new IOException("Missing cert chain");
        }

        certchain = CryptoUtil.normalizeCertStr(certchain);

        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop." + tag + ".pkcs7", certchain);

        // separate individual certs in chain for display
        byte[] decoded = CryptoUtil.base64Decode(certchain);
        java.security.cert.X509Certificate[] b_certchain = CryptoUtil.getX509CertificateFromPKCS7(decoded);

        int size;

        if (b_certchain == null) {
            logger.debug("ConfigurationUtils: no certificate chain");

            size = 0;

        } else {
            logger.debug("ConfigurationUtils: certificate chain:");
            for (java.security.cert.X509Certificate cert : b_certchain) {
                logger.debug("ConfigurationUtils: - " + cert.getSubjectDN());
            }

            size = b_certchain.length;
        }

        cs.putInteger("preop." + tag + ".certchain.size", size);
        for (int i = 0; i < size; i++) {
            byte[] bb = b_certchain[i].getEncoded();
            cs.putString("preop." + tag + ".certchain." + i,
                    CryptoUtil.normalizeCertStr(CryptoUtil.base64Encode(bb)));
        }

        cs.commit(false);

        byte[] bytes = CryptoUtil.base64Decode(certchain);
        CryptoUtil.importCertificateChain(bytes);
    }

    public static String getInstallToken(String sdhost, int sdport, String user, String passwd) throws Exception {
        IConfigStore cs = CMS.getConfigStore();

        String csType = cs.getString("cs.type");

        ClientConfig config = new ClientConfig();
        config.setServerURL("https://" + sdhost + ":" + sdport);
        config.setUsername(user);
        config.setPassword(passwd);

        PKIClient client = new PKIClient(config, null);

        // Ignore the "UNTRUSTED_ISSUER" validity status
        // during PKI instance creation since we are
        // utilizing an untrusted temporary CA certificate.
        client.addIgnoredCertStatus(SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER);

        // Ignore the "CA_CERT_INVALID" validity status
        // during PKI instance creation since we are
        // utilizing an untrusted temporary CA certificate.
        client.addIgnoredCertStatus(SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID);

        AccountClient accountClient = new AccountClient(client, "ca");
        SecurityDomainClient sdClient = new SecurityDomainClient(client, "ca");

        try {
            logger.debug("Getting install token");
            accountClient.login();
            InstallToken token = sdClient.getInstallToken(sdhost, csType);
            accountClient.logout();
            return token.getToken();
        } catch (PKIException e) {
            if (e.getCode() == Response.Status.NOT_FOUND.getStatusCode()) {
                // try the old servlet
                logger.warn("Getting old cookie");
                String tokenString = getOldCookie(sdhost, sdport, user, passwd);
                logger.debug("Token: " + tokenString);
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

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("uid", user);
        content.putSingle("pwd", passwd);
        content.putSingle("url", subca_url);

        String body = post(sdhost, sdport, true, "/ca/admin/ca/getCookie",
                content, null, null);
        logger.debug("ConfigurationUtils: response: " + body);

        return getContentValue(body, "header.session_id");
    }

    public static String getContentValue(String body, String header) {

        logger.debug("ConfigurationUtils: searching for " + header);

        StringTokenizer st = new StringTokenizer(body, "\n");

        while (st.hasMoreTokens()) {
            String line = st.nextToken();
            // format for line assumed to be name="value";

            int eqPos = line.indexOf('=');
            if (eqPos != -1) {
                String name = line.substring(0, eqPos).trim();
                String tempval = line.substring(eqPos + 1).trim();
                String value = tempval.replaceAll("(^\")|(\";$)", "");

                if (name.equals(header)) {
                    return value;
                }
            }
        }
        return null;
    }

    public static String getDomainXML(String hostname, int https_admin_port, boolean https)
            throws Exception {

        logger.debug("ConfigurationUtils: getting domain info");

        String c = get(hostname, https_admin_port, https, "/ca/admin/ca/getDomainXML", null, null);

        if (c != null) {

            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser = null;

            parser = new XMLObject(bis);
            String status = parser.getValue("Status");
            logger.debug("ConfigurationUtils: status: " + status);

            if (status.equals(SUCCESS)) {
                String domainInfo = parser.getValue("DomainInfo");
                logger.debug("ConfigurationUtils: domain info: " + domainInfo);
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
        logger.debug("len is " + len);
        for (int i = 0; i < len; i++) {
            String hostname = parser.getValuesFromContainer(nodeList.item(i), "Host").elementAt(0);
            String admin_port = parser.getValuesFromContainer(nodeList.item(i), "SecureAdminPort").elementAt(0);
            logger.debug("hostname: <" + hostname + ">");
            logger.debug("admin_port: <" + admin_port + ">");

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
            throws Exception {
        Vector<String> v = new Vector<String>();

        String hostname = config.getString("securitydomain.host");
        int httpsadminport = config.getInteger("securitydomain.httpsadminport");

        logger.debug("getUrlListFromSecurityDomain(): Getting domain.xml from CA...");
        String c = getDomainXML(hostname, httpsadminport, true);

        logger.debug("getUrlListFromSecurityDomain: Getting " + portType + " from Security Domain ...");
        if (!portType.equals("UnSecurePort") &&
                !portType.equals("SecureAgentPort") &&
                !portType.equals("SecurePort") &&
                !portType.equals("SecureAdminPort")) {
            logger.debug("getUrlListFromSecurityDomain:  " +
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

        logger.debug("Len " + len);
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
            throws Exception {

        IConfigStore config = CMS.getConfigStore();
        String cstype = "";

        cstype = config.getString("cs.type", "");

        cstype = cstype.toLowerCase();

        String session_id = CMS.getConfigSDSessionId();
        String master_hostname = config.getString("preop.master.hostname", "");
        int master_port = config.getInteger("preop.master.httpsadminport", -1);
        int master_ee_port = config.getInteger("preop.master.httpsport", -1);

        if (cstype.equals("ca") || cstype.equals("kra")) {
            MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
            content.putSingle("type", "request");
            content.putSingle("xmlOutput", "true");
            content.putSingle("sessionID", session_id);
            updateNumberRange(master_hostname, master_ee_port, master_port, true, content, "request");

            content = new MultivaluedHashMap<String, String>();
            content.putSingle("type", "serialNo");
            content.putSingle("xmlOutput", "true");
            content.putSingle("sessionID", session_id);
            updateNumberRange(master_hostname, master_ee_port, master_port, true, content, "serialNo");

            content = new MultivaluedHashMap<String, String>();
            content.putSingle("type", "replicaId");
            content.putSingle("xmlOutput", "true");
            content.putSingle("sessionID", session_id);
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

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("op", "get");
        content.putSingle("names", "cloning.module.token,cloning.token,instanceId,"
                + "internaldb.basedn,internaldb.ldapauth.password,internaldb.replication.password" + c1);
        content.putSingle("substores", s1.toString());
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", session_id);

        boolean success = updateConfigEntries(master_hostname, master_port, true,
                "/" + cstype + "/admin/" + cstype + "/getConfigEntries", content, config);
        if (!success) {
            throw new IOException("Failed to get configuration entries from the master");
        }
        config.putString("preop.clone.configuration", "true");

        config.commit(false);

    }

    public static void updateNumberRange(String hostname, int eePort, int adminPort, boolean https,
            MultivaluedMap<String, String> content, String type) throws Exception {

        logger.debug("updateNumberRange start host=" + hostname + " adminPort=" + adminPort + " eePort=" + eePort);
        logger.debug("updateNumberRange content: " + content);

        IConfigStore cs = CMS.getConfigStore();

        String cstype = cs.getString("cs.type", "");
        cstype = cstype.toLowerCase();

        String serverPath = "/" + cstype + "/admin/" + cstype + "/updateNumberRange";
        String c = null;
        XMLObject parser = null;
        try {
            c = post(hostname, adminPort, https, serverPath, content, null, null);
            if (c == null || c.equals("")) {
                logger.debug("updateNumberRange: content is null.");
                throw new IOException("The server you want to contact is not available");
            }

            logger.debug("content from admin interface =" + c);
            // when the admin servlet is unavailable, we return a badly formatted error page
            // in that case, this will throw an exception and be passed into the catch block.
            parser = new XMLObject(new ByteArrayInputStream(c.getBytes()));

        } catch (Exception e) {
            // for backward compatibility, try the old ee interface too
            logger.warn("updateNumberRange: Failed to contact master using admin port" + e);
            logger.warn("updateNumberRange: Attempting to contact master using EE port");
            serverPath = "/" + cstype + "/ee/" + cstype + "/updateNumberRange";
            c = post(hostname, eePort, https, serverPath, content, null, null);
            if (c == null || c.equals("")) {
                logger.error("updateNumberRange: content is null.");
                throw new IOException("The server you want to contact is not available", e);
            }
            logger.info("content from ee interface =" + c);
            parser = new XMLObject(new ByteArrayInputStream(c.getBytes()));
        }

        String status = parser.getValue("Status");

        logger.debug("updateNumberRange(): status=" + status);
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
            String servlet, MultivaluedMap<String, String> content, IConfigStore config)
            throws Exception {
        logger.debug("updateConfigEntries start");
        String c = post(hostname, port, https, servlet, content, null, null);

        if (c != null) {

            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser = null;

            parser = new XMLObject(bis);

            String status = parser.getValue("Status");
            logger.debug("updateConfigEntries: status=" + status);

            if (status.equals(SUCCESS)) {
                String cstype = "";

                cstype = config.getString("cs.type", "");

                logger.debug("Master's configuration:");
                Document doc = parser.getDocument();
                NodeList list = doc.getElementsByTagName("name");
                int len = list.getLength();
                for (int i = 0; i < len; i++) {
                    Node n = list.item(i);
                    NodeList nn = n.getChildNodes();
                    String name = nn.item(0).getNodeValue();
                    logger.debug(" - " + name);

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
                    IPasswordStore psStore = CMS.getPasswordStore();
                    psStore.putPassword("master_internaldb", master_pwd);
                    psStore.commit();
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

    public static void restoreCertsFromP12(String p12File, String p12Pass) throws Exception {

        // TODO: The PKCS #12 file is already imported in security_database.py.
        // This method should be removed.

        byte b[] = new byte[1000000];
        FileInputStream fis = new FileInputStream(p12File);
        while (fis.available() > 0)
            fis.read(b);
        fis.close();

        ByteArrayInputStream bis = new ByteArrayInputStream(b);
        StringBuffer reason = new StringBuffer();
        Password password = new Password(p12Pass.toCharArray());

        try {

            PFX pfx = (PFX) (new PFX.Template()).decode(bis);
            boolean verifypfx = pfx.verifyAuthSafes(password, reason);

            if (!verifypfx) {
                throw new IOException("PKCS #12 password is incorrect");
            }

            AuthenticatedSafes safes = pfx.getAuthSafes();
            Vector<Vector<Object>> pkeyinfo_collection = new Vector<Vector<Object>>();
            Vector<Vector<Object>> cert_collection = new Vector<Vector<Object>>();

            logger.debug("Importing PKCS #12 data");

            for (int i = 0; i < safes.getSize(); i++) {

                logger.debug("- Safe #" + i + ":");
                SEQUENCE scontent = safes.getSafeContentsAt(null, i);

                for (int j = 0; j < scontent.size(); j++) {

                    SafeBag bag = (SafeBag) scontent.elementAt(j);
                    OBJECT_IDENTIFIER oid = bag.getBagType();

                    if (oid.equals(SafeBag.PKCS8_SHROUDED_KEY_BAG)) {

                        logger.debug("  - Bag #" + j + ": key");
                        byte[] epki = bag.getBagContent().getEncoded();

                        SET bagAttrs = bag.getBagAttributes();
                        String subjectDN = null;

                        for (int k = 0; k < bagAttrs.size(); k++) {

                            Attribute attrs = (Attribute) bagAttrs.elementAt(k);
                            OBJECT_IDENTIFIER aoid = attrs.getType();

                            if (aoid.equals(SafeBag.FRIENDLY_NAME)) {
                                SET val = attrs.getValues();
                                ANY ss = (ANY) val.elementAt(0);

                                ByteArrayInputStream bbis = new ByteArrayInputStream(ss.getEncoded());
                                BMPString sss = (BMPString) new BMPString.Template().decode(bbis);
                                subjectDN = sss.toString();
                                logger.debug("    Subject DN: " + subjectDN);
                                break;
                            }
                        }

                        // pkeyinfo_v stores EncryptedPrivateKeyInfo
                        // (byte[]) and subject DN (String)
                        Vector<Object> pkeyinfo_v = new Vector<Object>();
                        pkeyinfo_v.addElement(epki);
                        if (subjectDN != null)
                            pkeyinfo_v.addElement(subjectDN);

                        pkeyinfo_collection.addElement(pkeyinfo_v);

                    } else if (oid.equals(SafeBag.CERT_BAG)) {

                        logger.debug("  - Bag #" + j + ": certificate");
                        CertBag cbag = (CertBag) bag.getInterpretedBagContent();
                        OCTET_STRING str = (OCTET_STRING) cbag.getInterpretedCert();
                        byte[] x509cert = str.toByteArray();

                        SET bagAttrs = bag.getBagAttributes();
                        String nickname = null;

                        if (bagAttrs != null) {

                            for (int k = 0; k < bagAttrs.size(); k++) {

                                Attribute attrs = (Attribute) bagAttrs.elementAt(k);
                                OBJECT_IDENTIFIER aoid = attrs.getType();

                                if (aoid.equals(SafeBag.FRIENDLY_NAME)) {
                                    SET val = attrs.getValues();
                                    ANY ss = (ANY) val.elementAt(0);

                                    ByteArrayInputStream bbis = new ByteArrayInputStream(ss.getEncoded());
                                    BMPString sss = (BMPString) (new BMPString.Template()).decode(bbis);
                                    nickname = sss.toString();
                                    logger.debug("    Nickname: " + nickname);
                                    break;
                                }
                            }
                        }

                        X509CertImpl certImpl = new X509CertImpl(x509cert);
                        logger.debug("    Serial number: " + certImpl.getSerialNumber());

                        try {
                            certImpl.checkValidity();
                            logger.debug("    Status: valid");

                        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                            logger.debug("    Status: " + e);
                            continue;
                        }

                        // cert_v stores certificate (byte[]) and nickname (String)
                        Vector<Object> cert_v = new Vector<Object>();
                        cert_v.addElement(x509cert);
                        if (nickname != null)
                            cert_v.addElement(nickname);

                        cert_collection.addElement(cert_v);
                    }
                }
            }

            importKeyCert(password, pkeyinfo_collection, cert_collection);
        } catch (Exception e) {
            throw e;
        } finally {
            if (password != null) {
                password.clear();
            }
        }
    }

    public static void verifySystemCertificates() throws Exception {

        IConfigStore cs = CMS.getConfigStore();

        CryptoManager cm = CryptoManager.getInstance();
        String certList = cs.getString("preop.cert.list");
        String cstype = cs.getString("cs.type").toLowerCase();
        StringTokenizer st = new StringTokenizer(certList, ",");

        while (st.hasMoreTokens()) {
            String tag = st.nextToken();
            if (tag.equals("sslserver"))
                continue;

            String tokenname = cs.getString("preop.module.token", "");
            CryptoUtil.getKeyStorageToken(tokenname); // throw exception if token doesn't exist

            String name1 = "preop.master." + tag + ".nickname";
            String nickname = cs.getString(name1, "");
            if (!CryptoUtil.isInternalToken(tokenname))
                nickname = tokenname + ":" + nickname;

            logger.debug("ConfigurationUtils.verifySystemCertificates(): checking certificate " + nickname);

            // TODO : remove this when we eliminate the extraneous nicknames
            // needed for self tests
            cs.putString(cstype + ".cert." + tag + ".nickname", nickname);

            try {
                cm.findCertByNickname(nickname);

            } catch (ObjectNotFoundException e) {
                throw new Exception("Missing system certificate: " + nickname, e);
            }
        }
    }

    public static void importKeyCert(
            Password password,
            Vector<Vector<Object>> pkeyinfo_collection,
            Vector<Vector<Object>> cert_collection
            ) throws Exception {

        logger.debug("ConfigurationUtils.importKeyCert()");
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        CryptoStore store = token.getCryptoStore();

        deleteExistingCerts();

        ArrayList<String> masterList = getMasterCertKeyList();

        logger.debug("Importing new keys:");
        for (int i = 0; i < pkeyinfo_collection.size(); i++) {
            Vector<Object> pkeyinfo_v = pkeyinfo_collection.elementAt(i);
            byte[] epki = (byte[]) pkeyinfo_v.elementAt(0);
            String nickname = (String) pkeyinfo_v.elementAt(1);
            logger.debug("- Key: " + nickname);

            if (!importRequired(masterList, nickname)) {
                logger.debug("  Key not in master list, ignore key");
                continue;
            }

            logger.debug("  Find cert with subject DN " + nickname);
            // TODO: use better mechanism to find the cert
            byte[] x509cert = getX509Cert(nickname, cert_collection);
            if (x509cert == null) {
                logger.debug("  Certificate is missing/removed, ignore key");
                continue;
            }

            X509Certificate cert = cm.importCACertPackage(x509cert);
            logger.debug("  Imported cert " + cert.getSerialNumber());

            // get public key
            PublicKey publicKey = cert.getPublicKey();

            // delete the cert again
            try {
                store.deleteCert(cert);
            } catch (NoSuchItemOnTokenException e) {
                // this is OK
            }

            try {
                // first true without BMPString-encoding the passphrase.
                store.importEncryptedPrivateKeyInfo(
                    null, password, nickname, publicKey, epki);
            } catch (Exception e) {
                // if that failed, try again with BMPString-encoded
                // passphrase.  This is required for PKCS #12 PBE
                // schemes and for PKCS #12 files using PBES2 generated
                // by NSS < 3.31
                store.importEncryptedPrivateKeyInfo(
                    new PasswordConverter(), password, nickname, publicKey, epki);
            }
        }

        logger.debug("Importing new certificates:");
        for (int i = 0; i < cert_collection.size(); i++) {

            Vector<Object> cert_v = cert_collection.elementAt(i);
            byte[] cert = (byte[]) cert_v.elementAt(0);

            if (cert_v.size() > 1) {
                String name = (String) cert_v.elementAt(1);
                logger.debug("- Certificate: " + name);

                if (!masterList.contains(name)) {
                    logger.debug("  Certificate not in master list, ignore certificate");
                    continue;
                }

                // we need to delete the trusted CA certificate if it is
                // the same as the ca signing certificate
                boolean isCASigningCert = isCASigningCert(name);
                logger.debug("  CA signing cert: " + isCASigningCert);

                if (isCASigningCert) {
                    X509Certificate certchain = getX509CertFromToken(cert);
                    if (certchain != null) {
                        if (store instanceof PK11Store) {
                            try {
                                logger.debug("  Deleting trusted CA cert");
                                PK11Store pk11store = (PK11Store) store;
                                pk11store.deleteCertOnly(certchain);
                            } catch (Exception e) {
                                logger.warn("Unable to delete trusted CA cert: " + e);
                            }
                        }
                    }
                }

                X509Certificate xcert = cm.importUserCACertPackage(cert, name);
                logger.debug("  Imported cert " + xcert.getSerialNumber());
                InternalCertificate icert = (InternalCertificate) xcert;

                if (isCASigningCert) {
                    // set trust flags to CT,C,C
                    icert.setSSLTrust(InternalCertificate.TRUSTED_CA
                            | InternalCertificate.TRUSTED_CLIENT_CA
                            | InternalCertificate.VALID_CA);
                    icert.setEmailTrust(InternalCertificate.TRUSTED_CA
                            | InternalCertificate.VALID_CA);
                    icert.setObjectSigningTrust(InternalCertificate.TRUSTED_CA
                            | InternalCertificate.VALID_CA);

                } else if (isAuditSigningCert(name)) {
                    // set trust flags to u,u,Pu
                    icert.setObjectSigningTrust(InternalCertificate.USER
                            | InternalCertificate.VALID_PEER
                            | InternalCertificate.TRUSTED_PEER);
                }

            } else {
                cm.importCACertPackage(cert);
            }
        }
    }

    /* We need to import the audit signing cert and CA signing cert to the soft token in order to
     * correctly set the trust permissions.
     */
    public static void importAndSetCertPermissionsFromHSM() throws EBaseException, NotInitializedException,
            IOException, CertificateEncodingException, NicknameConflictException, UserCertConflictException,
            NoSuchItemOnTokenException, TokenException {

        CryptoManager cm = CryptoManager.getInstance();
        IConfigStore cs = CMS.getConfigStore();

        // nickname has no token prepended to it, so no need to strip
        String nickname = cs.getString("preop.master.audit_signing.nickname");
        String cstype = cs.getString("cs.type", "");
        cstype = cstype.toLowerCase();

        //audit signing cert
        String certStr = cs.getString(cstype + ".audit_signing.cert");
        byte[] cert = CryptoUtil.base64Decode(certStr);
        X509Certificate xcert = cm.importUserCACertPackage(cert, nickname);

        InternalCertificate icert = (InternalCertificate) xcert;
        icert.setObjectSigningTrust(InternalCertificate.USER
                | InternalCertificate.VALID_PEER
                | InternalCertificate.TRUSTED_PEER);

        // ca signing cert
        if (cstype.equals("ca")) {
            // nickname has no token prepended to it, so no need to strip
            nickname = cs.getString("preop.master.signing.nickname");
            certStr = cs.getString(cstype + ".signing.cert");
            cert = CryptoUtil.base64Decode(certStr);
            xcert = cm.importUserCACertPackage(cert, nickname);
            icert = (InternalCertificate) xcert;
            icert.setSSLTrust(InternalCertificate.TRUSTED_CA
                    | InternalCertificate.TRUSTED_CLIENT_CA
                    | InternalCertificate.VALID_CA);
        }
    }

    private static boolean importRequired(ArrayList<String> masterList, String nickname) {
        if (masterList.contains(nickname))
            return true;
        try {
            X500Name xname = new X500Name(nickname);
            for (String key : masterList) {
                try {
                    X500Name xkey = new X500Name(key);
                    if (xkey.equals(xname))
                        return true;
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
            String issuer_p = permcerts[i].getIssuerDN().toString();
            BigInteger serial_p = permcerts[i].getSerialNumber();
            if (issuer_p.equals(issuer_impl) && serial_p.compareTo(serial_impl) == 0) {
                return permcerts[i];
            }
        }
        return null;
    }

    public static boolean isCASigningCert(String name) throws EBaseException {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String nickname = cs.getString("preop.master.signing.nickname");
            logger.debug("Property preop.master.signing.nickname: " + nickname);
            if (nickname.equals(name)) return true;

        } catch (EPropertyNotFound e) {
            logger.warn("Property preop.master.signing.nickname not found -> cert " + name + " is not CA signing cert");
            // nickname may not exist if this is not cloning a CA
        };

        return false;
    }


    public static boolean isAuditSigningCert(String name) throws EPropertyNotFound, EBaseException {
        IConfigStore cs = CMS.getConfigStore();
        String nickname = cs.getString("preop.master.audit_signing.nickname");
        if (nickname.equals(name))
            return true;
        return false;
    }

    public static void deleteExistingCerts() throws NotInitializedException, EBaseException, TokenException {

        logger.debug("Deleting existing certificates:");

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken ct = cm.getInternalKeyStorageToken();
        CryptoStore store = ct.getCryptoStore();

        IConfigStore cs = CMS.getConfigStore();
        String list = cs.getString("preop.cert.list", "");
        StringTokenizer st = new StringTokenizer(list, ",");

        while (st.hasMoreTokens()) {
            String s = st.nextToken();

            if (s.equals("sslserver"))
                continue;

            String name = "preop.master." + s + ".nickname";
            String nickname = cs.getString(name, "");
            logger.debug("- Certificate " + nickname);

            X509Certificate cert;
            try {
                cert = cm.findCertByNickname(nickname);
            } catch (ObjectNotFoundException ee) {
                logger.warn("  Certificate nickname " + nickname + " not found");
                continue;
            }

            try {
                store.deleteCert(cert);
            } catch (NoSuchItemOnTokenException ee) {
                logger.warn("  Certificate object " + nickname + " not found");
            }
        }
    }

    public static ArrayList<String> getMasterCertKeyList() throws EBaseException {
        ArrayList<String> list = new ArrayList<String>();
        IConfigStore cs = CMS.getConfigStore();
        String certList = cs.getString("preop.cert.list", "");
        StringTokenizer st = new StringTokenizer(certList, ",");

        logger.debug("Master certs:");
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
            logger.debug(" - " + name + ": " + dn);
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
            if (LDAPDN.equals(subjectdn.toString(), nickname))
                return b;
        }
        return null;
    }

    public static void releaseConnection(LDAPConnection conn) {
        try {
            if (conn != null)
                conn.disconnect();
        } catch (LDAPException e) {
            logger.warn("releaseConnection: " + e, e);
        }
    }

    public static void enableUSNPlugin() throws IOException, EBaseException {
        IConfigStore cs = CMS.getConfigStore();

        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = new LdapBoundConnFactory("ConfigurationUtils");
        dbFactory.init(dbCfg);
        LDAPConnection conn = dbFactory.getConn();
        try {
            importLDIFS("preop.internaldb.usn.ldif", conn);
        } catch (Exception e) {
            logger.error("Failed to enable USNPlugin: " + e);
            throw new EBaseException("Failed to enable USN plugin: " + e, e);
        } finally {
            releaseConnection(conn);
        }
    }

    public static void populateDB() throws IOException, EBaseException {

        IConfigStore cs = CMS.getConfigStore();
        String baseDN = cs.getString("internaldb.basedn");
        String database = cs.getString("internaldb.database", "");
        String select = cs.getString("preop.subsystem.select", "");
        boolean remove = cs.getBoolean("preop.database.removeData", false);
        boolean createNewDB = cs.getBoolean("preop.database.createNewDB", true);
        boolean setupReplication = cs.getBoolean("preop.database.setupReplication", true);
        boolean reindexData = cs.getBoolean("preop.database.reindexData", false);

        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = new LdapBoundConnFactory("ConfigurationUtils");
        dbFactory.init(dbCfg);
        LDAPConnection conn = dbFactory.getConn();

        try {
            if (createNewDB) {
                // check if base entry already exists
                LDAPEntry baseEntry = getBaseEntry(baseDN, remove, conn);

                // check if mapping entry already exists
                String mappingDN = "cn=\"" + baseDN + "\",cn=mapping tree, cn=config";
                LDAPEntry mappingEntry = getMappingEntry(baseDN, remove, conn, mappingDN);

                // check if the database already exists
                String databaseDN = "cn=" + LDAPUtil.escapeRDNValue(database) +
                        ",cn=ldbm database, cn=plugins, cn=config";
                LDAPEntry databaseEntry = getDatabaseEntry(database, remove, conn, databaseDN);

                // check if database is used by another subtree
                confirmNoConflictingMappingsForDB(baseDN, database, conn);

                // delete mapping entry
                if (mappingEntry != null) {
                    logger.debug("populateDB: Deleting mapping " + mappingDN);
                    deleteSubtree(conn, mappingDN);
                }

                // delete the database including the subtree data
                if (databaseEntry != null) {
                    logger.debug("populateDB: Deleting database " + database);
                    deleteSubtree(conn, databaseDN);
                }

                // delete subtree data in case it's stored by another database
                if (baseEntry != null) {
                    logger.debug("populateDB: Deleting subtree " + baseDN);
                    deleteSubtree(conn, baseDN);
                }

                createDatabaseEntry(baseDN, database, conn, databaseDN);
                createDatabaseMappingEntry(baseDN, database, conn, mappingDN);
                createBaseEntry(baseDN, conn);
            } else {
                if (select.equals("clone") && !setupReplication) {
                    // cloning a system where the database is a subtree of an existing tree
                    // and not setting up replication agreements.  The assumption then is
                    // that the data is already replicated.  No need to set up the base DN
                } else {
                    // check if base entry already exists
                    LDAPEntry baseEntry = getBaseEntry(baseDN, remove, conn);

                    // delete subtree data in case it's stored by another database
                    if (baseEntry != null) {
                        logger.debug("populateDB: Deleting subtree " + baseDN);
                        deleteSubtree(conn, baseDN);
                    }

                    checkParentExists(baseDN, conn);
                    createBaseEntry(baseDN, conn);
                }
            }

            try {
                if (select.equals("clone")) {
                    // in most cases, we want to replicate the schema and therefore
                    // NOT add it here.  We provide this option though in case the
                    // clone already has schema and we want to replicate back to the
                    // master.
                    // On the other hand, if we are not setting up replication, then we
                    // are assuming that replication is already taken care of, and schema
                    // has already been replicated.  No need to add.

                    // Also, data will be replicated from master to clone
                    // so clone does not need the data
                    boolean replicateSchema = cs.getBoolean("preop.internaldb.replicateSchema", true);
                    if (!replicateSchema || !setupReplication) {
                        importLDIFS("preop.internaldb.schema.ldif", conn);
                    }
                    importLDIFS("preop.internaldb.ldif", conn);

                    // add the index before replication, add VLV indexes afterwards
                    importLDIFS("preop.internaldb.index_ldif", conn);

                    if (!setupReplication && reindexData) {
                        // data has already been replicated but not yet indexed -
                        // re-index here
                        populateIndexes(conn);
                    }
                } else {
                    // this is the normal non-clone case
                    // import schema, database, initial data and indexes
                    importLDIFS("preop.internaldb.schema.ldif", conn);
                    importLDIFS("preop.internaldb.ldif", conn);
                    importLDIFS("preop.internaldb.data_ldif", conn);
                    importLDIFS("preop.internaldb.index_ldif", conn);
                }
            } catch (Exception e) {
                logger.error("Failed to import ldif files: " + e);
                throw new EBaseException("Failed to import ldif files: " + e, e);
            }
        } finally {
            releaseConnection(conn);
        }
    }

    private static void populateIndexes(LDAPConnection conn) throws EPropertyNotFound, IOException, EBaseException {
        logger.debug("populateIndexes(): start");
        IConfigStore cs = CMS.getConfigStore();

        importLDIFS("preop.internaldb.index_task_ldif", conn, false);

        /* For populating indexes, we need to check if the task has completed.
           Presence of nsTaskExitCode means task is complete
         */
        String wait_dn = cs.getString("preop.internaldb.index_wait_dn", "");
        if (!StringUtils.isEmpty(wait_dn)) {
            wait_for_task(conn, wait_dn);
        }
    }

    private static void wait_for_task(LDAPConnection conn, String wait_dn) {
        LDAPEntry task = null;
        boolean taskComplete = false;
        logger.debug("Checking wait_dn " + wait_dn);
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
                            logger.debug("Error in populating indexes: nsTaskExitCode=" + val);
                        }
                    }
                }
            } catch (Exception le) {
                logger.info("Still checking wait_dn '" + wait_dn + "' (" + le + ")");
            }
        } while (!taskComplete);
    }

    private static void createBaseEntry(String baseDN, LDAPConnection conn) throws EBaseException {
        try {
            logger.debug("Creating base DN: " + baseDN);
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
            logger.error("createBaseDN: Unable to add " + baseDN + ": " + e);
            throw new EBaseException("Failed to create root entry: " + e, e);
        }
    }

    private static void createDatabaseMappingEntry(String baseDN, String database, LDAPConnection conn, String mappingDN)
            throws EBaseException {
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
            logger.error("createDatabaseMapping: Unable to add " + mappingDN + ": " + e);
            throw new EBaseException("Failed to create subtree: " + e, e);
        }
    }

    private static void createDatabaseEntry(String baseDN, String database, LDAPConnection conn, String databaseDN)
            throws EBaseException {
        try {
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            String oc[] = { "top", "extensibleObject", "nsBackendInstance" };
            attrs.add(new LDAPAttribute("objectClass", oc));
            attrs.add(new LDAPAttribute("cn", database));
            attrs.add(new LDAPAttribute("nsslapd-suffix", baseDN));
            LDAPEntry entry = new LDAPEntry(databaseDN, attrs);
            conn.add(entry);
        } catch (LDAPException e) {
            logger.error("createDatabase: Unable to add " + databaseDN + ": " + e);
            throw new EBaseException("Failed to create the database: " + e, e);
        }
    }

    private static void confirmNoConflictingMappingsForDB(String baseDN, String database, LDAPConnection conn)
            throws EBaseException {
        try {
            logger.debug("confirmMappings: Checking other subtrees using database " + database + ".");
            LDAPSearchResults res = conn.search(
                    "cn=mapping tree, cn=config", LDAPConnection.SCOPE_ONE,
                    "nsslapd-backend=" + LDAPUtil.escapeFilter(database),
                    null, false, (LDAPSearchConstraints) null);

            while (res.hasMoreElements()) {
                LDAPEntry entry = res.next();

                LDAPAttribute cn = entry.getAttribute("cn");
                String dn = cn.getStringValueArray()[0];
                if (LDAPDN.equals(baseDN, dn))
                    continue;

                logger.error("confirmMappings: Database " + database + " is used by " + dn + ".");
                throw new EBaseException("The database (" + database + ") is used by another base DN. " +
                        "Please use a different database name.");
            }

            logger.debug("confirmMappings: Database " + database + " is not used by another subtree.");

        } catch (LDAPException e) {
            logger.error("populateDB: " + e);
            throw new EBaseException("Failed to check database mapping: " + e, e);
        }
    }

    private static LDAPEntry getDatabaseEntry(String database, boolean remove, LDAPConnection conn, String databaseDN)
            throws EBaseException {
        LDAPEntry databaseEntry = null;
        try {
            logger.debug("getDatabaseEntry: Checking database " + database + ".");
            databaseEntry = conn.read(databaseDN);
            logger.debug("getDatabaseEntry: Database " + database + " already exists.");

            if (!remove) {
                throw new EBaseException("The database (" + database + ") already exists. " +
                        "Please confirm to remove and reuse this database.");
            }

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.warn("getDatabaseEntry: Database " + database + " does not exist.");
            } else {
                logger.error("getDatabaseEntry: " + e);
                throw new EBaseException("Failed to determine if database exists: " + e, e);
            }
        }
        return databaseEntry;
    }

    private static LDAPEntry getMappingEntry(String baseDN, boolean remove, LDAPConnection conn, String mappingDN)
            throws EBaseException {
        LDAPEntry mappingEntry = null;
        try {
            logger.debug("getMappingDNEntry: Checking subtree " + baseDN + " mapping.");
            mappingEntry = conn.read(mappingDN);
            logger.debug("getMapppingDNEntry: Mapping for subtree " + baseDN + " already exists.");

            if (!remove) {
                throw new EBaseException("The base DN (" + baseDN + ") has already been used. " +
                        "Please confirm to remove and reuse this base DN.");
            }

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.warn("getMappingDNEntry: Mapping for subtree " + baseDN + " does not exist.");
            } else {
                logger.error("getMappingDNEntry: " + e);
                throw new EBaseException("Failed to determine if mapping entry exists: " + e, e);
            }
        }
        return mappingEntry;
    }

    private static LDAPEntry getBaseEntry(String baseDN, boolean remove, LDAPConnection conn) throws EBaseException {
        LDAPEntry baseEntry = null;
        try {
            logger.debug("getBaseDNEntry: Checking subtree " + baseDN + ".");
            baseEntry = conn.read(baseDN);
            logger.debug("getBaseDNEntry: Subtree " + baseDN + " already exists.");

            if (!remove) {
                throw new EBaseException("The base DN (" + baseDN + ") has already been used. " +
                        "Please confirm to remove and reuse this base DN.");
            }

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.warn("getBaseDNEntry: Subtree " + baseDN + " does not exist.");
            } else {
                logger.error("getBaseDNEntry: " + e);
                throw new EBaseException("Failed to determine if base DN exists: " + e, e);
            }
        }
        return baseEntry;
    }

    private static void checkParentExists(String baseDN, LDAPConnection conn) throws EBaseException {
        String[] dns = LDAPDN.explodeDN(baseDN, false);
        if (dns.length == 1) {
            logger.error("checkParentExists: no parent in baseDN: " + baseDN);
            throw new EBaseException("Invalid BaseDN. No parent DN in " + baseDN);
        }
        String parentDN = Arrays.toString(Arrays.copyOfRange(dns, 1, dns.length));
        parentDN = parentDN.substring(1, parentDN.length() - 1);
        try {
            logger.debug("checkParentExists: Checking parent " + parentDN + ".");
            conn.read(parentDN);
            logger.debug("checkParentExists: Parent entry " + parentDN + " exists.");
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                throw new EBaseException("Parent entry " + parentDN + " does not exist", e);
            } else {
                logger.error("checkParentExists: " + e);
                throw new EBaseException("Failed to determine if base DN exists: " + e, e);
            }
        }
    }

    public static void importLDIFS(String param, LDAPConnection conn) throws EPropertyNotFound, IOException,
            EBaseException {
        importLDIFS(param, conn, true);
    }

    public static void importLDIFS(String param, LDAPConnection conn, boolean suppressErrors) throws IOException,
            EPropertyNotFound,
            EBaseException {
        IConfigStore cs = CMS.getConfigStore();

        logger.debug("importLDIFS: param=" + param);
        String v = cs.getString(param);

        String baseDN = cs.getString("internaldb.basedn");
        String database = cs.getString("internaldb.database");
        String instancePath = cs.getString("instanceRoot");
        String instanceId = cs.getString("instanceId");
        String cstype = cs.getString("cs.type");
        String dbuser = cs.getString("preop.internaldb.dbuser",
                "uid=" + DBUSER + ",ou=people," + baseDN);

        String configDir = instancePath + File.separator + cstype.toLowerCase() + File.separator + "conf";

        StringTokenizer tokenizer = new StringTokenizer(v, ",");
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken().trim();
            int index = token.lastIndexOf("/");
            String name = token;

            if (index != -1) {
                name = token.substring(index + 1);
            }

            logger.debug("importLDIFS(): ldif file = " + token);
            String filename = configDir + File.separator + name;

            logger.debug("importLDIFS(): ldif file copy to " + filename);
            PrintStream ps = null;
            BufferedReader in = null;

            in = new BufferedReader(new InputStreamReader(new FileInputStream(token), "UTF-8"));
            ps = new PrintStream(filename, "UTF-8");
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
                logger.error("importLDIFS(): LDAP Errors in importing " + filename);
                for (String error : errors) {
                    logger.error(error);
                }
                if (!suppressErrors) {
                    throw new EBaseException("LDAP Errors in importing " + filename);
                }
            }
        }
    }

    public static void deleteSubtree(LDAPConnection conn, String dn) throws EBaseException {
        String[] excludedDNs = {};
        try {
            LDAPSearchResults res = conn.search(
                    dn, LDAPConnection.SCOPE_BASE, "objectclass=*",
                    null, true, (LDAPSearchConstraints) null);
            deleteEntries(res, conn, excludedDNs);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.warn("deleteSubtree: Subtree " + dn + " does not exist.");
            } else {
                logger.error("deleteSubtree: Unable to delete subtree " + dn + ": " + e);
                throw new EBaseException("Unable to delete subtree " + dn, e);
            }
        }
    }

    public static void deleteEntries(LDAPSearchResults res, LDAPConnection conn, String[] excludedDNs)
            throws LDAPException {
        while (res.hasMoreElements()) {
            LDAPEntry entry = res.next();
            String dn = entry.getDN();

            LDAPSearchResults res1 = conn.search(
                    dn, 1, "objectclass=*",
                    null, true, (LDAPSearchConstraints) null);
            deleteEntries(res1, conn, excludedDNs);
            deleteEntry(conn, dn, excludedDNs);
        }
    }

    public static void deleteEntry(LDAPConnection conn, String dn, String[] excludedDNs) throws LDAPException {
        for (String excludedDN : excludedDNs) {
            if (!LDAPDN.equals(dn, excludedDN))
                continue;

            logger.debug("deleteEntry: entry with this dn " + dn + " is not deleted.");
            return;
        }

        conn.delete(dn);
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
        logger.debug("populateDBManager(): start");
        IConfigStore cs = CMS.getConfigStore();

        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = new LdapBoundConnFactory("ConfigurationUtils");
        dbFactory.init(dbCfg);
        LDAPConnection conn = dbFactory.getConn();

        try {
            importLDIFS("preop.internaldb.manager_ldif", conn);
        } catch (Exception e) {
            logger.error("populateDBManager(): Exception thrown: " + e);
            throw e;
        } finally {
            releaseConnection(conn);
        }
    }

    public static void populateVLVIndexes() throws Exception {
        logger.debug("populateVLVIndexes(): start");
        IConfigStore cs = CMS.getConfigStore();

        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = new LdapBoundConnFactory("ConfigurationUtils");
        dbFactory.init(dbCfg);
        LDAPConnection conn = dbFactory.getConn();

        try {
            importLDIFS("preop.internaldb.post_ldif", conn);

            /* For vlvtask, we need to check if the task has
               been completed or not.  Presence of nsTaskExitCode means task is complete
             */
            String wait_dn = cs.getString("preop.internaldb.wait_dn", "");
            if (!wait_dn.equals("")) {
                wait_for_task(conn, wait_dn);
            }
        } catch (Exception e) {
            logger.error("populateVLVIndexes(): Exception thrown: " + e);
            throw e;
        } finally {
            releaseConnection(conn);
        }
    }

    public static KeyPair loadKeyPair(String nickname, String token) throws Exception {

        logger.debug("ConfigurationUtils: loadKeyPair(" + nickname + ", " + token + ")");

        CryptoManager cm = CryptoManager.getInstance();

        if (!CryptoUtil.isInternalToken(token)) {
            nickname = token + ":" + nickname;
        }

        logger.debug("ConfigurationUtils: loading cert: " + nickname);
        X509Certificate cert = cm.findCertByNickname(nickname);

        logger.debug("ConfigurationUtils: loading public key");
        PublicKey publicKey = cert.getPublicKey();

        logger.debug("ConfigurationUtils: loading private key");
        PrivateKey privateKey = cm.findPrivKeyByCert(cert);

        return new KeyPair(publicKey, privateKey);
    }

    public static void storeKeyPair(IConfigStore config, String tag, KeyPair pair)
            throws TokenException, EBaseException {

        logger.debug("ConfigurationUtils: storeKeyPair(" + tag + ")");

        PublicKey publicKey = pair.getPublic();

        if (publicKey instanceof RSAPublicKey) {

            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

            byte modulus[] = rsaPublicKey.getModulus().toByteArray();
            config.putString(PCERT_PREFIX + tag + ".pubkey.modulus",
                    CryptoUtil.byte2string(modulus));

            byte exponent[] = rsaPublicKey.getPublicExponent().toByteArray();
            config.putString(PCERT_PREFIX + tag + ".pubkey.exponent",
                    CryptoUtil.byte2string(exponent));

        } else { // ECC

            logger.debug("ConfigurationUtils: Public key class: " + publicKey.getClass().getName());
            byte encoded[] = publicKey.getEncoded();
            config.putString(PCERT_PREFIX + tag + ".pubkey.encoded", CryptoUtil.byte2string(encoded));
        }

        PrivateKey privateKey = (PrivateKey) pair.getPrivate();
        byte id[] = privateKey.getUniqueID();
        String kid = CryptoUtil.encodeKeyID(id);
        config.putString(PCERT_PREFIX + tag + ".privkey.id", kid);

        String keyAlgo = config.getString(PCERT_PREFIX + tag + ".signingalgorithm");
        setSigningAlgorithm(tag, keyAlgo, config);
    }

    public static KeyPair createECCKeyPair(CryptoToken token, String curveName, IConfigStore config, String ct)
            throws NoSuchAlgorithmException, NoSuchTokenException, TokenException,
            NotInitializedException, EPropertyNotFound, EBaseException {

        logger.debug("ConfigurationUtils.createECCKeyPair(" + token + ", " + curveName + ")");

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
        } catch (Exception e) {
        }

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
                logger.debug("ConfigurationUtils: createECCKeypair: sslserver cert for ECDH. Make sure server.xml is set "
                        +
                        "properly with -TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,+TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
                pair = CryptoUtil.generateECCKeyPair(token, curveName, null, ECDH_usages_mask);
            } else {
                if (ct.equals("sslserver")) {
                    logger.debug("ConfigurationUtils: createECCKeypair: sslserver cert for ECDHE. Make sure server.xml is set "
                            +
                            "properly with +TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,-TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
                }
                pair = CryptoUtil.generateECCKeyPair(token, curveName, null, usages_mask);
            }

            // XXX - store curve , w
            byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();
            String kid = CryptoUtil.encodeKeyID(id);

            // try to locate the private key
            org.mozilla.jss.crypto.PrivateKey privk = CryptoUtil.findPrivateKeyFromID(CryptoUtil.decodeKeyID(kid));
            if (privk == null) {
                logger.debug("Found bad ECC key id " + kid);
                pair = null;
            }
        } while (pair == null);

        return pair;
    }

    public static KeyPair createRSAKeyPair(CryptoToken token, int keysize, IConfigStore config, String ct)
            throws Exception {

        logger.debug("ConfigurationUtils.createRSAKeyPair(" + token + ")");

        KeyPair pair = null;
        do {
            pair = CryptoUtil.generateRSAKeyPair(token, keysize);
            byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();
            String kid = CryptoUtil.encodeKeyID(id);

            // try to locate the private key
            org.mozilla.jss.crypto.PrivateKey privk =
                    CryptoUtil.findPrivateKeyFromID(CryptoUtil.decodeKeyID(kid));

            if (privk == null) {
                logger.debug("Found bad RSA key id " + kid);
                pair = null;
            }
        } while (pair == null);

        return pair;
    }

    public static void setSigningAlgorithm(String ct, String keyAlgo, IConfigStore config) throws EPropertyNotFound,
            EBaseException {
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
            boolean https, String type) throws Exception {
        logger.debug("getSubsystemCount start");
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
            logger.debug("getSubsystemCount: SubsystemCount=" + countS);
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

    public static void configCert(
            ConfigurationRequest request,
            HttpServletResponse response,
            Context context,
            Cert certObj) throws Exception {

        IConfigStore config = CMS.getConfigStore();
        String caType = certObj.getType();
        logger.debug("configCert: caType is " + caType);
        X509CertImpl cert = null;
        String certTag = certObj.getCertTag();

        String selection = config.getString("preop.subsystem.select");
        String csType = config.getString("cs.type");
        String preop_ca_type = null;
        String preop_cert_signing_type = null;
        String preop_cert_signing_profile = null;
        String preop_cert_sslserver_type = null;
        String preop_cert_sslserver_profile = null;
        String original_caType = null;
        boolean sign_clone_sslserver_cert_using_master = false;

        if (selection.equals("clone") && csType.equals("CA") && certTag.equals("sslserver")) {
            // retrieve and store original 'CS.cfg' entries
            preop_ca_type = config.getString("preop.ca.type", "");
            preop_cert_signing_type = config.getString("preop.cert.signing.type", "");
            preop_cert_signing_profile = config.getString("preop.cert.signing.profile", "");
            preop_cert_sslserver_type = config.getString("preop.cert.sslserver.type", "");
            preop_cert_sslserver_profile = config.getString("preop.cert.sslserver.profile", "");

            // add/modify 'CS.cfg' entries
            config.putString("preop.ca.type", "sdca");
            config.putString("preop.cert.signing.type", "remote");
            config.putString("preop.cert.signing.profile", "caInstallCACert");
            config.putString("preop.cert.sslserver.type", "remote");

            config.putString("preop.cert.sslserver.profile",
                   request.getSystemCertProfileID("sslserver", "caInternalAuthServerCert"));

            // store original caType
            original_caType = caType;

            // modify caType
            certObj.setType("remote");

            // fetch revised caType
            caType = certObj.getType();
            logger.debug("configCert: caType is " + caType + " (revised)");

            // set master/clone signature flag
            sign_clone_sslserver_cert_using_master = true;
        }

        updateConfig(config, certObj);

        if (caType.equals("remote")) {

            cert = configRemoteCert(
                    request,
                    response,
                    context,
                    certObj,
                    config,
                    cert,
                    certTag,
                    preop_ca_type,
                    preop_cert_signing_type,
                    preop_cert_signing_profile,
                    preop_cert_sslserver_type,
                    preop_cert_sslserver_profile,
                    original_caType,
                    sign_clone_sslserver_cert_using_master);

        } else { // not remote CA, ie, self-signed or local

            cert = configLocalCert(context, certObj, config, caType, cert, certTag);

            if (cert != null) {
                if (certTag.equals("subsystem")) {
                    logger.debug("configCert: creating subsystem user");
                    CertUtil.addUserCertificate(cert);
                }
            }

        } // done self-signed or local

        if (cert != null) {
            byte[] certb = cert.getEncoded();
            String certs = CryptoUtil.base64Encode(certb);

            certObj.setCert(certb);
            String subsystem = config.getString(
                    PCERT_PREFIX + certTag + ".subsystem");
            config.putString(subsystem + "." + certTag + ".cert", certs);
        }
        config.commit(false);
    }

    private static X509CertImpl configRemoteCert(
            ConfigurationRequest request,
            HttpServletResponse response,
            Context context,
            Cert certObj,
            IConfigStore config,
            X509CertImpl cert,
            String certTag,
            String preop_ca_type,
            String preop_cert_signing_type,
            String preop_cert_signing_profile,
            String preop_cert_sslserver_type,
            String preop_cert_sslserver_profile,
            String original_caType,
            boolean sign_clone_sslserver_cert_using_master)
            throws Exception {

        String caType;
        String v = config.getString("preop.ca.type", "");

        logger.debug("configCert: remote CA");
        logger.debug("confgCert: tag: " + certTag);
        PKCS10 pkcs10 = CertUtil.getPKCS10(config, PCERT_PREFIX, certObj, context);
        byte[] binRequest = pkcs10.toByteArray();
        String b64Request = CryptoUtil.base64Encode(binRequest);
        certObj.setRequest(binRequest);

        String subsystem = config.getString(PCERT_PREFIX + certTag + ".subsystem");
        config.putString(subsystem + "." + certTag + ".certreq", b64Request);

        String profileId = config.getString(PCERT_PREFIX + certTag + ".profile");
        String session_id = CMS.getConfigSDSessionId();
        String sysType = config.getString("cs.type", "");
        String machineName = config.getString("machineName", "");
        String securePort = config.getString("service.securePort", "");

        if (certTag.equals("subsystem")) {

            String sd_hostname = config.getString("securitydomain.host", "");
            int sd_ee_port = config.getInteger("securitydomain.httpseeport", -1);

            MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
            content.putSingle("requestor_name", sysType + "-" + machineName + "-" + securePort);
            logger.debug("configRemoteCert: subsystemCert: setting profileId to: " + profileId);
            String actualProfileId = request.getSystemCertProfileID(certTag, profileId);
            logger.debug("configRemoteCert: subsystemCert: calculated profileId: " + actualProfileId);
            content.putSingle("profileId", actualProfileId);
            content.putSingle("cert_request_type", "pkcs10");
            content.putSingle("cert_request", b64Request);
            content.putSingle("xmlOutput", "true");
            content.putSingle("sessionID", session_id);

            cert = CertUtil.createRemoteCert(sd_hostname, sd_ee_port, content, response);

            if (cert == null) {
                throw new IOException("Error: remote certificate is null");
            }

        } else if (v.equals("sdca")) {

            String ca_hostname = "";
            int ca_port = -1;

            try {
                if (sign_clone_sslserver_cert_using_master) {

                    logger.debug("ConfigurationUtils: For this Cloned CA, always use its Master CA to generate " +
                            "the 'sslserver' certificate to avoid any changes which may have been " +
                            "made to the X500Name directory string encoding order.");
                    ca_hostname = config.getString("preop.master.hostname", "");
                    ca_port = config.getInteger("preop.master.httpsport", -1);

                } else {

                    ca_hostname = config.getString("preop.ca.hostname", "");
                    ca_port = config.getInteger("preop.ca.httpsport", -1);
                }

            } catch (Exception ee) {
            }

            String sslserver_extension = "";
            Boolean injectSAN = config.getBoolean("service.injectSAN", false);
            logger.debug("ConfigurationUtils: injectSAN: " + injectSAN);

            if (certTag.equals("sslserver") && injectSAN == true) {
                sslserver_extension = CertUtil.buildSANSSLserverURLExtension(config);
            }

            MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
            content.putSingle("requestor_name", sysType + "-" + machineName + "-" + securePort);
            //Get the correct profile id to send in case it's sslserver type:
            logger.debug("configRemoteCert: tag: " + certTag + " : setting profileId to: " + profileId);
            String actualProfileId = request.getSystemCertProfileID(certTag, profileId);
            logger.debug("configRemoteCert: tag: " + certTag + " calculated profileId: " + actualProfileId);

            content.putSingle("profileId", actualProfileId);
            content.putSingle("cert_request_type", "pkcs10");
            content.putSingle("cert_request", b64Request);
            content.putSingle("xmlOutput", "true");
            content.putSingle("sessionID", session_id);

            cert = CertUtil.createRemoteCert(ca_hostname, ca_port, content, response);

            if (cert == null) {
                throw new IOException("Error: remote certificate is null");
            }

            if (sign_clone_sslserver_cert_using_master) {
                // restore original 'CS.cfg' entries
                config.putString("preop.ca.type", preop_ca_type);
                config.putString("preop.cert.signing.type", preop_cert_signing_type);
                config.putString("preop.cert.signing.profile", preop_cert_signing_profile);
                config.putString("preop.cert.sslserver.type", preop_cert_sslserver_type);
                config.putString("preop.cert.sslserver.profile", preop_cert_sslserver_profile);

                // restore original 'caType'
                caType = original_caType;

                // reset master/clone signature flag
                sign_clone_sslserver_cert_using_master = false;
            }

        } else if (v.equals("otherca")) {

            // external certs already imported in configuration.py

        } else {
            logger.warn("ConfigurationUtils: no preop.ca.type is provided");
        }

        return cert;
    }

    private static X509CertImpl configLocalCert(
            Context context,
            Cert certObj,
            IConfigStore config,
            String caType,
            X509CertImpl cert,
            String certTag)
            throws Exception {

        ISubsystem ca = CMS.getSubsystem(ICertificateAuthority.ID);

        if (ca == null) {
            String s = PCERT_PREFIX + certTag + ".type";
            logger.error("The value for " + s + " should be remote, nothing else.");
            throw new IOException("The value for " + s + " should be remote");
        }

        String pubKeyType = config.getString(PCERT_PREFIX + certTag + ".keytype");

        if (pubKeyType.equals("rsa")) {

            String pubKeyModulus = config.getString(PCERT_PREFIX + certTag + ".pubkey.modulus");
            String pubKeyPublicExponent = config.getString(PCERT_PREFIX + certTag + ".pubkey.exponent");

            X509Key x509key = CryptoUtil.getPublicX509Key(
                    CryptoUtil.string2byte(pubKeyModulus),
                    CryptoUtil.string2byte(pubKeyPublicExponent));

            cert = CertUtil.createLocalCert(config, x509key, PCERT_PREFIX, certTag, caType);

        } else if (pubKeyType.equals("ecc")) {

            String pubKeyEncoded = config.getString(PCERT_PREFIX + certTag + ".pubkey.encoded");

            X509Key x509key = CryptoUtil.getPublicX509ECCKey(
                    CryptoUtil.string2byte(pubKeyEncoded));
            cert = CertUtil.createLocalCert(config, x509key, PCERT_PREFIX, certTag, caType);

        } else {
            // invalid key type
            logger.warn("Invalid key type " + pubKeyType);
        }

        return cert;
    }

    public static void updateConfig(IConfigStore config, Cert cert)
            throws EBaseException, IOException {

        String certTag = cert.getCertTag();
        String token = cert.getTokenname();
        String nickname = cert.getNickname();

        String subsystem = config.getString(PCERT_PREFIX + certTag + ".subsystem");

        logger.debug("ConfigurationUtils: updateConfig() for certTag " + certTag);
        if (certTag.equals("signing") || certTag.equals("ocsp_signing")) {
            logger.debug("ConfigurationUtils: setting signing nickname=" + nickname);
            config.putString(subsystem + "." + certTag + "." + ISigningUnit.PROP_CA_CERT_NICKNAME, nickname);
            config.putString(subsystem + "." + certTag + ".certnickname", nickname);
        }

        // if KRA, hardware token needs param "kra.storageUnit.hardware" in CS.cfg
        String cstype = config.getString("cs.type", null);
        cstype = cstype.toLowerCase();
        if (cstype.equals("kra")) {
            if (!CryptoUtil.isInternalToken(token)) {
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

        config.putString(subsystem + "." + certTag + ".nickname", nickname);
        config.putString(subsystem + "." + certTag + ".tokenname", StringUtils.defaultString(token));

        if (certTag.equals("audit_signing")) {
            if (!CryptoUtil.isInternalToken(token)) {
                config.putString("log.instance.SignedAudit.signedAuditCertNickname",
                        token + ":" + nickname);
            } else {
                config.putString("log.instance.SignedAudit.signedAuditCertNickname",
                        nickname);
            }
        }

        // for system certs verification
        if (!CryptoUtil.isInternalToken(token)) {
            config.putString(subsystem + ".cert." + certTag + ".nickname",
                    token + ":" + nickname);
        } else {
            config.putString(subsystem + ".cert." + certTag + ".nickname", nickname);
        }

        config.commit(false);
        logger.debug("updateConfig() done");
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

        logger.debug("ConfigurationUtils: Searching for " + wantedTag + " in " + csType + " hosts");

        IConfigStore cs = CMS.getConfigStore();
        ByteArrayInputStream bis = new ByteArrayInputStream(domainXML.getBytes());
        XMLObject parser = new XMLObject(bis);
        Document doc = parser.getDocument();

        NodeList nodeList = doc.getElementsByTagName(csType);

        // save domain name in cfg
        cs.putString("securitydomain.name", parser.getValue("Name"));

        int len = nodeList.getLength();
        for (int i = 0; i < len; i++) {
            Node node = nodeList.item(i);

            String v_host = parser.getValuesFromContainer(node, "Host").elementAt(0);
            logger.debug("ConfigurationUtils: host: " + v_host);

            String v_given_port = parser.getValuesFromContainer(node, givenTag).elementAt(0);
            logger.debug("ConfigurationUtils: " + givenTag + " port: " + v_given_port);

            if (!(v_host.equals(host) && v_given_port.equals(port + "")))
                continue;

            // v_host == host || v_given_port != port

            String wanted_port = parser.getValuesFromContainer(node, wantedTag).elementAt(0);
            logger.debug("ConfigurationUtils: " + wantedTag + " port found: " + wanted_port);

            return Integer.parseInt(wanted_port);
        }

        logger.warn("ConfigurationUtils: " + wantedTag + " port not found");
        return 0;
    }

    public static void updateCloneConfig() throws EBaseException, IOException {

        IConfigStore config = CMS.getConfigStore();
        String cstype = config.getString("cs.type", null);
        cstype = cstype.toLowerCase();

        if (cstype.equals("kra")) {

            String token = config.getString("preop.module.token");

            if (!CryptoUtil.isInternalToken(token)) {

                logger.debug("ConfigurationUtils: updating configuration for KRA clone with hardware token");

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
        String nickname = config.getString(cstype + ".audit_signing.nickname", "");
        String token = config.getString(cstype + ".audit_signing.tokenname", "");

        if (!CryptoUtil.isInternalToken(token)) {
            nickname = token + ":" + nickname;
        }

        config.putString("log.instance.SignedAudit.signedAuditCertNickname", nickname);
    }

    public static byte[] loadCertRequest(IConfigStore config, String subsystem, String tag) throws Exception {

        logger.debug("ConfigurationUtils.loadCertRequest(" + tag + ")");

        // the CSR must exist in the second step of external CA scenario
        String certreq = config.getString(subsystem + "." + tag + ".certreq");
        return CryptoUtil.base64Decode(certreq);
    }

    public static void generateCertRequest(IConfigStore config, String certTag, Cert cert) throws Exception {

        logger.debug("generateCertRequest: getting public key for certificate " + certTag);

        String pubKeyType = config.getString(PCERT_PREFIX + certTag + ".keytype");
        String algorithm = config.getString(PCERT_PREFIX + certTag + ".keyalgorithm");

        X509Key pubk;
        if (pubKeyType.equals("rsa")) {
            pubk = getRSAX509Key(config, certTag);

        } else if (pubKeyType.equals("ecc")) {
            pubk = getECCX509Key(config, certTag);

        } else {
            logger.error("generateCertRequest: Unsupported public key type: " + pubKeyType);
            throw new BadRequestException("Unsupported public key type: " + pubKeyType);
        }

        // public key cannot be null here

        logger.debug("generateCertRequest: getting private key for certificate " + certTag);
        String privKeyID = config.getString(PCERT_PREFIX + certTag + ".privkey.id");

        logger.debug("generateCertRequest: private key ID: " + privKeyID);
        byte[] keyIDb = CryptoUtil.decodeKeyID(privKeyID);

        PrivateKey privk = CryptoUtil.findPrivateKeyFromID(keyIDb);
        if (privk == null) {
            logger.error("generateCertRequest: Unable to find private key for certificate " + certTag);
            throw new BadRequestException("Unable to find private key for certificate " + certTag);
        }

        // construct cert request
        String caDN = config.getString(PCERT_PREFIX + certTag + ".dn");

        cert.setDN(caDN);

        Extensions exts = new Extensions();
        if (certTag.equals("signing")) {
            logger.debug("generateCertRequest: generating basic CA extensions");
            createBasicCAExtensions(config, exts);
        }

        logger.debug("generateCertRequest: generating generic extensions");
        createGenericExtensions(config, certTag, exts);

        logger.debug("generateCertRequest: generating PKCS #10 request");
        PKCS10 certReq = CryptoUtil.createCertificationRequest(caDN, pubk, privk, algorithm, exts);

        logger.debug("generateCertRequest: storing cert request");
        byte[] certReqb = certReq.toByteArray();
        String certReqs = CryptoUtil.base64Encode(certReqb);

        String subsystem = config.getString(PCERT_PREFIX + certTag + ".subsystem");
        config.putString(subsystem + "." + certTag + ".certreq", certReqs);
        config.commit(false);

        cert.setRequest(certReqb);
    }

    /*
     * createBasicCAExtensions creates the basic Extensions needed for a CSR to a
     * CA signing certificate
     */
    private static void createBasicCAExtensions(IConfigStore config, Extensions exts) throws Exception {
        logger.debug("ConfigurationUtils: createBasicCAExtensions: begins");

        // create BasicConstraintsExtension
        BasicConstraintsExtension bcExt = new BasicConstraintsExtension(true, -1);
        exts.add(bcExt);

        // create KeyUsageExtension
        boolean[] kuBits = new boolean[KeyUsageExtension.NBITS];
        for (int i = 0; i < kuBits.length; i++) {
            kuBits[i] = false;
        }
        kuBits[KeyUsageExtension.DIGITAL_SIGNATURE_BIT] = true;
        kuBits[KeyUsageExtension.NON_REPUDIATION_BIT] = true;
        kuBits[KeyUsageExtension.KEY_CERTSIGN_BIT] = true;
        kuBits[KeyUsageExtension.CRL_SIGN_BIT] = true;
        KeyUsageExtension kuExt = new KeyUsageExtension(true, kuBits);
        exts.add(kuExt);

        /* save this for later when we want to allow more selection for pkispawn configuration
        // create NSCertTypeExtension
        boolean[] nsBits = new boolean[NSCertTypeExtension.NBITS];
        for (int i = 0; i < nsBits.length; i++) {
            nsBits[i] = false;
        }
        nsBits[NSCertTypeExtension.SSL_CA_BIT] = true;
        NSCertTypeExtension nsctExt = new NSCertTypeExtension(false, nsBits);
        exts.add(nsctExt);
        */
    }

    private static void createGenericExtensions(IConfigStore config, String tag, Extensions exts) throws Exception {
        logger.debug("ConfigurationUtils: createGenericExtensions: begins");
        // if specified, add a generic extension
        try {
            String oidString = config.getString(PCERT_PREFIX + tag + ".ext.oid");
            String dataString = config.getString(PCERT_PREFIX + tag + ".ext.data");

            if (oidString != null && dataString != null) {
                logger.debug("ConfigurationUtils: createGenericExtensions: adding generic extension for " + tag);
                boolean critical = config.getBoolean(PCERT_PREFIX + tag + ".ext.critical");
                ObjectIdentifier oid = new ObjectIdentifier(oidString);

                byte data[] = CryptoUtil.hexString2Bytes(dataString);
                DerOutputStream out = new DerOutputStream();
                out.putOctetString(data);

                Extension genExt = new Extension(oid, critical, out.toByteArray());
                out.close();

                exts.add(genExt);
                logger.debug("ConfigurationUtils: createGenericExtensions: generic extension added: " + oidString);
            }

        } catch (EPropertyNotFound e) {
            // generic extension not specified, ignore

        } catch (EBaseException e) {
            logger.error("ConfigurationUtils: createGenericExtensions: Unable to add generic extension: " + e);
            throw new BadRequestException("Unable to add generic certificate extension: " + e, e);
        }
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

    public static void createCertRecord(IConfigStore cs, Cert cert) throws Exception {

        String tag = cert.getCertTag();
        logger.debug("ConfigurationUtils.createCertRecord(" + tag + ")");

        // parsing cert data
        X509CertImpl x509CertImpl = new X509CertImpl(cert.getCert());
        X509CertInfo info = x509CertImpl.getInfo();

        // parsing cert request
        String certreq = cs.getString("ca." + tag + ".certreq");
        byte[] b = Utils.base64decode(certreq);
        PKCS10 pkcs10 = new PKCS10(b);
        X509Key x509key = pkcs10.getSubjectPublicKeyInfo();

        // loading cert profile
        String profileName = cs.getString(ConfigurationUtils.PCERT_PREFIX + tag + ".profile");
        logger.debug("SystemConfigService: profile: " + profileName);

        String instanceRoot = cs.getString("instanceRoot");
        String configurationRoot = cs.getString("configurationRoot");
        CertInfoProfile profile = new CertInfoProfile(instanceRoot + configurationRoot + profileName);

        // creating cert request record
        ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(ICertificateAuthority.ID);
        ICertificateRepository cr = ca.getCertificateRepository();
        IRequestQueue queue = ca.getRequestQueue();

        IRequest req = CertUtil.createLocalRequest(
                cs,
                queue,
                tag,
                profile,
                info,
                x509key);

        req.setExtData(IEnrollProfile.REQUEST_ISSUED_CERT, x509CertImpl);
        req.setExtData("cert_request", cert.getRequest());
        req.setExtData("cert_request_type", "pkcs10");

        queue.updateRequest(req);

        RequestId reqId = req.getRequestId();
        logger.debug("SystemConfigService: request: " + reqId);

        cs.putString("preop.cert." + tag + ".reqId", reqId.toString());

        BigInteger serialNo = x509CertImpl.getSerialNumber();

        MetaInfo meta = new MetaInfo();
        meta.set(ICertRecord.META_REQUEST_ID, req.getRequestId().toString());
        meta.set(ICertRecord.META_PROFILE_ID, profile.getProfileIDMapping());

        ICertRecord record = cr.createCertRecord(serialNo, x509CertImpl, meta);
        cr.addCertificateRecord(record);
    }

    public static void handleCert(Cert cert) throws Exception {

        String certTag = cert.getCertTag();
        logger.debug("ConfigurationUtils.handleCert(" + certTag + ")");

        String subsystem = cert.getSubsystem();
        String nickname = cert.getNickname();
        IConfigStore config = CMS.getConfigStore();

        boolean enable = config.getBoolean(PCERT_PREFIX + certTag + ".enable", true);
        if (!enable)
            return;

        logger.debug("ConfigurationUtils: cert type: " + cert.getType());

        String tokenname = config.getString("preop.module.token", "");

        byte[] certb = cert.getCert();
        X509CertImpl impl = new X509CertImpl(certb);

        importCert(subsystem, certTag, tokenname, nickname, impl);

        //update requests in request queue for local certs to allow renewal
        if ((cert.getType().equals("local")) || (cert.getType().equals("selfsign"))) {
            CertUtil.updateLocalRequest(config, certTag, cert.getRequest(), "pkcs10", null);
        }
    }

    public static void importCert(
            String subsystem,
            String tag,
            String tokenname,
            String nickname,
            X509CertImpl impl
            ) throws Exception {

        logger.debug("ConfigurationUtils.importCert(" + tag + ")");

        if (tag.equals("sslserver")) {
            logger.info("ConfigurationUtils: temporary SSL server cert will be replaced on restart");
            return;
        }

        String fullNickname = nickname;
        if (!CryptoUtil.isInternalToken(tokenname)) {
            fullNickname = tokenname + ":" + nickname;
        }

        X509Certificate cert = CertUtil.findCertificate(fullNickname);

        if (cert != null) {
            logger.debug("ConfigurationUtils: deleting existing " + tag + " cert");
            CertUtil.deleteCert(tokenname, cert);
        }

        logger.debug("ConfigurationUtils: importing " + tag + " cert");
        cert = CryptoUtil.importUserCertificate(impl.getEncoded(), nickname);

        if (tag.equals("signing") && subsystem.equals("ca")) { // set trust flags to CT,C,C
            CryptoUtil.trustCACert(cert);

        } else if (tag.equals("audit_signing")) { // set trust flags to u,u,Pu
            CryptoUtil.trustAuditSigningCert(cert);

        } // user certs will have u,u,u by default
    }

    public static void backupKeys(String pwd, String fname) throws Exception {

        logger.debug("backupKeys(): start");
        IConfigStore cs = CMS.getConfigStore();
        String certlist = cs.getString("preop.cert.list");

        StringTokenizer st = new StringTokenizer(certlist, ",");
        CryptoManager cm = CryptoManager.getInstance();

        Password pass = new org.mozilla.jss.util.Password(pwd.toCharArray());

        try {

            PKCS12Util util = new PKCS12Util();
            PKCS12 pkcs12 = new PKCS12();

            // load system certificate (with key but without chain)
            while (st.hasMoreTokens()) {

                String t = st.nextToken();
                if (t.equals("sslserver"))
                    continue;

                String nickname = cs.getString("preop.cert." + t + ".nickname");
                String modname = cs.getString("preop.module.token");

                if (!CryptoUtil.isInternalToken(modname))
                    nickname = modname + ":" + nickname;

                util.loadCertFromNSS(pkcs12, nickname, true, false);
            }

            // load CA certificates (without keys or chains)
            for (X509Certificate caCert : cm.getCACerts()) {
                util.loadCertFromNSS(pkcs12, caCert, false, false);
            }

            PFX pfx = util.generatePFX(pkcs12, pass);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            pfx.encode(bos);
            byte[] output = bos.toByteArray();

            cs.putString("preop.pkcs12", CryptoUtil.byte2string(output));
            cs.commit(false);

            if (fname != null) {
                FileOutputStream fout = null;
                try {
                    fout = new FileOutputStream(fname);
                    fout.write(output);

                } catch (Exception e) {
                    throw new IOException("Failed to store keys in backup file " + e, e);

                } finally {
                    if (fout != null) {
                        fout.close();
                    }
                }
            }

        } catch (Exception e) {
            throw e;
        } finally {
            if (pass != null) {
                pass.clear();
            }
        }
    }

    public static void createAdminCertificate(String certRequest, String certRequestType, String subject)
            throws Exception {

        IConfigStore cs = CMS.getConfigStore();

        byte[] binRequest = Utils.base64decode(certRequest);
        X509Key x509key;

        if (certRequestType.equals("crmf")) {
            SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(binRequest);
            subject = CryptoUtil.getSubjectName(crmfMsgs);
            x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);

        } else if (certRequestType.equals("pkcs10")) {
            PKCS10 pkcs10 = new PKCS10(binRequest);
            x509key = pkcs10.getSubjectPublicKeyInfo();

        } else {
            throw new Exception("Certificate request type not supported: " + certRequestType);
        }

        if (x509key == null) {
            logger.error("createAdminCertificate() - x509key is null!");
            throw new IOException("x509key is null");
        }

        cs.putString(PCERT_PREFIX + "admin.dn", subject);
        String caType = cs.getString(PCERT_PREFIX + "admin.type", "local");
        X509CertImpl impl = CertUtil.createLocalCert(cs, x509key, PCERT_PREFIX, "admin", caType);

        // update the locally created request for renewal
        CertUtil.updateLocalRequest(cs, "admin", binRequest, certRequestType, subject);

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
        String p7Str = Utils.base64encode(p7Bytes, true);
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
            logger.warn("ConfigurationUtils: createAdmin: addUser " + e);
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
                logger.debug("ConfigurationUtils: createAdmin:  add user '" + uid
                        + "' to group 'Security Domain Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise CA Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("ConfigurationUtils: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise CA Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise KRA Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("ConfigurationUtils: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise KRA Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise RA Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("ConfigurationUtils: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise RA Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise TKS Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("ConfigurationUtils: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise TKS Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise OCSP Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("ConfigurationUtils: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise OCSP Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise TPS Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("ConfigurationUtils: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise TPS Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }
        }
    }

    public static String submitAdminCertRequest(String ca_hostname, int ca_port, String profileId,
            String certRequestType, String certRequest, String subjectDN) throws Exception {

        logger.debug("ConfigurationUtils: submitAdminCertRequest()");

        IConfigStore config = CMS.getConfigStore();

        if (profileId == null) {
            profileId = config.getString("preop.admincert.profile", "caAdminCert");
        }

        String session_id = CMS.getConfigSDSessionId();

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("profileId", profileId);
        content.putSingle("cert_request_type", certRequestType);
        content.putSingle("cert_request", certRequest);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", session_id);
        content.putSingle("subject", subjectDN);

        String c = post(ca_hostname, ca_port, true, "/ca/ee/ca/profileSubmit", content, null, null);

        // retrieve the request Id and admin certificate
        if (c != null) {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser = new XMLObject(bis);

            String status = parser.getValue("Status");
            logger.debug("submitAdminXertRequest: status=" + status);
            if (status.equals(AUTH_FAILURE)) {
                throw new EAuthException("Unable to generate admin certificate: authentication failure");

            } else if (!status.equals(SUCCESS)) {
                String error = parser.getValue("Error");
                logger.error("Error: " + error);
                throw new IOException("Unable to generate admin certificate: " + error);
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

            PrintStream ps = new PrintStream(dir, "UTF-8");
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
        ILdapConnFactory dbFactory = new LdapBoundConnFactory("ConfigurationUtils");
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

        logger.debug("createSecurityDomain(): finish updating domain info");
        conn.disconnect();

        // Fetch the "new" security domain and display it
        // logger.debug("createSecurityDomain(): Dump contents of new Security Domain . . .");
        // @SuppressWarnings("unused")
        // String c = getDomainXML(CMS.getEESSLHost(), Integer.parseInt(CMS.getAdminPort()), true);
    }

    public static void updateSecurityDomain() throws Exception {

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
            logger.debug("Cloning a domain master");
        }

        String url = "/ca/admin/ca/updateDomainXML";

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("list", type + "List");
        content.putSingle("type", type);
        content.putSingle("host", CMS.getEESSLHost());
        content.putSingle("name", subsystemName);
        content.putSingle("sport", CMS.getEESSLPort());
        content.putSingle("dm", cloneMaster ? "true" : "false");
        content.putSingle("clone", select.equals("clone") ? "true" : "false");
        content.putSingle("agentsport", CMS.getAgentPort());
        content.putSingle("adminsport", CMS.getAdminPort());

        if (CMS.getEEClientAuthSSLPort() != null) {
            content.putSingle("eeclientauthsport", CMS.getEEClientAuthSSLPort());
        }

        content.putSingle("httpport", CMS.getEENonSSLPort());

        try {
            logger.debug("Update security domain using admin interface");
            String session_id = CMS.getConfigSDSessionId();
            content.putSingle("sessionID", session_id);
            updateDomainXML(sd_host, sd_admin_port, true, url, content, false);

        } catch (Exception e) {
            logger.warn("Unable to access admin interface: " + e);

            logger.warn("Update security domain using agent interface");
            url = "/ca/agent/ca/updateDomainXML";
            updateDomainXML(sd_host, sd_agent_port, true, url, content, true);
        }

        // Fetch the "updated" security domain and display it
        logger.debug("updateSecurityDomain(): Dump contents of updated Security Domain . . .");
        @SuppressWarnings("unused")
        String c = getDomainXML(sd_host, sd_admin_port, true);
    }

    public static boolean isSDHostDomainMaster(IConfigStore config) throws Exception {
        String dm = "false";

        String hostname = config.getString("securitydomain.host");
        int httpsadminport = config.getInteger("securitydomain.httpsadminport");

        logger.debug("isSDHostDomainMaster(): Getting domain.xml from CA...");
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
            String servlet, MultivaluedMap<String, String> content, boolean useClientAuth)
            throws Exception {

        logger.debug("ConfigurationUtils: updateDomainXML start hostname=" + hostname + " port=" + port);

        String c = null;
        if (useClientAuth) {
            IConfigStore cs = CMS.getConfigStore();
            String nickname = cs.getString("preop.cert.subsystem.nickname", "");
            String tokenname = cs.getString("preop.module.token", "");

            if (!CryptoUtil.isInternalToken(tokenname)) {
                nickname = tokenname + ":" + nickname;
            }
            logger.debug("updateDomainXML() nickname=" + nickname);

            c = post(hostname, port, https, servlet, content, nickname, null);

        } else {
            c = post(hostname, port, https, servlet, content, null, null);
        }

        if (c == null || c.equals("")) {
            logger.error("Unable to update security domain: empty response");
            throw new IOException("Unable to update security domain: empty response");
        }

        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject obj = new XMLObject(bis);
            String status = obj.getValue("Status");
            logger.debug("ConfigurationUtils: updateDomainXML: status=" + status);

            if (status.equals(SUCCESS)) {
                return;

            } else if (status.equals(AUTH_FAILURE)) {
                logger.error("Unable to update security domain: authentication failure");
                throw new IOException("Unable to update security domain: authentication failure");

            } else {
                String error = obj.getValue("Error");
                logger.error("Unable to update security domain: " + error);
                throw new IOException("Unable to update security domain: " + error);
            }

        } catch (SAXParseException e) {
            logger.error("Response: " + c);
            logger.error("Unable to update security domain: " + e);
            throw new IOException("Unable to update security domain: " + e, e);
        }
    }

    public static void setupClientAuthUser() throws Exception {
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
            certs[0] = new X509CertImpl(Utils.base64decode(b64));
            user.setX509Certificates(certs);
            try {
                logger.debug("setupClientAuthUser: adding user: " + id);
                system.addUser(user);
            } catch (ConflictingOperationException e) {
                // ignore exception
                logger.warn("setupClientAuthUser: User already exists: " + e);
            }
            try {
                logger.debug("setupClientAuthUser: Adding cert to user: " + id);
                system.addUserCert(user);
            } catch (ConflictingOperationException e) {
                // ignore exception
                logger.warn("setupClientAuthUser: Cert already added: " + e);
            }
            cs.commit(false);
        }

        String groupName = "Trusted Managers";
        IGroup group = system.getGroupFromName(groupName);
        if (!group.isMember(id)) {
            logger.debug("setupClientAuthUser: adding user to the " + groupName + " group.");
            group.addMemberName(id);
            system.modifyGroup(group);
        }

    }

    public static String getSubsystemCert(String host, int port, boolean https)
            throws Exception {

        logger.debug("getSubsystemCert() start");

        String c = get(host, port, https, "/ca/admin/ca/getSubsystemCert", null, null);

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
            throws Exception {
        logger.debug("getTransportCert() start");
        String sessionId = CMS.getConfigSDSessionId();

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionId);
        content.putSingle("auth_hostname", secdomainURI.getHost());
        content.putSingle("auth_port", secdomainURI.getPort() + "");

        String c = post(
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
            EBaseException, URISyntaxException, InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NotInitializedException, TokenException, ObjectNotFoundException,
            IOException {
        IConfigStore cs = CMS.getConfigStore();
        String host = cs.getString("service.machineName");
        String port = cs.getString("service.securePort");
        String dbDir = cs.getString("instanceRoot") + "/alias";
        String dbNick = cs.getString("tps.cert.subsystem.nickname");

        String passwordFile = cs.getString("passwordFile");
        IConfigStore psStore = CMS.createFileConfigStore(passwordFile);
        String dbPass = psStore.getString("internal");

        ClientConfig config = new ClientConfig();
        config.setServerURL("https://" + tksHost + ":" + tksPort);
        config.setNSSDatabase(dbDir);
        config.setNSSPassword(dbPass);
        config.setCertNickname(dbNick);

        PKIClient client = new PKIClient(config, null);

        logger.debug("In ConfigurationUtils.getSharedSecret! importKey: " + importKey);

        // Ignore the "UNTRUSTED_ISSUER" and "CA_CERT_INVALID" validity status
        // during PKI instance creation since we are using an untrusted temporary CA cert.
        client.addIgnoredCertStatus(SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER);
        client.addIgnoredCertStatus(SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID);

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


        // The connId or data.getID will be the id of the shared secret
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

        String nick = "TPS-" + host + "-" + port + " sharedSecret";

        if (importKey) {
            logger.debug("getSharedSecret: About to attempt to import shared secret key.");
            byte[] sessionKeyData = Utils.base64decode(keyData.getWrappedPrivateData());
            byte[] sharedSecretData = Utils.base64decode(keyData.getAdditionalWrappedPrivateData());

            try {
                CryptoUtil.importSharedSecret(sessionKeyData, sharedSecretData, dbNick, nick);
            } catch (Exception e) {
                logger.warn("getSharedSecret()): WARNING, Failed to automatically import shared secret. Please follow the manual procedure." + e.toString());
            }
            // this is not needed if we are using a shared database with
            // the tks.
        }

        // store the new nick in CS.cfg

        cs.putString("conn.tks1.tksSharedSymKeyName", nick);
        cs.commit(false);
    }

    public static void setupDBUser() throws CertificateException, LDAPException, EBaseException,
            NotInitializedException, ObjectNotFoundException, TokenException, IOException {

        IUGSubsystem system = (IUGSubsystem) CMS.getSubsystem(IUGSubsystem.ID);

        // checking existing user
        IUser user = system.getUser(DBUSER);

        if (user != null) {
            // user found
            logger.warn("setupDBUser(): user already exists: " + DBUSER);
            return;
        }

        // user not found
        logger.debug("setupDBUser(): creating user: " + DBUSER);

        String b64 = getSubsystemCert();
        if (b64 == null) {
            logger.error("setupDBUser(): failed to fetch subsystem cert");
            throw new EBaseException("setupDBUser(): failed to fetch subsystem cert");
        }

        user = system.createUser(DBUSER);
        user.setFullName(DBUSER);
        user.setEmail("");
        user.setPassword("");
        user.setUserType("agentType");
        user.setState("1");
        user.setPhone("");

        X509CertImpl[] certs = new X509CertImpl[1];
        certs[0] = new X509CertImpl(Utils.base64decode(b64));
        user.setX509Certificates(certs);

        system.addUser(user);
        logger.debug("setupDBUser(): successfully added " + DBUSER);

        system.addUserCert(user);
        logger.debug("setupDBUser(): successfully add the user certificate");

        // set subject dn
        system.addCertSubjectDN(user);

        // remove old db users
        logger.debug("setupDBUser(): removing seeAlso from old dbusers");
        removeOldDBUsers(certs[0].getSubjectDN().toString());

        // workaround for ticket #1595
        IConfigStore cs = CMS.getConfigStore();
        String csType = cs.getString("cs.type").toUpperCase();

        Collection<String> groupNames = new ArrayList<String>();

        if ("CA".equals(csType)) {
            groupNames.add("Subsystem Group");
            groupNames.add("Certificate Manager Agents");

        } else if ("KRA".equals(csType)) {
            groupNames.add("Data Recovery Manager Agents");
            groupNames.add("Trusted Managers");

        } else if ("OCSP".equals(csType)) {
            groupNames.add("Trusted Managers");

        } else if ("TKS".equals(csType)) {
            groupNames.add("Token Key Service Manager Agents");
        }

        for (String groupName : groupNames) {
            IGroup group = system.getGroupFromName(groupName);
            if (!group.isMember(DBUSER)) {
                logger.debug("setupDBUser(): adding " + DBUSER + " to the " + groupName + " group.");
                group.addMemberName(DBUSER);
                system.modifyGroup(group);
            }
        }
    }

    public static void addProfilesToTPSUser(String adminID) throws EUsrGrpException, LDAPException {
        logger.debug("Adding all profiles to TPS admin user");
        IUGSubsystem system = (IUGSubsystem) CMS.getSubsystem(IUGSubsystem.ID);
        IUser user = system.getUser(adminID);

        List<String> profiles = new ArrayList<String>();
        profiles.add(UserResource.ALL_PROFILES);

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

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("uid", uid);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionId);
        content.putSingle("auth_hostname", secdomainURI.getHost());
        content.putSingle("auth_port", secdomainURI.getPort() + "");
        content.putSingle("certificate", getSubsystemCert());
        content.putSingle("name", subsystemName);

        String targetURL = "/" + targetType + "/admin/" + targetType + "/registerUser";

        String response = post(
                targetURI.getHost(),
                targetURI.getPort(),
                true,
                targetURL,
                content, null, null);

        if (response == null || response.equals("")) {
            logger.error("registerUser: response is empty or null.");
            throw new IOException("The server " + targetURI + "is not available");

        } else {
            logger.debug("registerUser: response: " + response);
            ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
            XMLObject parser = new XMLObject(bis);

            String status = parser.getValue("Status");
            logger.debug("registerUser: status=" + status);

            if (status.equals(SUCCESS)) {
                logger.debug("registerUser: Successfully added user " + uid + " to " + targetURI +
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

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("name", name);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionId);
        content.putSingle("auth_hostname", secdomainURI.getHost());
        content.putSingle("auth_port", secdomainURI.getPort() + "");
        content.putSingle("certificate", transportCert);

        String targetURL = "/tks/admin/tks/importTransportCert";

        String response = post(
                targetURI.getHost(),
                targetURI.getPort(),
                true,
                targetURL,
                content, null, null);

        if (response == null || response.equals("")) {
            logger.error("exportTransportCert: response is empty or null.");
            throw new IOException("The server " + targetURI + " is not available");
        } else {
            ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
            XMLObject parser = new XMLObject(bis);

            String status = parser.getValue("Status");
            logger.debug("exportTransportCert: status=" + status);

            if (status.equals(SUCCESS)) {
                logger.debug("exportTransportCert: Successfully added transport cert to " + targetURI);
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
        ILdapConnFactory dbFactory = new LdapBoundConnFactory("ConfigurationUtils");
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
                logger.debug("removeOldDUsers: Removing seeAlso from " + uid);
                system.removeCertSubjectDN(user);
            }
        }
    }

    public static String getSubsystemCert() throws EBaseException, NotInitializedException, ObjectNotFoundException,
            TokenException, CertificateEncodingException, IOException {

        IConfigStore cs = CMS.getConfigStore();
        String subsystem = cs.getString(PCERT_PREFIX + "subsystem.subsystem");

        String nickname = cs.getString(subsystem + ".subsystem.nickname");
        String tokenname = cs.getString(subsystem + ".subsystem.tokenname");

        if (!CryptoUtil.isInternalToken(tokenname)) {
            nickname = tokenname + ":" + nickname;
        }

        logger.debug("ConfigurationUtils: getSubsystemCert: nickname=" + nickname);

        CryptoManager cm = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate cert = cm.findCertByNickname(nickname);
        if (cert == null) {
            logger.warn("ConfigurationUtils: getSubsystemCert: subsystem cert is null");
            return null;
        }
        byte[] bytes = cert.getEncoded();
        String s = CryptoUtil.normalizeCertStr(CryptoUtil.base64Encode(bytes));
        return s;
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
        ILdapConnFactory dbFactory = new LdapBoundConnFactory("ConfigurationUtils");
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
     *
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
