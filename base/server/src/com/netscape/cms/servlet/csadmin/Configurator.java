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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.StringTokenizer;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NicknameConflictException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.UserCertConflictException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXParseException;

import com.netscape.certsrv.account.AccountClient;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.CloneSetupRequest;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.DatabaseSetupRequest;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainSetupRequest;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.apps.ServerXml;
import com.netscape.cmscore.apps.SubsystemConfig;
import com.netscape.cmscore.apps.SubsystemsConfig;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.xml.XMLObject;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;

/**
 * Utility class for functions to be used by the RESTful installer.
 *
 * @author alee
 *
 */
public class Configurator {

    public final static Logger logger = LoggerFactory.getLogger(Configurator.class);

    // Hard coded values for ECC and RSA internal cert profile names
    public static final String ECC_INTERNAL_SERVER_CERT_PROFILE = "caECInternalAuthServerCert";
    public static final String RSA_INTERNAL_SERVER_CERT_PROFILE = "caInternalAuthServerCert";

    public static final String ECC_INTERNAL_SUBSYSTEM_CERT_PROFILE = "caECInternalAuthSubsystemCert";
    public static final String RSA_INTERNAL_SUBSYSTEM_CERT_PROFILE = "caInternalAuthSubsystemCert";

    public static final String ECC_INTERNAL_ADMIN_CERT_PROFILE = "caECAdminCert";
    public static final String RSA_INTERNAL_ADMIN_CERT_PROFILE = "caAdminCert";

    public static String SUCCESS = "0";
    public static String FAILURE = "1";
    public static String AUTH_FAILURE = "2";
    public static final BigInteger BIG_ZERO = new BigInteger("0");
    public static final Long MINUS_ONE = Long.valueOf(-1);
    public static final String DBUSER = "pkidbuser";

    public static ConfigCertApprovalCallback certApprovalCallback = new ConfigCertApprovalCallback();

    protected CMSEngine engine;
    protected EngineConfig cs;
    protected ServerXml serverXml;

    public Configurator(CMSEngine engine) {
        this.engine = engine;
        this.cs = engine.getConfig();
        this.serverXml = engine.getServerXml();
    }

    public static PKIClient createClient(
            String serverURL,
            String clientnickname,
            SSLCertificateApprovalCallback certApprovalCallback)
            throws Exception {

        ClientConfig config = new ClientConfig();
        config.setServerURL(serverURL);
        config.setCertNickname(clientnickname);

        if (certApprovalCallback == null) certApprovalCallback = Configurator.certApprovalCallback;

        return new PKIClient(config, null, certApprovalCallback);
    }

    public void setConfigStore(EngineConfig cs) {
        this.cs = cs;
    }

    public void setServerXml(ServerXml serverXml) throws Exception {
        this.serverXml = serverXml;
    }

    public void configureSecurityDomain(ConfigurationRequest request) throws Exception {

        String securityDomainType = request.getSecurityDomainType();

        if (securityDomainType.equals(ConfigurationRequest.NEW_DOMAIN)) {
            logger.info("Creating new security domain");
            return;
        }

        if (securityDomainType.equals(ConfigurationRequest.NEW_SUBDOMAIN)){
            logger.info("Configuring new security subdomain");
            return;
        }

        logger.info("Joining existing security domain");

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String keyType = preopConfig.getString("cert.subsystem.keytype");
        String profileID = getSystemCertProfileID(keyType, "subsystem", "caInternalAuthSubsystemCert");
        preopConfig.putString("cert.subsystem.profile", profileID);
    }

    private String logIntoSecurityDomain(
            ConfigurationRequest request,
            String hostname,
            int port,
            String username,
            String password,
            Long sleep) throws Exception {

        logger.debug("Getting installation token from security domain");

        String installToken;

        try {
            installToken = getInstallToken(hostname, port, username, password);
        } catch (Exception e) {
            logger.error("Unable to get installation token: " + e.getMessage(), e);
            throw new PKIException("Unable to get installation token: " + e.getMessage(), e);
        }

        if (installToken == null) {
            logger.error("Missing installation token");
            throw new PKIException("Missing installation token");
        }

        /* Sleep for a bit to allow security domain session to replicate
         * to other clones.  In the future we can use signed tokens
         * (ticket https://pagure.io/dogtagpki/issue/2831) but we need to
         * be mindful of working with older versions, too.
         *
         * The default sleep time is 5s.
         */
        if (null == sleep || sleep <= 0) {
            sleep = new Long(5);
        }

        logger.debug("Logged into security domain; sleeping for " + sleep + "s");
        Thread.sleep(sleep * 1000);

        return installToken;
    }

    public String getInstallToken(String sdhost, int sdport, String user, String passwd) throws Exception {

        String csType = cs.getType();

        ClientConfig config = new ClientConfig();
        config.setServerURL("https://" + sdhost + ":" + sdport);
        config.setUsername(user);
        config.setPassword(passwd);

        PKIClient client = new PKIClient(config);

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
            logger.info("Logging into security domain");
            accountClient.login();

            logger.info("Getting install token");
            InstallToken token = sdClient.getInstallToken(sdhost, csType);

            logger.info("Logging out of security domain");
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

    public String getOldCookie(String sdhost, int sdport, String user, String passwd) throws Exception {

        String subca_url = "https://" + engine.getEEHost() + ":"
                + engine.getAdminPort() + "/ca/admin/console/config/wizard" +
                "?p=5&subsystem=" + cs.getType();

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("uid", user);
        content.putSingle("pwd", passwd);
        content.putSingle("url", subca_url);

        String serverURL = "https://" + sdhost + ":" + sdport;

        PKIClient client = Configurator.createClient(serverURL, null, null);
        String body = client.post("/ca/admin/ca/getCookie", content);
        logger.debug("Configurator: response: " + body);

        return getContentValue(body, "header.session_id");
    }

    public String getContentValue(String body, String header) {

        logger.debug("Configurator: searching for " + header);

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

    private DomainInfo getDomainInfo(String hostname, int port) throws Exception {

        logger.info("Getting security domain info");

        ClientConfig config = new ClientConfig();
        config.setServerURL("https://" + hostname + ":" + port);

        PKIClient client = new PKIClient(config);

        // Ignore the "UNTRUSTED_ISSUER" validity status
        // during PKI instance creation since we are
        // utilizing an untrusted temporary CA certificate.
        client.addIgnoredCertStatus(SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER);

        // Ignore the "CA_CERT_INVALID" validity status
        // during PKI instance creation since we are
        // utilizing an untrusted temporary CA certificate.
        client.addIgnoredCertStatus(SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID);

        SecurityDomainClient sdClient = new SecurityDomainClient(client, "ca");

        return sdClient.getDomainInfo();
    }

    public SecurityDomainHost getHostInfo(
            DomainInfo domainInfo,
            String csType,
            String hostname,
            int securePort) throws Exception {

        SecurityDomainSubsystem subsystem = domainInfo.getSubsystem(csType);

        for (SecurityDomainHost host : subsystem.getHostArray()) {

            if (!host.getHostname().equals(hostname)) continue;
            if (!host.getSecurePort().equals(securePort + "")) continue;

            return host;
        }

        return null;
    }

    public void setupClone(CloneSetupRequest request) throws Exception {

        String csType = cs.getType();
        PreOpConfig preopConfig = cs.getPreOpConfig();

        String sessionID = request.getInstallToken().getToken();

        String cloneUri = request.getCloneUri();
        URL url = new URL(cloneUri);
        String masterHostname = url.getHost();
        int masterPort = url.getPort();

        logger.debug("SystemConfigService: getting " + csType + " master host info: " + url);

        DomainInfo domainInfo = request.getDomainInfo();
        logger.info("Domain: " + domainInfo);

        SecurityDomainHost masterHost = getHostInfo(domainInfo, csType, masterHostname, masterPort);

        if (masterHost == null) {
            throw new BadRequestException("Clone URI does not match available subsystems: " + url);
        }

        String masterAdminPort = masterHost.getSecureAdminPort();

        preopConfig.putString("master.hostname", masterHostname);
        preopConfig.putInteger("master.httpsport", masterPort);
        preopConfig.putString("master.httpsadminport", masterAdminPort);

        cs.commit(false);

        if (csType.equals("CA") || csType.equals("KRA")) {
            setupNumberRanges(sessionID, masterHost);
        }

        logger.debug("SystemConfigService: get configuration entries from master");
        getConfigEntriesFromMaster(sessionID, masterHost);

        String token = preopConfig.getString("module.token", null);
        CryptoUtil.getKeyStorageToken(token); // throw exception if token doesn't exist

        if (!CryptoUtil.isInternalToken(token)) {
            logger.debug("SystemConfigService: import certificates from HSM and set permission");
            importAndSetCertPermissionsFromHSM();
        }

        logger.debug("SystemConfigService: verify certificates");
        verifySystemCertificates();

        if (request.getSetupReplication()) {
            setupReplication(request);
        }
    }

    public void setupNumberRanges(
            String sessionID,
            SecurityDomainHost masterHost) throws Exception {

        logger.info("Setting up number ranges");

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String masterHostname = masterHost.getHostname();
        int masterAdminPort = Integer.parseInt(masterHost.getSecureAdminPort());
        int masterEEPort = Integer.parseInt(masterHost.getSecurePort());

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("type", "request");
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionID);
        updateNumberRange(masterHostname, masterEEPort, masterAdminPort, true, content, "request");

        content = new MultivaluedHashMap<String, String>();
        content.putSingle("type", "serialNo");
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionID);
        updateNumberRange(masterHostname, masterEEPort, masterAdminPort, true, content, "serialNo");

        content = new MultivaluedHashMap<String, String>();
        content.putSingle("type", "replicaId");
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionID);
        updateNumberRange(masterHostname, masterEEPort, masterAdminPort, true, content, "replicaId");

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        dbConfig.putString("enableSerialManagement", "true");

        cs.commit(false);
    }

    public void updateNumberRange(String hostname, int eePort, int adminPort, boolean https,
            MultivaluedMap<String, String> content, String type) throws Exception {

        String cstype = cs.getType();
        logger.info("Getting " + type + " number range from " + cstype + " master");

        String subsystem = cstype.toLowerCase();
        String serverURL = "https://" + hostname + ":" + adminPort;

        PKIClient client = createClient(serverURL, null, null);
        String response = client.post("/" + subsystem + "/admin/" + subsystem + "/updateNumberRange", content);
        logger.debug("Response: " + response);

        if (StringUtils.isEmpty(response)) {
            String message = "Unable to get " + type + " number range from " + cstype + " master";
            logger.error(message);
            throw new IOException(message);
        }

        // when the admin servlet is unavailable, we return a badly formatted error page
        XMLObject parser = new XMLObject(new ByteArrayInputStream(response.getBytes()));

        String status = parser.getValue("Status");
        logger.debug("Status: " + status);

        if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);
        }

        if (!status.equals(SUCCESS)) {
            String error = parser.getValue("Error");
            throw new IOException(error);
        }

        String beginNumber = parser.getValue("beginNumber");
        logger.info("Begin number: " + beginNumber);

        String endNumber = parser.getValue("endNumber");
        logger.info("End number: " + endNumber);

        DatabaseConfig dbConfig = cs.getDatabaseConfig();

        if (type.equals("request")) {
            dbConfig.putString("beginRequestNumber", beginNumber);
            dbConfig.putString("endRequestNumber", endNumber);

        } else if (type.equals("serialNo")) {
            dbConfig.putString("beginSerialNumber", beginNumber);
            dbConfig.putString("endSerialNumber", endNumber);

        } else if (type.equals("replicaId")) {
            dbConfig.putString("beginReplicaNumber", beginNumber);
            dbConfig.putString("endReplicaNumber", endNumber);
        }
    }

    public void getConfigEntriesFromMaster(
            String sessionID,
            SecurityDomainHost masterHost) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String cstype = cs.getType();

        cstype = cstype.toLowerCase();

        String masterHostname = masterHost.getHostname();
        int masterAdminPort = Integer.parseInt(masterHost.getSecureAdminPort());

        StringBuffer c1 = new StringBuffer();
        StringBuffer s1 = new StringBuffer();

        String value = preopConfig.getString("cert.list");
        String[] certList = value.split(",");

        for (String tag : certList) {

            if (tag.equals("sslserver")) {
                continue;
            }

            if (s1.length() != 0) {
                s1.append(",");
            }

            s1.append(cstype + "." + tag);
        }

        if (!cstype.equals("ca")) {
            c1.append(",cloning.ca.type");
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
        content.putSingle("names", "internaldb.ldapauth.password,internaldb.replication.password" + c1);
        content.putSingle("substores", s1.toString());
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionID);

        updateConfigEntries(masterHostname, masterAdminPort, true,
                "/" + cstype + "/admin/" + cstype + "/getConfigEntries", content);

        preopConfig.putString("clone.configuration", "true");

        cs.commit(false);
    }

    public void updateConfigEntries(String hostname, int port, boolean https,
            String servlet, MultivaluedMap<String, String> content)
            throws Exception {

        String cstype = cs.getType();
        logger.info("Getting " + cstype + " master configuration entries");

        String subsystem = cs.getType().toLowerCase();

        PreOpConfig preopConfig = cs.getPreOpConfig();

        LDAPConfig masterConfig = preopConfig.getSubStore("internaldb.master", LDAPConfig.class);
        LDAPConnectionConfig masterConnConfig = masterConfig.getConnectionConfig();

        LDAPConfig replicaConfig = cs.getInternalDBConfig();
        LDAPConnectionConfig replicaConnConfig = replicaConfig.getConnectionConfig();

        String serverURL = "https://" + hostname + ":" + port;

        PKIClient client = Configurator.createClient(serverURL, null, null);
        String response = client.post("/" + subsystem + "/admin/" + subsystem + "/getConfigEntries", content);

        if (response == null) {
            throw new IOException("Unable to get " + cstype + " master configuration");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        logger.debug("Status: " + status);

        if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);
        }

        if (!status.equals(SUCCESS)) {
            String error = parser.getValue("Error");
            throw new IOException(error);
        }

        logger.info("Retrieved configuration entries:");

        Document doc = parser.getDocument();
        NodeList list = doc.getElementsByTagName("name");
        int len = list.getLength();

        for (int i = 0; i < len; i++) {
            Node n = list.item(i);
            NodeList nn = n.getChildNodes();
            String name = nn.item(0).getNodeValue();
            logger.info("- " + name);

            Node parent = n.getParentNode();
            nn = parent.getChildNodes();
            int len1 = nn.getLength();

            String v = "";
            for (int j = 0; j < len1; j++) {
                Node nv = nn.item(j);
                String val = nv.getNodeName();

                if (val.equals("value")) {
                    NodeList n2 = nv.getChildNodes();
                    if (n2.getLength() > 0) {
                        v = n2.item(0).getNodeValue();
                    }
                    break;
                }
            }

            if (name.startsWith("internaldb")) {
                preopConfig.putString(name.replaceFirst("internaldb", "internaldb.master"), v);

            } else if (name.startsWith("cloning.ca")) {
                cs.putString(name.replaceFirst("cloning", "preop"), v);

            } else if (name.startsWith("cloning")) {
                cs.putString(name.replaceFirst("cloning", "preop.cert"), v);

            } else {
                cs.putString(name, v);
            }
        }

        String masterHostname = masterConnConfig.getString("host", "");
        String masterPort = masterConnConfig.getString("port", "");

        String replicaHostname = cs.getHostname();
        String replicaPort = replicaConnConfig.getString("port");

        if (masterHostname.equals(replicaHostname) && masterPort.equals(replicaPort)) {
            throw new BadRequestException("Master and clone must not share the same LDAP database");
        }
    }

    public void verifySystemCertificates() throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        PreOpConfig preopConfig = cs.getPreOpConfig();

        String certList = preopConfig.getString("cert.list");
        String cstype = cs.getType().toLowerCase();
        StringTokenizer st = new StringTokenizer(certList, ",");

        while (st.hasMoreTokens()) {
            String tag = st.nextToken();

            if (tag.equals("sslserver"))
                continue;

            String nickname = cs.getString(cstype + ".cert." + tag + ".nickname");
            logger.info("Checking " + tag + " certificate: " + nickname);

            try {
                cm.findCertByNickname(nickname);

            } catch (ObjectNotFoundException e) {
                throw new Exception("Missing system certificate: " + nickname, e);
            }
        }
    }

    /* We need to import the audit signing cert and CA signing cert to the soft token in order to
     * correctly set the trust permissions.
     */
    public void importAndSetCertPermissionsFromHSM() throws EBaseException, NotInitializedException,
            IOException, CertificateEncodingException, NicknameConflictException, UserCertConflictException,
            NoSuchItemOnTokenException, TokenException {

        CryptoManager cm = CryptoManager.getInstance();
        PreOpConfig preopConfig = cs.getPreOpConfig();

        // nickname has no token prepended to it, so no need to strip
        String nickname = preopConfig.getString("cert.audit_signing.nickname");
        String cstype = cs.getType();
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
            nickname = preopConfig.getString("cert.signing.nickname");
            certStr = cs.getString(cstype + ".signing.cert");
            cert = CryptoUtil.base64Decode(certStr);
            xcert = cm.importUserCACertPackage(cert, nickname);
            icert = (InternalCertificate) xcert;
            icert.setSSLTrust(InternalCertificate.TRUSTED_CA
                    | InternalCertificate.TRUSTED_CLIENT_CA
                    | InternalCertificate.VALID_CA);
        }
    }

    public void setupDatabase(DatabaseSetupRequest request) throws Exception {
        reinitSubsystems();
    }

    public void reinitSubsystems() throws EBaseException {

        engine.setSubsystemEnabled(UGSubsystem.ID, true);

        engine.reinit(UGSubsystem.ID);
        engine.reinit(AuthSubsystem.ID);
        engine.reinit(AuthzSubsystem.ID);
    }

    public void setupReplication(CloneSetupRequest request) throws Exception {

        IPasswordStore passwordStore = engine.getPasswordStore();

        String instanceId = cs.getInstanceID();
        String subsystem = cs.getType().toLowerCase();
        PreOpConfig preopConfig = cs.getPreOpConfig();

        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        String database = ldapConfig.getDatabase();
        String baseDN = ldapConfig.getBaseDN();
        String databaseDN = "cn=" + LDAPUtil.escapeRDNValue(database) + ",cn=ldbm database, cn=plugins, cn=config";
        String mappingDN = "cn=\"" + baseDN + "\",cn=mapping tree, cn=config";

        LdapBoundConnFactory ldapFactory = new LdapBoundConnFactory("LDAPConfigurator");
        ldapFactory.init(cs, ldapConfig, passwordStore);

        LDAPConnection conn = ldapFactory.getConn();
        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, instanceId, ldapConfig);

        try {
            LDAPConfig masterConfig = preopConfig.getSubStore("internaldb.master", LDAPConfig.class);
            LDAPConnectionConfig masterConnConfig = masterConfig.getConnectionConfig();
            String masterPort = masterConnConfig.getString("port", "");

            String masterReplicationPort = request.getMasterReplicationPort();
            if (masterReplicationPort == null || masterReplicationPort.equals("")) {
                masterReplicationPort = masterPort;
            }

            String masterReplicationPassword = preopConfig.getString("internaldb.master.replication.password", "");
            String replicaReplicationPassword = passwordStore.getPassword("replicationdb", 0);

            // set master ldap password (if it exists) temporarily in password store
            // in case it is needed for replication.  Not stored in password.conf.

            LDAPAuthenticationConfig masterAuthConfig = masterConfig.getAuthenticationConfig();
            String masterPassword = masterAuthConfig.getString("password", "");

            if (!masterPassword.equals("")) {
                masterAuthConfig.putString("bindPWPrompt", "master_internaldb");
                passwordStore.putPassword("master_internaldb", masterPassword);
                passwordStore.commit();
            }

            LdapBoundConnFactory masterFactory = new LdapBoundConnFactory("MasterLDAPConfigurator");
            masterFactory.init(cs, masterConfig, passwordStore);

            LDAPConnection masterConn = masterFactory.getConn();
            LDAPConfigurator masterConfigurator = new LDAPConfigurator(masterConn);

            try {
                setupReplicationAgreement(
                        masterConfigurator,
                        ldapConfigurator,
                        masterReplicationPassword,
                        replicaReplicationPassword,
                        Integer.parseInt(masterReplicationPort),
                        Integer.parseInt(request.getCloneReplicationPort()),
                        request.getReplicationSecurity());

            } finally {
                releaseConnection(masterConn);
            }

            // remove master ldap password from password.conf (if present)

            if (!masterPassword.equals("")) {
                String passwordFile = cs.getString("passwordFile");
                IConfigStore psStore = engine.createFileConfigStore(passwordFile);
                psStore.remove("master_internaldb");
                psStore.commit(false);
            }

            ldapConfigurator.setupDatabaseManager();

            ldapConfigurator.createVLVIndexes(subsystem);
            ldapConfigurator.rebuildVLVIndexes(subsystem);

        } finally {
            releaseConnection(conn);
        }
    }

    public void setupReplicationAgreement(
            LDAPConfigurator masterConfigurator,
            LDAPConfigurator replicaConfigurator,
            String masterReplicationPassword,
            String replicaReplicationPassword,
            int masterReplicationPort,
            int replicaReplicationPort,
            String replicationSecurity) throws Exception {

        logger.info("Configurator: setting up replication");

        PreOpConfig preopConfig = cs.getPreOpConfig();
        DatabaseConfig dbConfig = cs.getDatabaseConfig();

        String hostname = cs.getHostname();
        String instanceID = cs.getInstanceID();

        LDAPConfig masterCfg = preopConfig.getSubStore("internaldb.master", LDAPConfig.class);
        LDAPConnectionConfig masterConnCfg = masterCfg.getConnectionConfig();

        LDAPConfig replicaConfig = cs.getInternalDBConfig();
        LDAPConnectionConfig replicaConnCfg = replicaConfig.getConnectionConfig();

        String baseDN = replicaConfig.getBaseDN();

        String masterHostname = masterConnCfg.getString("host", "");
        String replicaHostname = replicaConnCfg.getString("host", "");

        String masterAgreementName = "masterAgreement1-" + hostname + "-" + instanceID;
        String replicaAgreementName = "cloneAgreement1-" + hostname + "-" + instanceID;

        String replicaDN = "cn=replica,cn=\"" + baseDN + "\",cn=mapping tree,cn=config";
        logger.debug("Configurator: replica DN: " + replicaDN);

        String masterBindUser = "Replication Manager " + masterAgreementName;
        logger.debug("Configurator: creating replication manager on master");
        masterConfigurator.createSystemContainer();
        masterConfigurator.createReplicationManager(masterBindUser, masterReplicationPassword);

        String masterChangelog = masterConfigurator.getInstanceDir() + "/changelogs";
        logger.debug("Configurator: creating master changelog dir: " + masterChangelog);
        masterConfigurator.createChangeLog(masterChangelog);

        String replicaBindUser = "Replication Manager " + replicaAgreementName;
        logger.debug("Configurator: creating replication manager on replica");
        replicaConfigurator.createSystemContainer();
        replicaConfigurator.createReplicationManager(replicaBindUser, replicaReplicationPassword);

        String replicaChangelog = replicaConfigurator.getInstanceDir() + "/changelogs";
        logger.debug("Configurator: creating replica changelog dir: " + masterChangelog);
        replicaConfigurator.createChangeLog(replicaChangelog);

        int replicaID = dbConfig.getInteger("beginReplicaNumber", 1);

        logger.debug("Configurator: enabling replication on master");
        replicaID = masterConfigurator.enableReplication(replicaDN, masterBindUser, baseDN, replicaID);

        logger.debug("Configurator: enabling replication on replica");
        replicaID = replicaConfigurator.enableReplication(replicaDN, replicaBindUser, baseDN, replicaID);

        logger.debug("Configurator: replica ID: " + replicaID);
        dbConfig.putString("beginReplicaNumber", Integer.toString(replicaID));

        logger.debug("Configurator: creating master replication agreement");
        masterConfigurator.createReplicationAgreement(
                replicaDN,
                masterAgreementName,
                replicaHostname,
                replicaReplicationPort,
                replicaReplicationPassword,
                baseDN,
                replicaBindUser,
                replicationSecurity);

        logger.debug("Configurator: creating replica replication agreement");
        replicaConfigurator.createReplicationAgreement(
                replicaDN,
                replicaAgreementName,
                masterHostname,
                masterReplicationPort,
                masterReplicationPassword,
                baseDN,
                masterBindUser,
                replicationSecurity);

        logger.debug("Configurator: initializing replication consumer");
        masterConfigurator.initializeConsumer(replicaDN, masterAgreementName);
    }

    public void releaseConnection(LDAPConnection conn) {
        try {
            if (conn != null)
                conn.disconnect();
        } catch (LDAPException e) {
            logger.warn("releaseConnection: " + e, e);
        }
    }

    public void importLDIFS(LDAPConfigurator ldapConfigurator, String param) throws Exception {
        importLDIFS(ldapConfigurator, param, true);
    }

    public void importLDIFS(LDAPConfigurator ldapConfigurator, String param, boolean ignoreErrors) throws Exception {

        logger.info("Configurator: Importing " + param);

        String filenames = cs.getString(param);
        StringTokenizer tokenizer = new StringTokenizer(filenames, ",");

        while (tokenizer.hasMoreTokens()) {
            String filename = tokenizer.nextToken().trim();
            ldapConfigurator.importFile(filename, ignoreErrors);
        }
    }

    public boolean deleteDir(File dir) {
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

    public KeyPair loadKeyPair(String nickname, String token) throws Exception {

        logger.debug("Configurator: loadKeyPair(" + nickname + ", " + token + ")");

        CryptoManager cm = CryptoManager.getInstance();

        if (!CryptoUtil.isInternalToken(token)) {
            nickname = token + ":" + nickname;
        }

        logger.debug("Configurator: loading cert: " + nickname);
        X509Certificate cert = cm.findCertByNickname(nickname);

        logger.debug("Configurator: loading public key");
        PublicKey publicKey = cert.getPublicKey();

        logger.debug("Configurator: loading private key");
        PrivateKey privateKey = cm.findPrivKeyByCert(cert);

        return new KeyPair(publicKey, privateKey);
    }

    public KeyPair createECCKeyPair(CryptoToken token, String curveName, String ct)
            throws NoSuchAlgorithmException, NoSuchTokenException, TokenException,
            NotInitializedException, EPropertyNotFound, EBaseException {

        logger.debug("Configurator.createECCKeyPair(" + token + ", " + curveName + ")");

        PreOpConfig preopConfig = cs.getPreOpConfig();

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
            sslType = preopConfig.getString("cert." + ct + "ec.type", "ECDHE");
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
                logger.debug("Configurator: createECCKeypair: sslserver cert for ECDH. Make sure server.xml is set "
                        +
                        "properly with -TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,+TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
                pair = CryptoUtil.generateECCKeyPair(token, curveName, null, ECDH_usages_mask);
            } else {
                if (ct.equals("sslserver")) {
                    logger.debug("Configurator: createECCKeypair: sslserver cert for ECDHE. Make sure server.xml is set "
                            +
                            "properly with +TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,-TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
                }
                pair = CryptoUtil.generateECCKeyPair(token, curveName, null, usages_mask);
            }

            // XXX - store curve , w
            byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();
            String kid = CryptoUtil.encodeKeyID(id);

            // try to locate the private key
            java.security.PrivateKey privk = CryptoUtil.findPrivateKeyFromID(CryptoUtil.decodeKeyID(kid));
            if (privk == null) {
                logger.debug("Found bad ECC key id " + kid);
                pair = null;
            }
        } while (pair == null);

        return pair;
    }

    public KeyPair createRSAKeyPair(CryptoToken token, int keysize, String ct)
            throws Exception {

        logger.debug("Configurator.createRSAKeyPair(" + token + ")");

        KeyPair pair = null;
        do {
            pair = CryptoUtil.generateRSAKeyPair(token, keysize);
            byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();
            String kid = CryptoUtil.encodeKeyID(id);

            // try to locate the private key
            java.security.PrivateKey privk =
                    CryptoUtil.findPrivateKeyFromID(CryptoUtil.decodeKeyID(kid));

            if (privk == null) {
                logger.debug("Found bad RSA key id " + kid);
                pair = null;
            }
        } while (pair == null);

        return pair;
    }

    public X509CertImpl configCert(CertificateSetupRequest request, KeyPair keyPair, Cert certObj) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String certType = certObj.getType();
        logger.debug("Configurator: cert type: " + certType);

        String certTag = certObj.getCertTag();

        String csType = cs.getType();
        String preop_ca_type = null;
        String preop_cert_signing_profile = null;
        String preop_cert_sslserver_type = null;
        String preop_cert_sslserver_profile = null;
        String original_certType = null;
        boolean sign_clone_sslserver_cert_using_master = false;

        if (request.isClone() && csType.equals("CA") && certTag.equals("sslserver")) {

            logger.info("Configuring sslserver cert for CA clone");

            // retrieve and store original 'CS.cfg' entries
            preop_ca_type = preopConfig.getString("ca.type", "");
            preop_cert_signing_profile = preopConfig.getString("cert.signing.profile", "");
            preop_cert_sslserver_type = preopConfig.getString("cert.sslserver.type", "");
            preop_cert_sslserver_profile = preopConfig.getString("cert.sslserver.profile", "");

            // add/modify 'CS.cfg' entries
            preopConfig.putString("ca.type", "sdca");
            preopConfig.putString("cert.signing.profile", "caInstallCACert");
            preopConfig.putString("cert.sslserver.type", "remote");

            String keyType = preopConfig.getString("cert.sslserver.keytype");
            String profileID = getSystemCertProfileID(keyType, "sslserver", "caInternalAuthServerCert");
            preopConfig.putString("cert.sslserver.profile", profileID);

            // store original certType
            original_certType = certType;

            // modify certType
            certObj.setType("remote");

            // fetch revised certType
            certType = certObj.getType();
            logger.debug("Configurator: cert type: " + certType + " (revised)");

            // set master/clone signature flag
            sign_clone_sslserver_cert_using_master = true;
        }

        cs.commit(false);

        if (certType.equals("remote")) {

            logger.info("CertUtil: Generating CSR for " + certTag);

            String dn = preopConfig.getString("cert." + certTag + ".dn");
            logger.debug("CertUtil: subject: " + dn);

            String algorithm = preopConfig.getString("cert." + certTag + ".keyalgorithm");
            logger.debug("CertUtil: algorithm: " + algorithm);

            X509Key key = CryptoUtil.createX509Key(keyPair.getPublic());
            PKCS10 pkcs10 = CryptoUtil.createCertificationRequest(
                    dn,
                    key,
                    keyPair.getPrivate(),
                    algorithm,
                    null);

            byte[] binRequest = pkcs10.toByteArray();
            String b64Request = CryptoUtil.base64Encode(binRequest);
            certObj.setRequest(binRequest);

            String subsystem = preopConfig.getString("cert." + certTag + ".subsystem");
            cs.putString(subsystem + "." + certTag + ".certreq", b64Request);

            String session_id = request.getInstallToken().getToken();

            String preopCaType = preopConfig.getString("ca.type", "");
            logger.debug("Configurator: preop.ca.type: " + preopCaType);

            String profileID = preopConfig.getString("cert." + certTag + ".profile");
            logger.debug("Configurator: profile ID: " + profileID);

            String keyType = preopConfig.getString("cert." + certTag + ".keytype");
            logger.debug("Configurator: key type: " + keyType);

            String actualProfileID = getSystemCertProfileID(keyType, certTag, profileID);
            logger.debug("Configurator: actual profile ID: " + actualProfileID);

            String hostname;
            int port;

            if (certTag.equals("subsystem")) {
                hostname = cs.getString("securitydomain.host", "");
                port = cs.getInteger("securitydomain.httpseeport", -1);

            } else if (sign_clone_sslserver_cert_using_master) {
                // For Cloned CA always use its Master CA to generate the
                // sslserver certificate to avoid any changes which may have
                // been made to the X500Name directory string encoding order.
                hostname = preopConfig.getString("master.hostname", "");
                port = preopConfig.getInteger("master.httpsport", -1);

            } else {
                hostname = preopConfig.getString("ca.hostname", "");
                port = preopConfig.getInteger("ca.httpsport", -1);
            }

            X509CertImpl cert = configRemoteCert(
                    hostname,
                    port,
                    actualProfileID,
                    session_id,
                    b64Request,
                    certTag);

            if (sign_clone_sslserver_cert_using_master) {
                // restore original 'CS.cfg' entries
                preopConfig.putString("ca.type", preop_ca_type);
                preopConfig.putString("cert.signing.profile", preop_cert_signing_profile);
                preopConfig.putString("cert.sslserver.type", preop_cert_sslserver_type);
                preopConfig.putString("cert.sslserver.profile", preop_cert_sslserver_profile);
            }

            return cert;

        } else { // not remote CA, ie, self-signed or local

            ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);

            String dn = preopConfig.getString("cert." + certTag + ".dn");
            String issuerDN = preopConfig.getString("cert.signing.dn", "");
            String algorithm = preopConfig.getString("cert." + certTag + ".keyalgorithm");

            String instanceRoot = cs.getInstanceDir();
            String configurationRoot = cs.getString("configurationRoot");
            String profileName = preopConfig.getString("cert." + certTag + ".profile");
            CertInfoProfile profile = new CertInfoProfile(instanceRoot + configurationRoot + profileName);

            PublicKey publicKey = keyPair.getPublic();
            X509Key x509key = CryptoUtil.createX509Key(publicKey);
            X509CertInfo info = CertUtil.createCertInfo(dn, issuerDN, algorithm, x509key, certType);

            java.security.PrivateKey signingPrivateKey;
            String signingAlgorithm;

            if (certType.equals("selfsign")) {
                signingPrivateKey = keyPair.getPrivate();
                signingAlgorithm = preopConfig.getString("cert.signing.keyalgorithm", "SHA256withRSA");
            } else {
                signingPrivateKey = ca.getSigningUnit().getPrivateKey();
                signingAlgorithm = preopConfig.getString("cert.signing.signingalgorithm", "SHA256withRSA");
            }

            IRequest req = createRequest(certTag, profile, x509key, info);

            RequestId reqId = req.getRequestId();
            preopConfig.putString("cert." + certTag + ".reqId", reqId.toString());

            X509CertImpl cert = CertUtil.createLocalCert(
                    req,
                    profile,
                    info,
                    signingPrivateKey,
                    signingAlgorithm);

            IRequestQueue queue = ca.getRequestQueue();
            queue.updateRequest(req);

            if (cert != null) {
                if (certTag.equals("subsystem")) {
                    logger.debug("configCert: creating subsystem user");
                    setupSubsystemUser(cert);
                }
            }

            return cert;
        }
    }

    private X509CertImpl configRemoteCert(
            String hostname,
            int port,
            String actualProfileId,
            String session_id,
            String b64Request,
            String certTag)
            throws Exception {

        logger.info("Configurator: Creating remote " + certTag + " certificate");

        X509CertImpl cert = null;

        String sysType = cs.getType();
        String machineName = cs.getHostname();
        String securePort = cs.getString("service.securePort", "");

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("requestor_name", sysType + "-" + machineName + "-" + securePort);
        content.putSingle("profileId", actualProfileId);
        content.putSingle("cert_request_type", "pkcs10");
        content.putSingle("cert_request", b64Request);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", session_id);

        Boolean injectSAN = cs.getBoolean("service.injectSAN", false);
        logger.debug("Configurator: injectSAN: " + injectSAN);

        if (certTag.equals("sslserver") && injectSAN) {
            CertUtil.buildSANSSLserverURLExtension(cs, content);
        }

        cert = CertUtil.createRemoteCert(hostname, port, content);

        if (cert == null) {
            throw new IOException("Unable to create remote certificate");
        }

        return cert;
    }

    public String getNickname(String certTag) throws EBaseException {

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String instanceID = cs.getInstanceID();

        String nickname = certTag + "Cert cert-" + instanceID;
        String preferredNickname = preopConfig.getString("cert." + certTag + ".nickname", null);

        if (preferredNickname != null) {
            return preferredNickname;
        }
        return nickname;
    }

    public void generateCertRequest(String certTag, KeyPair keyPair, Cert cert) throws Exception {

        logger.debug("generateCertRequest: getting public key for certificate " + certTag);

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String algorithm = preopConfig.getString("cert." + certTag + ".keyalgorithm");

        PublicKey publicKey = keyPair.getPublic();
        X509Key x509key = CryptoUtil.createX509Key(publicKey);
        java.security.PrivateKey privk = keyPair.getPrivate();

        // construct cert request
        String caDN = preopConfig.getString("cert." + certTag + ".dn");

        cert.setDN(caDN);

        Extensions exts = new Extensions();
        if (certTag.equals("signing")) {
            logger.debug("generateCertRequest: generating basic CA extensions");
            createBasicCAExtensions(exts);
        }

        String extOID = preopConfig.getString("cert." + certTag + ".ext.oid", null);
        String extData = preopConfig.getString("cert." + certTag + ".ext.data", null);

        if (extOID != null && extData != null) {
            logger.debug("Configurator: Creating generic extension");
            boolean extCritical = preopConfig.getBoolean("cert." + certTag + ".ext.critical");
            Extension ext = createGenericExtension(extOID, extData, extCritical);
            exts.add(ext);
        }

        logger.debug("generateCertRequest: generating PKCS #10 request");
        PKCS10 certReq = CryptoUtil.createCertificationRequest(caDN, x509key, privk, algorithm, exts);

        logger.debug("generateCertRequest: storing cert request");
        byte[] certReqb = certReq.toByteArray();
        String certReqs = CryptoUtil.base64Encode(certReqb);

        String subsystem = preopConfig.getString("cert." + certTag + ".subsystem");
        cs.putString(subsystem + "." + certTag + ".certreq", certReqs);
        cs.commit(false);

        cert.setRequest(certReqb);
    }

    /*
     * createBasicCAExtensions creates the basic Extensions needed for a CSR to a
     * CA signing certificate
     */
    private void createBasicCAExtensions(Extensions exts) throws Exception {
        logger.debug("Configurator: createBasicCAExtensions: begins");

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

    private Extension createGenericExtension(String oid, String data, boolean critical) throws Exception {

        try (DerOutputStream out = new DerOutputStream()) {

            byte[] bytes = CryptoUtil.hexString2Bytes(data);
            out.putOctetString(bytes);

            return new Extension(
                    new ObjectIdentifier(oid),
                    critical,
                    out.toByteArray());
        }
    }

    public IRequest createRequest(
            String tag,
            CertInfoProfile profile,
            X509Key x509key,
            X509CertInfo info) throws Exception {

        logger.debug("Configurator.createRequest(" + tag + ")");

        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        IRequestQueue queue = ca.getRequestQueue();

        Boolean injectSAN = cs.getBoolean("service.injectSAN", false);
        String[] sanHostnames = null;

        if (tag.equals("sslserver") && injectSAN) {
            String value = cs.getString("service.sslserver.san");
            sanHostnames = StringUtils.split(value, ",");
        }

        boolean installAdjustValidity = !tag.equals("signing");

        return CertUtil.createLocalRequest(
                queue,
                profile,
                info,
                x509key,
                sanHostnames,
                installAdjustValidity);
    }

    public void handleCert(Cert cert) throws Exception {

        String certTag = cert.getCertTag();
        logger.debug("Configurator.handleCert(" + certTag + ")");

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String subsystem = cert.getSubsystem();
        String nickname = cert.getNickname();

        logger.debug("Configurator: cert type: " + cert.getType());

        String tokenname = preopConfig.getString("module.token", "");

        byte[] certb = cert.getCert();
        X509CertImpl impl = new X509CertImpl(certb);

        importCert(subsystem, certTag, tokenname, nickname, impl);

        if ((cert.getType().equals("local")) || (cert.getType().equals("selfsign"))) {

            String reqId = preopConfig.getString("cert." + certTag + ".reqId", null);
            if (reqId == null) {
                logger.warn("Configurator: cert has no request record");

            } else {
                // update requests in request queue for local certs to allow renewal
                CertUtil.updateLocalRequest(reqId, cert.getRequest(), "pkcs10", null);
            }
        }
    }

    public void importCert(
            String subsystem,
            String tag,
            String tokenname,
            String nickname,
            X509CertImpl impl
            ) throws Exception {

        logger.debug("Configurator.importCert(" + tag + ")");

        if (tag.equals("sslserver")) {
            logger.info("Configurator: temporary SSL server cert will be replaced on restart");
            return;
        }

        String fullNickname = nickname;
        if (!CryptoUtil.isInternalToken(tokenname)) {
            fullNickname = tokenname + ":" + nickname;
        }

        X509Certificate cert = CertUtil.findCertificate(fullNickname);

        if (cert != null) {
            logger.debug("Configurator: deleting existing " + tag + " cert");
            CertUtil.deleteCert(tokenname, cert);
        }

        logger.debug("Configurator: importing " + tag + " cert");
        cert = CryptoUtil.importUserCertificate(impl.getEncoded(), nickname);

        if (tag.equals("signing") && subsystem.equals("ca")) { // set trust flags to CT,C,C
            CryptoUtil.trustCACert(cert);

        } else if (tag.equals("audit_signing")) { // set trust flags to u,u,Pu
            CryptoUtil.trustAuditSigningCert(cert);

        } // user certs will have u,u,u by default
    }

    public X509CertImpl createAdminCertificate(AdminSetupRequest request) throws Exception {

        if (request.getImportAdminCert().equalsIgnoreCase("true")) {

            String cert = request.getAdminCert();
            logger.info("Configurator: Importing admin cert: " + cert);
            // standalone admin cert is already stored into CS.cfg by configuration.py

            String b64 = CryptoUtil.stripCertBrackets(cert.trim());
            b64 = CryptoUtil.normalizeCertStr(b64);
            byte[] b = CryptoUtil.base64Decode(b64);

            return new X509CertImpl(b);
        }

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String adminSubjectDN = request.getAdminSubjectDN();

        String csType = cs.getType();

        if (csType.equals("CA")) {

            logger.info("Configurator: Generating admin cert");

            createAdminCertificate(request.getAdminCertRequest(),
                    request.getAdminCertRequestType(), adminSubjectDN);

            String serialno = preopConfig.getString("admincert.serialno.0");
            ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
            ICertificateRepository repo = ca.getCertificateRepository();

            return repo.getX509Certificate(new BigInteger(serialno, 16));
        }

        logger.info("Configurator: Requesting admin cert from CA");

        String type = preopConfig.getString("ca.type", "");
        String ca_hostname = "";
        int ca_port = -1;

        if (type.equals("sdca")) {
            ca_hostname = preopConfig.getString("ca.hostname");
            ca_port = preopConfig.getInteger("ca.httpsport");
        } else {
            ca_hostname = cs.getString("securitydomain.host", "");
            ca_port = cs.getInteger("securitydomain.httpseeport");
        }

        String keyType = request.getAdminKeyType();
        String profileID;

        if ("ecc".equalsIgnoreCase(keyType)) {
            profileID = ECC_INTERNAL_ADMIN_CERT_PROFILE;
        } else { // rsa
            profileID = RSA_INTERNAL_ADMIN_CERT_PROFILE;
        }

        logger.debug("Configurator: profile: " + profileID);

        return submitAdminCertRequest(
                request,
                ca_hostname,
                ca_port,
                profileID,
                adminSubjectDN);
    }

    public void updateAdminUserCert(AdminSetupRequest request, X509CertImpl adminCert) throws Exception {

        X509CertImpl[] adminCerts = new X509CertImpl[] { adminCert };

        UGSubsystem ug = engine.getUGSubsystem();
        IUser user = ug.getUser(request.getAdminUID());
        user.setX509Certificates(adminCerts);
        ug.addUserCert(user);
    }

    public void createAdminCertificate(String certRequest, String certRequestType, String subject)
            throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

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

        String caType = preopConfig.getString("cert.admin.type", "local");

        String dn = preopConfig.getString("cert.admin.dn");
        String issuerdn = preopConfig.getString("cert.signing.dn", "");

        String caSigningKeyType = preopConfig.getString("cert.signing.keytype", "rsa");
        String profileFile = cs.getString("profile.caAdminCert.config");
        String defaultSigningAlgsAllowed = cs.getString(
                "ca.profiles.defaultSigningAlgsAllowed", "SHA256withRSA,SHA256withEC,SHA1withDSA");
        String keyAlgorithm = CertUtil.getAdminProfileAlgorithm(
                caSigningKeyType, profileFile, defaultSigningAlgsAllowed);

        X509CertInfo info = CertUtil.createCertInfo(dn, issuerdn, keyAlgorithm, x509key, caType);

        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        java.security.PrivateKey signingPrivateKey = ca.getSigningUnit().getPrivateKey();

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");
        String profileName = preopConfig.getString("cert.admin.profile");
        logger.debug("CertUtil: profile: " + profileName);

        CertInfoProfile profile = new CertInfoProfile(instanceRoot + configurationRoot + profileName);

        // cfu - create request to enable renewal
        IRequestQueue queue = ca.getRequestQueue();

        IRequest req = CertUtil.createLocalRequest(
                queue,
                profile,
                info,
                x509key,
                null /* sanHostnames */,
                true /* installAdjustValidity */);

        RequestId reqId = req.getRequestId();
        preopConfig.putString("cert.admin.reqId", reqId.toString());

        String caSigningKeyAlgo;
        if (caType.equals("selfsign")) {
            caSigningKeyAlgo = preopConfig.getString("cert.signing.keyalgorithm", "SHA256withRSA");
        } else {
            caSigningKeyAlgo = preopConfig.getString("cert.signing.signingalgorithm", "SHA256withRSA");
        }
        logger.debug("Configurator: CA signing key algorithm: " + caSigningKeyAlgo);

        X509CertImpl impl = CertUtil.createLocalCert(
                req,
                profile,
                info,
                signingPrivateKey,
                caSigningKeyAlgo);

        // store request in db
        queue.updateRequest(req);

        // update the locally created request for renewal
        CertUtil.updateLocalRequest(reqId.toString(), binRequest, certRequestType, subject);

        if (ca != null) {
            PKCS7 pkcs7 = createPKCS7(impl);
            byte[] bytes = pkcs7.getBytes();
            String base64 = Utils.base64encodeSingleLine(bytes);

            preopConfig.putString("admincert.pkcs7", base64);
        }

        preopConfig.putString("admincert.serialno.0", impl.getSerialNumber().toString(16));
    }

    public PKCS7 createPKCS7(X509CertImpl cert) throws IOException {

        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        CertificateChain cachain = ca.getCACertChain();
        java.security.cert.X509Certificate[] cacerts = cachain.getChain();

        X509CertImpl[] userChain = new X509CertImpl[cacerts.length + 1];
        for (int i=0; i < cacerts.length; i++) {
            userChain[i + 1] = (X509CertImpl) cacerts[i];
        }
        userChain[0] = cert;

        return new PKCS7(
                new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                userChain,
                new SignerInfo[0]);
    }

    public void setupAdminUser(AdminSetupRequest request, X509CertImpl cert) throws Exception {
        createAdminUser(request);
        updateAdminUserCert(request, cert);
    }

    public void createAdminUser(AdminSetupRequest request) throws Exception {

        String uid = request.getAdminUID();
        String email = request.getAdminEmail();
        String name = request.getAdminName();
        String pwd = request.getAdminPassword();

        PreOpConfig preopConfig = cs.getPreOpConfig();
        UGSubsystem system = engine.getUGSubsystem();

        String groupNames = preopConfig.getString("admin.group", "Certificate Manager Agents,Administrators");

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
            logger.warn("Configurator: createAdmin: addUser " + e);
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

        String select = cs.getString("securitydomain.select", "");
        if (select.equals("new")) {
            group = system.getGroupFromName("Security Domain Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("Configurator: createAdmin:  add user '" + uid
                        + "' to group 'Security Domain Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise CA Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("Configurator: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise CA Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise KRA Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("Configurator: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise KRA Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise RA Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("Configurator: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise RA Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise TKS Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("Configurator: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise TKS Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise OCSP Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("Configurator: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise OCSP Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            group = system.getGroupFromName("Enterprise TPS Administrators");
            if (group != null && !group.isMember(uid)) {
                logger.debug("Configurator: createAdmin:  add user '" + uid
                        + "' to group 'Enterprise TPS Administrators'");
                group.addMemberName(uid);
                system.modifyGroup(group);
            }
        }

        engine.reinit(UGSubsystem.ID);
    }

    public X509CertImpl submitAdminCertRequest(
            AdminSetupRequest request,
            String ca_hostname,
            int ca_port,
            String profileId,
            String subjectDN) throws Exception {

        logger.info("Configurator: Generating admin cert on https://" + ca_hostname + ":" + ca_port);

        PreOpConfig preopConfig = cs.getPreOpConfig();

        if (profileId == null) {
            profileId = preopConfig.getString("admincert.profile", "caAdminCert");
        }

        String certRequestType = request.getAdminCertRequestType();
        String certRequest = request.getAdminCertRequest();
        String session_id = request.getInstallToken().getToken();

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("profileId", profileId);
        content.putSingle("cert_request_type", certRequestType);
        content.putSingle("cert_request", certRequest);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", session_id);
        content.putSingle("subject", subjectDN);

        String serverURL = "https://" + ca_hostname + ":" + ca_port;

        PKIClient client = Configurator.createClient(serverURL, null, null);
        String c = client.post("/ca/ee/ca/profileSubmit", content);

        if (c == null) {
            logger.error("Unable to generate admin certificate: no response from CA");
            throw new IOException("Unable to generate admin certificate: no response from CA");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        logger.info("Configurator: Status: " + status);

        if (status.equals(AUTH_FAILURE)) {
            logger.error("Unable to generate admin certificate: authentication failure");
            throw new EAuthException("Unable to generate admin certificate: authentication failure");
        }

        if (!status.equals(SUCCESS)) {
            String error = parser.getValue("Error");
            logger.error("Unable to generate admin certificate: " + error);
            throw new IOException("Unable to generate admin certificate: " + error);
        }

        String id = parser.getValue("Id");
        logger.info("Configurator: Request ID: " + id);
        preopConfig.putString("admincert.requestId.0", id);

        String serial = parser.getValue("serialno");
        logger.info("Configurator: Serial: " + serial);
        preopConfig.putString("admincert.serialno.0", serial);

        String b64 = parser.getValue("b64");
        logger.info("Configurator: Cert: " + b64);
        b64 = CryptoUtil.stripCertBrackets(b64.trim());
        byte[] bytes = CryptoUtil.base64Decode(b64);

        return new X509CertImpl(bytes);
    }

    public void setupSecurityDomain(SecurityDomainSetupRequest request) throws Exception {

        String type = request.getSecurityDomainType();

        if (type.equals(ConfigurationRequest.NEW_DOMAIN)) {
            logger.info("Creating new security domain");
            createSecurityDomain();

        } else if (type.equals(ConfigurationRequest.NEW_SUBDOMAIN)) {
            logger.info("Configuring new security subdomain");
            createSecurityDomain();

        } else {
            logger.info("Updating existing security domain");
            updateSecurityDomain(request);
        }

        cs.commit(false);
    }

    public void createSecurityDomain() throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        LDAPConfig dbCfg = cs.getInternalDBConfig();
        LdapBoundConnFactory dbFactory = new LdapBoundConnFactory("Configurator");
        dbFactory.init(cs, dbCfg, engine.getPasswordStore());

        LDAPConnection conn = dbFactory.getConn();
        LDAPEntry entry = null;
        LDAPAttributeSet attrs = null;

        // Create security domain ldap entry
        String basedn = dbCfg.getBaseDN();
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
        String cn = engine.getEESSLHost() + ":" + engine.getAdminPort();
        dn = "cn=" + LDAPUtil.escapeRDNValue(cn) + ",cn=CAList,ou=Security Domain," + basedn;
        String subsystemName = preopConfig.getString("subsystem.name");

        attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectclass", "top"));
        attrs.add(new LDAPAttribute("objectclass", "pkiSubsystem"));
        attrs.add(new LDAPAttribute("Host", engine.getEESSLHost()));
        attrs.add(new LDAPAttribute("SecurePort", engine.getEESSLPort()));
        attrs.add(new LDAPAttribute("SecureAgentPort", engine.getAgentPort()));
        attrs.add(new LDAPAttribute("SecureAdminPort", engine.getAdminPort()));
        if (engine.getEEClientAuthSSLPort() != null) {
            attrs.add(new LDAPAttribute("SecureEEClientAuthPort", engine.getEEClientAuthSSLPort()));
        }
        attrs.add(new LDAPAttribute("UnSecurePort", engine.getEENonSSLPort()));
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
        // getDomainInfo(engine.getEESSLHost(), Integer.parseInt(engine.getAdminPort()));
    }

    public void updateSecurityDomain(SecurityDomainSetupRequest request) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        int sd_admin_port = cs.getInteger("securitydomain.httpsadminport");
        String type = cs.getType();
        String sd_host = cs.getString("securitydomain.host");
        String subsystemName = preopConfig.getString("subsystem.name");

        boolean cloneMaster = false;

        DomainInfo domainInfo = request.getDomainInfo();
        logger.info("Domain: " + domainInfo);

        if (request.isClone() && type.equalsIgnoreCase("CA") && isSDHostDomainMaster(domainInfo)) {
            cloneMaster = true;
            logger.debug("Cloning a domain master");
        }

        String url = "/ca/admin/ca/updateDomainXML";

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("list", type + "List");
        content.putSingle("type", type);
        content.putSingle("host", engine.getEESSLHost());
        content.putSingle("name", subsystemName);
        content.putSingle("sport", engine.getEESSLPort());
        content.putSingle("dm", cloneMaster ? "true" : "false");
        content.putSingle("clone", request.isClone() ? "true" : "false");
        content.putSingle("agentsport", engine.getAgentPort());
        content.putSingle("adminsport", engine.getAdminPort());

        if (engine.getEEClientAuthSSLPort() != null) {
            content.putSingle("eeclientauthsport", engine.getEEClientAuthSSLPort());
        }

        content.putSingle("httpport", engine.getEENonSSLPort());

        logger.debug("Update security domain using admin interface");
        String session_id = request.getInstallToken().getToken();
        content.putSingle("sessionID", session_id);

        updateDomainXML(sd_host, sd_admin_port, true, url, content, false);
    }

    public boolean isSDHostDomainMaster(DomainInfo domainInfo) throws Exception {

        logger.info("Checking whether security domain host is master");

        String hostname = cs.getString("securitydomain.host");
        int httpsadminport = cs.getInteger("securitydomain.httpsadminport");

        SecurityDomainHost host = getHostInfo(domainInfo, "CA", hostname, httpsadminport);

        String dm = host.getDomainManager();
        return dm.equalsIgnoreCase("true");
    }

    public void updateDomainXML(String hostname, int port, boolean https,
            String servlet, MultivaluedMap<String, String> content, boolean useClientAuth)
            throws Exception {

        logger.debug("Configurator: updateDomainXML start hostname=" + hostname + " port=" + port);

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String serverURL = "https://" + hostname + ":" + port;
        PKIClient client;

        if (useClientAuth) {
            String subsystem = cs.getType().toLowerCase();
            String fullname = cs.getString(subsystem + ".cert.subsystem.nickname");

            logger.debug("Configurator: Updating security domain with " + fullname);
            client = Configurator.createClient(serverURL, fullname, null);

        } else {
            client = Configurator.createClient(serverURL, null, null);
        }

        String c = client.post(servlet, content);

        if (c == null || c.equals("")) {
            logger.error("Unable to update security domain: empty response");
            throw new IOException("Unable to update security domain: empty response");
        }

        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject obj = new XMLObject(bis);
            String status = obj.getValue("Status");
            logger.debug("Configurator: updateDomainXML: status=" + status);

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

    public void setupSubsystemUser(X509CertImpl cert) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String sysType = cs.getType();
        String machineName = cs.getHostname();
        String securePort = cs.getString("service.securePort", "");

        int num = preopConfig.getInteger("subsystem.count", 0);
        num++;
        preopConfig.putInteger("subsystem.count", num);
        cs.putInteger("subsystem.count", num);
        cs.commit(false);

        String id = sysType + "-" + machineName + "-" + securePort;
        String groupName = "Subsystem Group";

        setupUser(id, cert, groupName);
    }

    public void setupClientAuthUser() throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String host = preopConfig.getString("ca.hostname");
        int port = preopConfig.getInteger("ca.httpsadminport");
        String url = "https://" + host + ":" + port;

        logger.info("Configurator: Retrieving subsystem certificate from " + url);

        X509CertImpl cert = getSubsystemCert(host, port);
        if (cert == null) {
            throw new Exception("Unable to retrieve subsystem certificate from " + url);
        }

        int num = preopConfig.getInteger("subsystem.count", 0);
        num++;
        preopConfig.putInteger("subsystem.count", num);
        cs.putInteger("subsystem.count", num);
        cs.commit(false);

        String id = "CA-" + host + "-" + port;
        String groupName = "Trusted Managers";

        setupUser(id, cert, groupName);
    }

    public void setupUser(String id, X509CertImpl cert, String groupName) throws Exception {

        UGSubsystem system = engine.getUGSubsystem();

        IUser user = system.createUser(id);
        user.setFullName(id);
        user.setEmail("");
        user.setPassword("");
        user.setUserType("agentType");
        user.setState("1");
        user.setPhone("");

        try {
            logger.info("Configurator: Adding user: " + id);
            system.addUser(user);
        } catch (ConflictingOperationException e) {
            // ignore exception
            logger.warn("Configurator: User already exists: " + id);
        }

        X509CertImpl[] certs = new X509CertImpl[1];
        certs[0] = cert;
        user.setX509Certificates(certs);

        try {
            logger.info("Configurator: Adding user certificate: " + cert.getSubjectDN());
            system.addUserCert(user);
        } catch (ConflictingOperationException e) {
            // ignore exception
            logger.warn("Configurator: User certificate already exists: " + cert.getSubjectDN());
        }

        IGroup group = system.getGroupFromName(groupName);

        if (!group.isMember(id)) {
            logger.info("Configurator: Adding user to group: " + groupName);
            group.addMemberName(id);
            system.modifyGroup(group);
        }
    }

    public X509CertImpl getSubsystemCert(String host, int port) throws Exception {

        String serverURL = "https://" + host + ":" + port;
        logger.info("Configurator: Getting subsystem certificate from " + serverURL);

        PKIClient client = createClient(serverURL, null, null);
        String c = client.get("/ca/admin/ca/getSubsystemCert");

        if (c == null) {
            logger.warn("Configurator: No response from " + serverURL);
            return null;
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        if (!status.equals(SUCCESS)) {
            logger.warn("Configurator: Unable to get subsystem certificate from " + serverURL);
            return null;
        }

        String b64 = parser.getValue("Cert");
        return new X509CertImpl(Utils.base64decode(b64));
    }

    public void setupDatabaseUser() throws Exception {

        UGSubsystem system = engine.getUGSubsystem();

        // checking existing user
        IUser user = system.getUser(DBUSER);

        if (user != null) {
            // user found
            logger.warn("Configurator: user already exists: " + DBUSER);
            return;
        }

        // user not found
        logger.debug("Configurator: creating user: " + DBUSER);

        String b64 = getSubsystemCert();
        if (b64 == null) {
            logger.error("Configurator: failed to fetch subsystem cert");
            throw new EBaseException("Failed to fetch subsystem cert");
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
        logger.debug("Configurator: successfully added " + DBUSER);

        system.addUserCert(user);
        logger.debug("Configurator: successfully add the user certificate");

        // set subject dn
        system.addCertSubjectDN(user);

        // remove old db users
        logger.debug("Configurator: removing seeAlso from old dbusers");
        removeOldDBUsers(certs[0].getSubjectDN().toString());

        // workaround for ticket #1595
        Collection<String> groupNames = new ArrayList<String>();
        getDatabaseGroups(groupNames);

        for (String groupName : groupNames) {

            IGroup group = system.getGroupFromName(groupName);

            if (!group.isMember(DBUSER)) {
                logger.debug("Configurator: adding " + DBUSER + " to the " + groupName + " group.");
                group.addMemberName(DBUSER);
                system.modifyGroup(group);
            }
        }
    }

    public void getDatabaseGroups(Collection<String> groups) throws Exception {
    }

    public void registerUser(
            FinalizeConfigRequest request,
            URI secdomainURI,
            URI targetURI,
            String targetType) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String csType = cs.getType();
        String uid = csType.toUpperCase() + "-" + cs.getHostname()
                + "-" + cs.getString("service.securePort", "");
        String sessionId = request.getInstallToken().getToken();
        String subsystemName = preopConfig.getString("subsystem.name");

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("uid", uid);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionId);
        content.putSingle("auth_hostname", secdomainURI.getHost());
        content.putSingle("auth_port", secdomainURI.getPort() + "");
        content.putSingle("certificate", getSubsystemCert());
        content.putSingle("name", subsystemName);

        String serverURL = "https://" + targetURI.getHost() + ":" + targetURI.getPort();

        PKIClient client = Configurator.createClient(serverURL, null, null);
        String response = client.post("/" + targetType + "/admin/" + targetType + "/registerUser", content);

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
                logger.debug("registerUser: Successfully added user " + uid + " to " + targetURI);

            } else if (status.equals(AUTH_FAILURE)) {
                throw new EAuthException(AUTH_FAILURE);

            } else {
                String error = parser.getValue("Error");
                throw new IOException(error);
            }
        }
    }

    public void removeOldDBUsers(String subjectDN) throws EBaseException, LDAPException {

        UGSubsystem system = engine.getUGSubsystem();

        LDAPConfig dbCfg = cs.getInternalDBConfig();
        String userbasedn = "ou=people, " + dbCfg.getBaseDN();

        LdapBoundConnFactory dbFactory = new LdapBoundConnFactory("Configurator");
        dbFactory.init(cs, dbCfg, engine.getPasswordStore());

        LDAPConnection conn = dbFactory.getConn();

        String filter = "(&(seeAlso=" + LDAPUtil.escapeFilter(subjectDN) + ")(!(uid=" + DBUSER + ")))";
        String[] attrs = null;
        LDAPSearchResults res = conn.search(userbasedn, LDAPConnection.SCOPE_SUB, filter,
                attrs, false);
        if (res != null) {
            while (res.hasMoreElements()) {
                String uid = res.next().getAttribute("uid").getStringValues().nextElement();
                IUser user = system.getUser(uid);
                logger.debug("removeOldDUsers: Removing seeAlso from " + uid);
                system.removeCertSubjectDN(user);
            }
        }
    }

    public String getSubsystemCert() throws EBaseException, NotInitializedException, ObjectNotFoundException,
            TokenException, CertificateEncodingException, IOException {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String subsystem = preopConfig.getString("cert.subsystem.subsystem");

        String nickname = cs.getString(subsystem + ".subsystem.nickname");
        String tokenname = cs.getString(subsystem + ".subsystem.tokenname");

        if (!CryptoUtil.isInternalToken(tokenname)) {
            nickname = tokenname + ":" + nickname;
        }

        logger.debug("Configurator: getSubsystemCert: nickname=" + nickname);

        CryptoManager cm = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate cert = cm.findCertByNickname(nickname);
        if (cert == null) {
            logger.warn("Configurator: getSubsystemCert: subsystem cert is null");
            return null;
        }
        byte[] bytes = cert.getEncoded();
        String s = CryptoUtil.normalizeCertStr(CryptoUtil.base64Encode(bytes));
        return s;
    }

    public void updateNextRanges() throws EBaseException, LDAPException {

        String type = cs.getType();

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        String endRequestNumStr = dbConfig.getString("endRequestNumber", "");
        String endSerialNumStr = dbConfig.getString("endSerialNumber", "");

        LDAPConfig ldapCfg = cs.getInternalDBConfig();
        String basedn = ldapCfg.getBaseDN();

        BigInteger endRequestNum = new BigInteger(endRequestNumStr);
        BigInteger endSerialNum = new BigInteger(endSerialNumStr);
        BigInteger oneNum = new BigInteger("1");

        // update global next range entries
        LdapBoundConnFactory dbFactory = new LdapBoundConnFactory("Configurator");
        dbFactory.init(cs, ldapCfg, engine.getPasswordStore());

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
    public void finalizeConfiguration(FinalizeConfigRequest request) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String type = cs.getType();

        // more cloning variables needed for non-ca clones

        if (!type.equals("CA")) {

            String val = preopConfig.getString("ca.type", "");
            if (val.length() != 0) {
                cs.putString("cloning.ca.type", val);
            }
        }

        // save EC type for sslserver cert (if present)
        String ecType = preopConfig.getString("cert.sslserver.ec.type", "ECDHE");
        cs.putString("jss.ssl.sslserver.ectype", ecType);

        cs.removeSubStore("preop");
        cs.setState(1);

        cs.commit(false);
    }

    /**
     * Set whether the given subsystem is enabled.
     *
     * @param id The subsystem ID.
     * @param enabled Whether the subsystem is enabled
     */
    public void setSubsystemEnabled(String id, boolean enabled) throws EBaseException {

        SubsystemsConfig ssconfig = cs.getSubsystemsConfig();

        for (String ssName : ssconfig.getSubsystemNames()) {
            SubsystemConfig subsystemConfig = ssconfig.getSubsystemConfig(ssName);

            if (id.equalsIgnoreCase(subsystemConfig.getID())) {
                subsystemConfig.setEnabled(enabled);
                break;
            }
        }
    }

    public String getSystemCertProfileID(String keyType, String tag, String defaultName) {

        String profileName = defaultName;

        logger.debug("Configurator: tag: " + tag + " defaultName: " + defaultName + " keyType: " + keyType);
        if (keyType == null) {
            return profileName;
        }

        // Hard code for now based on key type.  Method can be changed later to read pkispawn
        // params sent over in the future.
        if ("ecc".equalsIgnoreCase(keyType)) {
            if ("sslserver".equalsIgnoreCase(tag)) {
                profileName = ECC_INTERNAL_SERVER_CERT_PROFILE;
            } else if ("subsystem".equalsIgnoreCase(tag)) {
                profileName = ECC_INTERNAL_SUBSYSTEM_CERT_PROFILE;
            }

        } else if ("rsa".equalsIgnoreCase(keyType)) {
            if ("sslserver".equalsIgnoreCase(tag)) {
                profileName = RSA_INTERNAL_SERVER_CERT_PROFILE;
            } else if ("subsystem".equalsIgnoreCase(tag)) {
                profileName = RSA_INTERNAL_SUBSYSTEM_CERT_PROFILE;
            }
        }

        logger.debug("Configurator: returning: " + profileName);
        return profileName;
    }
}
