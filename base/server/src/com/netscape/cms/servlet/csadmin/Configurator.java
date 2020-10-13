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
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.StringTokenizer;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.dogtag.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.AccountClient;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainSetupRequest;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.apps.ServerXml;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.xml.XMLObject;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
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

    private String logIntoSecurityDomain(
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
         * (ticket https://github.com/dogtagpki/pki/issues/2951) but we need to
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

        AccountClient accountClient = new AccountClient(client, "ca", "rest");
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

        String subca_url = "https://" + cs.getHostname() + ":"
                + engine.getAdminPort() + "/ca/admin/console/config/wizard" +
                "?p=5&subsystem=" + cs.getType();

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("uid", user);
        content.putSingle("pwd", passwd);
        content.putSingle("url", subca_url);

        String serverURL = "https://" + sdhost + ":" + sdport;

        PKIClient client = Configurator.createClient(serverURL, null, null);
        String response = client.post("/ca/admin/ca/getCookie", content, String.class);
        logger.debug("Configurator: Response: " + response);

        return getContentValue(response, "header.session_id");
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

    public KeyPair loadKeyPair(X509Certificate cert) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();

        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = cm.findPrivKeyByCert(cert);

        return new KeyPair(publicKey, privateKey);
    }

    public KeyPair createECCKeyPair(String tag, CryptoToken token, String curveName)
            throws NoSuchAlgorithmException, NoSuchTokenException, TokenException,
            NotInitializedException, EPropertyNotFound, EBaseException {

        if (curveName == null) {
            curveName = cs.getString("keys.ecc.curve.default");
        }

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
            sslType = preopConfig.getString("cert." + tag + ".ec.type", "ECDHE");
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
            if (tag.equals("sslserver") && sslType.equalsIgnoreCase("ECDH")) {
                logger.debug("Configurator: createECCKeypair: sslserver cert for ECDH. Make sure server.xml is set "
                        +
                        "properly with -TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,+TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
                pair = CryptoUtil.generateECCKeyPair(token, curveName, null, ECDH_usages_mask);
            } else {
                if (tag.equals("sslserver")) {
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

    public KeyPair createRSAKeyPair(String tag, CryptoToken token, String keySize)
            throws Exception {

        logger.debug("Configurator.createRSAKeyPair(" + token + ")");

        if (keySize == null) {
            keySize = cs.getString("keys.rsa.keysize.default");
        }

        int size = Integer.parseInt(keySize);

        KeyPair pair = null;
        do {
            pair = CryptoUtil.generateRSAKeyPair(token, size);
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

    public KeyPair createKeyPair(String tag, CryptoToken token, String keyType, String keySize) throws Exception {

        if (keyType.equals("ecc")) {
            return createECCKeyPair(tag, token, keySize);

        } else {
            return createRSAKeyPair(tag, token, keySize);
        }
    }

    public X509CertImpl createCert(
            String tag,
            CertificateSetupRequest request,
            KeyPair keyPair,
            byte[] certreq,
            String certType) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String hostname;
        int port;

        if (tag.equals("subsystem")) {
            hostname = cs.getString("securitydomain.host", "");
            port = cs.getInteger("securitydomain.httpseeport", -1);

        } else {
            hostname = preopConfig.getString("ca.hostname", "");
            port = preopConfig.getInteger("ca.httpsport", -1);
        }

        String sessionID = request.getInstallToken().getToken();

        String profileID = preopConfig.getString("cert." + tag + ".profile");
        logger.debug("Configurator: profile ID: " + profileID);

        Boolean injectSAN = cs.getBoolean("service.injectSAN", false);
        logger.debug("Configurator: inject SAN: " + injectSAN);
        String[] dnsNames = null;

        if (tag.equals("sslserver") && injectSAN) {
            String list = cs.getString("service.sslserver.san");
            logger.debug("Configurator: DNS names: " + list);
            dnsNames = StringUtils.split(list, ",");
        }

        return createRemoteCert(hostname, port, sessionID, profileID, certreq, dnsNames);
    }

    // Dynamically apply the SubjectAlternativeName extension to a
    // remote PKI instance's request for its SSL Server Certificate.
    //
    // Since this information may vary from instance to
    // instance, obtain the necessary information from the
    // 'service.sslserver.san' value(s) in the instance's
    // CS.cfg, process these values converting each item into
    // its individual SubjectAlternativeName components, and
    // build an SSL Server Certificate URL extension consisting
    // of this information.
    //
    // 03/27/2013 - Should consider removing this
    //              "buildSANSSLserverURLExtension()"
    //              method if it becomes possible to
    //              embed a certificate extension into
    //              a PKCS #10 certificate request.
    //
    public void injectSANExtension(String[] dnsNames, MultivaluedMap<String, String> content) throws Exception {

        int i = 0;
        for (String dnsName : dnsNames) {
            content.putSingle("req_san_pattern_" + i, dnsName);
            i++;
        }

        content.putSingle("req_san_entries", "" + i);
    }

    public X509CertImpl createRemoteCert(
            String hostname,
            int port,
            String sessionID,
            String profileID,
            byte[] request,
            String[] dnsNames)
            throws Exception {

        String sysType = cs.getType();
        String machineName = cs.getHostname();
        String securePort = cs.getString("service.securePort", "");

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("requestor_name", sysType + "-" + machineName + "-" + securePort);
        content.putSingle("profileId", profileID);
        content.putSingle("cert_request_type", "pkcs10");
        content.putSingle("cert_request", CryptoUtil.base64Encode(request));
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionID);

        if (dnsNames != null) {
            injectSANExtension(dnsNames, content);
        }

        String serverURL = "https://" + hostname + ":" + port;
        PKIClient client = Configurator.createClient(serverURL, null, null);

        X509CertImpl cert = CertUtils.createRemoteCert(client, content);

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

    public byte[] createCertRequest(String tag, KeyPair keyPair) throws Exception {

        logger.info("Configurator: Creating request for " + tag + " certificate");

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String dn = preopConfig.getString("cert." + tag + ".dn");
        logger.debug("Configurator: subject: " + dn);

        String algorithm = preopConfig.getString("cert." + tag + ".keyalgorithm");
        logger.debug("Configurator: algorithm: " + algorithm);

        X509Key x509key = CryptoUtil.createX509Key(keyPair.getPublic());

        Extensions exts = new Extensions();
        if (tag.equals("signing")) {
            logger.debug("Configurator: Generating basic CA extensions");
            createBasicCAExtensions(exts);
        }

        String extOID = preopConfig.getString("cert." + tag + ".ext.oid", null);
        String extData = preopConfig.getString("cert." + tag + ".ext.data", null);

        if (extOID != null && extData != null) {
            logger.debug("Configurator: Creating generic extension");
            boolean extCritical = preopConfig.getBoolean("cert." + tag + ".ext.critical");
            Extension ext = createGenericExtension(extOID, extData, extCritical);
            exts.add(ext);
        }

        logger.debug("Configurator: Generating PKCS #10 request");
        PKCS10 certReq = CryptoUtil.createCertificationRequest(
                dn,
                x509key,
                keyPair.getPrivate(),
                algorithm,
                exts);

        return certReq.toByteArray();
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

    public void loadCert(String tag, byte[] certreq, X509Certificate x509Cert) throws Exception {
    }

    public void processCert(
            CertificateSetupRequest request,
            Cert cert,
            String certType,
            KeyPair keyPair,
            X509Certificate x509Cert) throws Exception {

        String tag = cert.getCertTag();
        String type = cs.getType();

        logger.info("Configurator: Processing " + tag + " certificate");

        // For external/existing CA case, some/all system certs may be provided.
        // The SSL server cert will always be generated for the current host.

        // For external/standalone KRA/OCSP case, all system certs will be provided.
        // No system certs will be generated including the SSL server cert.

        if (type.equals("CA") && request.isExternal() && !tag.equals("sslserver") && x509Cert != null
                || type.equals("KRA") && (request.isExternal() || request.getStandAlone())
                || type.equals("OCSP") && (request.isExternal() || request.getStandAlone())) {

            logger.info("Configurator: Loading existing " + tag + " cert request");

            String certreq = cs.getString(type.toLowerCase() + "." + tag + ".certreq");
            logger.debug("Configurator: request: " + certreq);

            byte[] binCertRequest = CryptoUtil.base64Decode(certreq);
            cert.setRequest(binCertRequest);

            logger.info("Configurator: Loading existing " + tag + " certificate");
            cert.setCert(x509Cert.getEncoded());

            loadCert(tag, binCertRequest, x509Cert);

        } else {
            byte[] binCertRequest = createCertRequest(tag, keyPair);
            cert.setRequest(binCertRequest);

            String certreq = CryptoUtil.base64Encode(binCertRequest);
            logger.debug("Configurator: request: " + certreq);
            cs.putString(type.toLowerCase() + "." + tag + ".certreq", certreq);

            X509CertImpl certImpl = createCert(tag, request, keyPair, binCertRequest, certType);
            cert.setCert(certImpl.getEncoded());

            String certStr = CryptoUtil.base64Encode(cert.getCert());
            logger.debug("Configurator: cert: " + certStr);
            cs.putString(type.toLowerCase() + "." + tag + ".cert", certStr);

            cs.commit(false);
        }

        logger.debug("Configurator.importCert(" + tag + ")");

        if (tag.equals("sslserver")) {
            logger.info("Configurator: temporary SSL server cert will be replaced on restart");
            return;
        }

        if (x509Cert != null) {
            logger.debug("Configurator: deleting existing " + tag + " cert");
            CertUtil.deleteCert(cert.getTokenname(), x509Cert);
        }

        logger.debug("Configurator: importing " + tag + " cert");
        x509Cert = CryptoUtil.importUserCertificate(cert.getCert(), cert.getNickname());

        if (tag.equals("signing") && type.equals("CA")) { // set trust flags to CT,C,C
            CryptoUtil.trustCACert(x509Cert);

        } else if (tag.equals("audit_signing")) { // set trust flags to u,u,Pu
            CryptoUtil.trustAuditSigningCert(x509Cert);

        } // user certs will have u,u,u by default
    }

    public Cert setupCert(CertificateSetupRequest request) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String tag = request.getTag();
        SystemCertData certData = request.getSystemCert();

        String nickname = certData.getNickname();
        logger.debug("Configurator: nickname: " + nickname);

        String tokenName = certData.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = preopConfig.getString("module.token", null);
        }

        logger.debug("Configurator: token: " + tokenName);

        // cert type is selfsign, local, or remote
        String certType = preopConfig.getString("cert." + tag + ".type");
        logger.debug("Configurator: cert type: " + certType);

        String fullName = nickname;
        if (!CryptoUtil.isInternalToken(tokenName)) {
            fullName = tokenName + ":" + nickname;
        }

        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        Cert cert = new Cert(tokenName, nickname, tag);

        X509Certificate x509Cert;
        KeyPair keyPair;

        try {
            logger.info("Configurator: Loading " + tag + " cert from NSS database: " + fullName);
            CryptoManager cm = CryptoManager.getInstance();
            x509Cert = cm.findCertByNickname(fullName);

            logger.info("Configurator: Loading " + tag + " key pair from NSS database");
            keyPair = loadKeyPair(x509Cert);

        } catch (ObjectNotFoundException e) {
            logger.info("Configurator: " + tag + " cert not found: " + fullName);
            x509Cert = null;

            String keyType = preopConfig.getString("cert." + tag + ".keytype");
            String keySize = certData.getKeySize();
            keyPair = createKeyPair(tag, token, keyType, keySize);
        }

        processCert(request, cert, certType, keyPair, x509Cert);

        return cert;
    }

    public X509CertImpl createAdminCertificate(AdminSetupRequest request) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String adminSubjectDN = request.getAdminSubjectDN();

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

        return createRemoteAdminCert(
                request,
                ca_hostname,
                ca_port,
                profileID,
                adminSubjectDN);
    }

    public void updateAdminUserCert(AdminSetupRequest request, X509CertImpl adminCert) throws Exception {

        X509CertImpl[] adminCerts = new X509CertImpl[] { adminCert };

        UGSubsystem ug = engine.getUGSubsystem();
        User user = ug.getUser(request.getAdminUID());
        user.setX509Certificates(adminCerts);
        ug.addUserCert(user);
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

        User user = null;

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

        Group group = null;
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
    }

    public X509CertImpl createRemoteAdminCert(
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
        String response = client.post("/ca/ee/ca/profileSubmit", content, String.class);
        logger.info("Configurator: Response: " + response);

        if (response == null) {
            logger.error("Unable to generate admin certificate: no response from CA");
            throw new IOException("Unable to generate admin certificate: no response from CA");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
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

        String serial = parser.getValue("serialno");
        logger.info("Configurator: Serial: " + serial);

        String b64 = parser.getValue("b64");
        logger.info("Configurator: Cert: " + b64);

        b64 = CryptoUtil.stripCertBrackets(b64.trim());
        byte[] bytes = CryptoUtil.base64Decode(b64);
        return new X509CertImpl(bytes);
    }

    public void setupSecurityDomain(SecurityDomainSetupRequest request) throws Exception {

        String type = request.getSecurityDomainType();

        if (type.equals("newdomain")) {
            logger.info("Creating new security domain");
            createSecurityDomain();

        } else if (type.equals("newsubdomain")) {
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

        PKISocketConfig socketConfig = cs.getSocketConfig();
        LDAPConfig dbCfg = cs.getInternalDBConfig();

        LdapBoundConnFactory dbFactory = new LdapBoundConnFactory("Configurator");
        dbFactory.init(socketConfig, dbCfg, engine.getPasswordStore());

        LDAPConnection conn = dbFactory.getConn();
        LDAPEntry entry = null;
        LDAPAttributeSet attrs = null;

        // Create security domain ldap entry
        String basedn = dbCfg.getBaseDN();
        String secdomain = cs.getString("securitydomain.name");

        String dn = "ou=Security Domain," + basedn;
        logger.info("Configurator: adding " + dn);

        attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectclass", new String[] { "top", "pkiSecurityDomain" }));
        attrs.add(new LDAPAttribute("name", secdomain));
        attrs.add(new LDAPAttribute("ou", "Security Domain"));

        for (Enumeration<LDAPAttribute> e = attrs.getAttributes(); e.hasMoreElements(); ) {
            LDAPAttribute attr = e.nextElement();
            String[] values = attr.getStringValueArray();
            if (values == null) continue;
            logger.info("Configurator: - " + attr.getName());
        }

        entry = new LDAPEntry(dn, attrs);
        conn.add(entry);

        // create list containers
        String clist[] = { "CAList", "OCSPList", "KRAList", "RAList", "TKSList", "TPSList" };
        for (int i = 0; i < clist.length; i++) {

            dn = "cn=" + LDAPUtil.escapeRDNValue(clist[i]) + ",ou=Security Domain," + basedn;
            logger.info("Configurator: adding " + dn);

            attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", new String[] { "top", "pkiSecurityGroup" }));
            attrs.add(new LDAPAttribute("cn", clist[i]));

            for (Enumeration<LDAPAttribute> e = attrs.getAttributes(); e.hasMoreElements(); ) {
                LDAPAttribute attr = e.nextElement();
                String[] values = attr.getStringValueArray();
                if (values == null) continue;
                logger.info("Configurator: - " + attr.getName());
            }

            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);
        }

        // Add this host
        String cn = cs.getHostname() + ":" + engine.getAdminPort();
        dn = "cn=" + LDAPUtil.escapeRDNValue(cn) + ",cn=CAList,ou=Security Domain," + basedn;
        logger.info("Configurator: adding " + dn);

        String subsystemName = preopConfig.getString("subsystem.name");

        attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectclass", new String[] { "top", "pkiSubsystem" }));
        attrs.add(new LDAPAttribute("Host", cs.getHostname()));
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

        for (Enumeration<LDAPAttribute> e = attrs.getAttributes(); e.hasMoreElements(); ) {
            LDAPAttribute attr = e.nextElement();
            String[] values = attr.getStringValueArray();
            if (values == null) continue;
            logger.info("Configurator: - " + attr.getName());
        }

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
        content.putSingle("host", cs.getHostname());
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

        String response = client.post(servlet, content, String.class);
        logger.debug("Configurator: Response: " + response);

        if (response == null || response.equals("")) {
            logger.error("Unable to update security domain: empty response");
            throw new IOException("Unable to update security domain: empty response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject obj = new XMLObject(bis);
        String status = obj.getValue("Status");
        logger.debug("Configurator: Status: " + status);

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
    }

    public void setupSubsystemUser(X509CertImpl cert) throws Exception {

        String sysType = cs.getType();
        String machineName = cs.getHostname();
        String securePort = cs.getString("service.securePort", "");

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

        String id = "CA-" + host + "-" + port;
        String groupName = "Trusted Managers";

        setupUser(id, cert, groupName);
    }

    public void setupUser(String id, X509CertImpl cert, String groupName) throws Exception {

        UGSubsystem system = engine.getUGSubsystem();

        User user = system.createUser(id);
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

        Group group = system.getGroupFromName(groupName);

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
        String c = client.get("/ca/admin/ca/getSubsystemCert", String.class);

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
        User user = system.getUser(DBUSER);

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

            Group group = system.getGroupFromName(groupName);

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
        String response = client.post(
                "/" + targetType + "/admin/" + targetType + "/registerUser",
                content,
                String.class);
        logger.debug("Configurator: Response: " + response);

        if (response == null || response.equals("")) {
            logger.error("Unable to add user: empty response");
            throw new IOException("Unable to add user: empty response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        logger.debug("Configurator: Status: " + status);

        if (status.equals(SUCCESS)) {
            logger.debug("Configurator: Successfully added user " + uid + " to " + targetURI);

        } else if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);

        } else {
            String error = parser.getValue("Error");
            throw new IOException(error);
        }
    }

    public void removeOldDBUsers(String subjectDN) throws EBaseException, LDAPException {

        UGSubsystem system = engine.getUGSubsystem();

        PKISocketConfig socketConfig = cs.getSocketConfig();
        LDAPConfig dbCfg = cs.getInternalDBConfig();
        String userbasedn = "ou=people, " + dbCfg.getBaseDN();

        LdapBoundConnFactory dbFactory = new LdapBoundConnFactory("Configurator");
        dbFactory.init(socketConfig, dbCfg, engine.getPasswordStore());

        LDAPConnection conn = dbFactory.getConn();

        String filter = "(&(seeAlso=" + LDAPUtil.escapeFilter(subjectDN) + ")(!(uid=" + DBUSER + ")))";
        String[] attrs = null;
        LDAPSearchResults res = conn.search(userbasedn, LDAPConnection.SCOPE_SUB, filter,
                attrs, false);
        if (res != null) {
            while (res.hasMoreElements()) {
                String uid = res.next().getAttribute("uid").getStringValues().nextElement();
                User user = system.getUser(uid);
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

    /**
     * save variables needed for cloning and remove preops
     *
     * @throws EBaseException
     */
    public void finalizeConfiguration(FinalizeConfigRequest request) throws Exception {
        cs.commit(false);
    }
}
