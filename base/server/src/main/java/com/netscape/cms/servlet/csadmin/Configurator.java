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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.StringTokenizer;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.AccountClient;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.ServerXml;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Utility class for functions to be used by the RESTful installer.
 *
 * @author alee
 *
 */
public class Configurator {

    public final static Logger logger = LoggerFactory.getLogger(Configurator.class);

    public static String SUCCESS = "0";
    public static String FAILURE = "1";
    public static String AUTH_FAILURE = "2";
    public static final BigInteger BIG_ZERO = new BigInteger("0");
    public static final Long MINUS_ONE = Long.valueOf(-1);

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

        MultivaluedMap<String, String> content = new MultivaluedHashMap<>();
        content.putSingle("uid", user);
        content.putSingle("pwd", passwd);
        content.putSingle("url", subca_url);

        String serverURL = "https://" + sdhost + ":" + sdport;

        PKIClient client = Configurator.createClient(serverURL, null, null);
        String response = client.post("ca/admin/ca/getCookie", content, String.class);
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

    public RequestId createRequestID() throws Exception {
        return null;
    }

    public KeyPair loadKeyPair(X509Certificate cert) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();

        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = cm.findPrivKeyByCert(cert);

        return new KeyPair(publicKey, privateKey);
    }

    /**
     * This method creates an ECC keypair for a system cert.
     *
     * For ECDHE SSL server cert, server.xml should have the following ciphers:
     * +TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     * -TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
     *
     * For ECDH SSL server cert, server.xml should have the following ciphers:
     * -TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     * +TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
     */
    public KeyPair createECCKeyPair(String tag, CryptoToken token, String curveName, String ecType)
            throws Exception {

        if (curveName == null) {
            curveName = cs.getString("keys.ecc.curve.default");
        }

        logger.info("Configurator: Creating ECC keypair for " + tag);
        logger.info("Configurator: - token: " + token);
        logger.info("Configurator: - curve: " + curveName);

        KeyPair pair = null;
        logger.info("Configurator: - type: " + ecType);

        do {
            if (tag.equals("sslserver") && ecType.equalsIgnoreCase("ECDH")) {
                pair = CryptoUtil.generateECCKeyPair(token, curveName, null, CryptoUtil.ECDH_USAGES_MASK);

            } else {
                pair = CryptoUtil.generateECCKeyPair(token, curveName, null, CryptoUtil.ECDHE_USAGES_MASK);
            }

            // XXX - store curve , w
            byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();

            // try to locate the private key
            PrivateKey privk = CryptoUtil.findPrivateKey(token, id);
            if (privk == null) {
                logger.debug("Bad ECC key ID: " + CryptoUtil.encodeKeyID(id));
                pair = null;
            }
        } while (pair == null);

        return pair;
    }

    public KeyPair createRSAKeyPair(String tag, CryptoToken token, String keySize)
            throws Exception {

        logger.info("Configurator: Creating RSA keypair for " + tag);
        logger.info("Configurator: - token: " + token);

        if (keySize == null) {
            keySize = cs.getString("keys.rsa.keysize.default");
        }

        int size = Integer.parseInt(keySize);
        logger.info("Configurator: - size: " + size);

        KeyPair pair = null;
        do {
            if("transport".equals(tag) || "storage".equals(tag)) {
                pair = CryptoUtil.generateRSAKeyPair(token,size,
                                CryptoUtil.RSA_KEYPAIR_USAGES,
                                CryptoUtil.RSA_KEYPAIR_USAGES_MASK);
            } else {
                pair = CryptoUtil.generateRSAKeyPair(token, size);
            }

            byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();

            // try to locate the private key
            PrivateKey privk = CryptoUtil.findPrivateKey(token, id);

            if (privk == null) {
                logger.error("Bad RSA key ID: " + CryptoUtil.encodeKeyID(id));
                pair = null;
            }
        } while (pair == null);

        return pair;
    }

    public X509CertImpl createCert(
            RequestId requestID,
            String keyAlgorithm,
            X509Key x509key,
            String profileID,
            PrivateKey signingPrivateKey,
            String signingAlgorithm,
            String certRequestType,
            byte[] binCertRequest,
            X500Name issuerName,
            X500Name subjectName) throws Exception {

        return null;
    }

    public PKCS10 createPKCS10Request(
            KeyPair keyPair,
            String subjectDN,
            String algorithm,
            Extensions requestExtensionss) throws Exception {

        logger.info("Configurator: Creating PKCS #10 request");
        logger.info("Configurator: - subject: " + subjectDN);
        logger.info("Configurator: - algorithm: " + algorithm);

        return CryptoUtil.createCertificationRequest(
                subjectDN,
                keyPair,
                algorithm,
                requestExtensionss);
    }

    /*
     * createBasicCAExtensions creates the basic Extensions needed for a CSR to a
     * CA signing certificate
     */
    public void createBasicCAExtensions(Extensions exts) throws Exception {

        logger.info("Configurator: Creating basic CA extensions");

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

    public Extension createGenericExtension(String oid, String data, boolean critical) throws Exception {

        logger.info("Configurator: Creating generic extension");
        logger.info("Configurator: - OID: " + oid);
        logger.info("Configurator: - data: " + data);
        logger.info("Configurator: - critical: " + critical);

        try (DerOutputStream out = new DerOutputStream()) {

            byte[] bytes = CryptoUtil.hexString2Bytes(data);
            out.putOctetString(bytes);

            return new Extension(
                    new ObjectIdentifier(oid),
                    critical,
                    out.toByteArray());
        }
    }

    public void importRequest(
            RequestId requestID,
            String profileID,
            String[] dnsNames,
            boolean installAdjustValidity,
            String certRequestType,
            byte[] binCertRequest) throws Exception {
    }

    public void initSubsystem() throws Exception {
    }
}
