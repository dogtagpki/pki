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

import java.io.File;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.StringTokenizer;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.dogtag.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
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
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
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
    public KeyPair createECCKeyPair(String tag, CryptoToken token, String curveName, String ecType, String usage, String usageMask)
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
            KeyPairGeneratorSpi.Usage[] eccUsage = null;
            KeyPairGeneratorSpi.Usage[] eccUsageMask = null;
            if (usage != null && !usage.isEmpty()) {
                eccUsage = CryptoUtil.generateUsage(usage);
            }
            if (usageMask != null && !usageMask.isEmpty()) {
                eccUsageMask = CryptoUtil.generateUsage(usageMask);
            } else {
                if (tag.equals("sslserver") && ecType.equalsIgnoreCase("ECDH")) {
                    eccUsageMask = CryptoUtil.ECDH_USAGES_MASK;
                } else {
                    eccUsageMask = CryptoUtil.ECDHE_USAGES_MASK;
                }
            }
            pair = CryptoUtil.generateECCKeyPair(token, curveName,
                    eccUsage,
                    eccUsageMask);

            // XXX - store curve , w
            byte id[] = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();
            String kid = CryptoUtil.encodeKeyID(id);

            // try to locate the private key
            PrivateKey privk = CryptoUtil.findPrivateKeyFromID(CryptoUtil.decodeKeyID(kid));
            if (privk == null) {
                logger.debug("Found bad ECC key id " + kid);
                pair = null;
            }
        } while (pair == null);

        return pair;
    }

    public KeyPair createRSAKeyPair(String tag, CryptoToken token, String keySize, String usage, String usageMask)
            throws Exception {

        logger.debug("Configurator.createRSAKeyPair(" + token + ")");

        if (keySize == null) {
            keySize = cs.getString("keys.rsa.keysize.default");
        }

        int size = Integer.parseInt(keySize);

        logger.info("Configurator.createRSAKeyPair: tag " + tag);
        KeyPair pair = null;
        do {
            KeyPairGeneratorSpi.Usage[] rsaUsage = null;
            KeyPairGeneratorSpi.Usage[] rsaUsageMask = null;
            if (usage != null && !usage.isEmpty()) {
                rsaUsage = CryptoUtil.generateUsage(usage);
            } else {
                if("transport".equals(tag) || "storage".equals(tag) || "subsystem".equals(tag)) {
                    rsaUsage = CryptoUtil.RSA_KEYPAIR_USAGES;
                }
            }
            if (usageMask != null && !usageMask.isEmpty()) {
                rsaUsageMask = CryptoUtil.generateUsage(usageMask);
            } else {
                if("transport".equals(tag) || "storage".equals(tag) || "subsystem".equals(tag)) {
                    rsaUsageMask = CryptoUtil.RSA_KEYPAIR_USAGES_MASK;
                }
            }

            if (rsaUsage == null && rsaUsageMask == null) {
                pair = CryptoUtil.generateRSAKeyPair(token, size);
            } else {
                pair = CryptoUtil.generateRSAKeyPair(token, size,
                        rsaUsage, rsaUsageMask);
            }

            byte[] id = ((org.mozilla.jss.crypto.PrivateKey) pair.getPrivate()).getUniqueID();
            String kid = CryptoUtil.encodeKeyID(id);

            // try to locate the private key
            PrivateKey privk = CryptoUtil.findPrivateKeyFromID(CryptoUtil.decodeKeyID(kid));

            if (privk == null) {
                logger.debug("Found bad RSA key id " + kid);
                pair = null;
            }
        } while (pair == null);

        return pair;
    }

    public X509CertImpl createLocalCert(
            String subjectDN,
            String keyAlgorithm,
            X509Key x509key,
            String profileID,
            String[] dnsNames,
            boolean installAdjustValidity,
            String issuerDN,
            PrivateKey signingPrivateKey,
            String signingAlgorithm,
            String certRequestType,
            byte[] certRequest,
            X500Name subjectName) throws Exception {

        return null;
    }

    public X509CertImpl createCert(
            String tag,
            KeyPair keyPair,
            byte[] certreq,
            String certType,
            String profileID,
            String[] dnsNames,
            Boolean clone,
            URL masterURL,
            InstallToken installToken) throws Exception {

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

        return createRemoteCert(hostname, port, profileID, certreq, dnsNames, installToken);
    }

    public X509CertImpl createRemoteCert(
            String hostname,
            int port,
            String profileID,
            byte[] request,
            String[] dnsNames,
            InstallToken installToken)
            throws Exception {

        String serverURL = "https://" + hostname + ":" + port;
        logger.info("Configurator: Submitting cert request to " + serverURL);

        String certRequestType = "pkcs10";
        String certRequest = CryptoUtil.base64Encode(request);

        String sysType = cs.getType();
        String machineName = cs.getHostname();
        String securePort = cs.getString("service.securePort", "");
        String requestor = sysType + "-" + machineName + "-" + securePort;

        String sessionID = installToken.getToken();

        PKIClient client = Configurator.createClient(serverURL, null, null);
        CAClient caClient = new CAClient(client);
        CACertClient caCertClient = new CACertClient(caClient);

        return caCertClient.submitRequest(
                certRequestType,
                certRequest,
                profileID,
                null,
                dnsNames,
                requestor,
                sessionID);
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

    public byte[] createCertRequest(
            String tag,
            KeyPair keyPair,
            String dn,
            String algorithm,
            String extOID,
            String extData,
            boolean extCritical) throws Exception {

        logger.info("Configurator: Creating request for " + tag + " certificate");
        logger.info("Configurator: - subject: " + dn);
        logger.info("Configurator: - algorithm: " + algorithm);

        Extensions exts = new Extensions();
        if (tag.equals("signing")) {
            logger.info("Configurator: Creating basic CA extensions");
            createBasicCAExtensions(exts);
        }

        if (extOID != null && extData != null) {
            logger.info("Configurator: Creating generic extension");
            logger.info("Configurator: - OID: " + extOID);
            logger.info("Configurator: - data: " + extData);
            logger.info("Configurator: - critical: " + extCritical);
            Extension ext = createGenericExtension(extOID, extData, extCritical);
            exts.add(ext);
        }

        logger.debug("Configurator: Generating PKCS #10 request");
        PKCS10 certReq = CryptoUtil.createCertificationRequest(
                dn,
                keyPair,
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

    public void importCert(
            X509Key x509key,
            X509CertImpl certImpl,
            String profileID,
            String[] dnsNames,
            boolean installAdjustValidity,
            String certRequestType,
            byte[] certRequest,
            X500Name subjectName) throws Exception {
    }

    public void loadCert(
            String type,
            String tag,
            X509Certificate x509Cert,
            String profileID,
            String[] dnsNames) throws Exception {

        logger.info("Configurator: Loading existing " + tag + " cert request");

        String certreq = cs.getString(type.toLowerCase() + "." + tag + ".certreq");
        logger.debug("Configurator: request: " + certreq);
        byte[] binCertRequest = CryptoUtil.base64Decode(certreq);

        logger.info("Configurator: Loading existing " + tag + " certificate");
        byte[] binCert = x509Cert.getEncoded();

        boolean installAdjustValidity = !tag.equals("signing");
        String certRequestType = "pkcs10";
        X500Name subjectName = null;

        PKCS10 pkcs10 = new PKCS10(binCertRequest);
        X509Key x509key = pkcs10.getSubjectPublicKeyInfo();
        X509CertImpl certImpl = new X509CertImpl(binCert);

        importCert(
                x509key,
                certImpl,
                profileID,
                dnsNames,
                installAdjustValidity,
                certRequestType,
                binCertRequest,
                subjectName);

        trustCert(type, tag, x509Cert);
    }

    public void trustCert(String type, String tag, X509Certificate x509Cert) {

        if (tag.equals("signing") && type.equals("CA")) { // set trust flags to CT,C,C
            CryptoUtil.trustCACert(x509Cert);

        } else if (tag.equals("audit_signing")) { // set trust flags to u,u,Pu
            CryptoUtil.trustAuditSigningCert(x509Cert);

        } // user certs will have u,u,u by default
    }

    public Cert setupCert(CertificateSetupRequest request) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String type = cs.getType();
        String tag = request.getTag();

        logger.info("Configurator: Processing " + tag + " certificate");

        SystemCertData certData = request.getSystemCert();

        String nickname = certData.getNickname();
        logger.info("Configurator: - nickname: " + nickname);

        String tokenName = certData.getToken();
        logger.info("Configurator: - token: " + tokenName);

        String profileID = certData.getProfile();
        logger.info("Configurator: - profile: " + profileID);

        // cert type is selfsign, local, or remote
        String certType = certData.getType();
        logger.info("Configurator: - cert type: " + certType);

        String usage = certData.getOpsFlag();
        logger.info("Configurator: - cert usage: " + usage);

        String usageMask = certData.getOpsFlagMask();
        logger.info("Configurator: - cert usageMask: " + usageMask);

        String[] dnsNames = certData.getDNSNames();
        if (dnsNames != null) {
            logger.info("Configurator: - SAN extension: ");
            for (String dnsName : dnsNames) {
                logger.info("Configurator:   - " + dnsName);
            }
        }

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

            if (keyType.equals("ecc")) {

                // Default ssl server cert to ECDHE unless stated otherwise.
                // Note: IE only supports "ECDHE", but "ECDH" is more efficient.
                String ecType = preopConfig.getString("cert." + tag + ".ec.type", "ECDHE");

                keyPair = createECCKeyPair(tag, token, keySize, ecType, usage, usageMask);

            } else {
                keyPair = createRSAKeyPair(tag, token, keySize, usage, usageMask);
            }
        }

        String subjectDN = certData.getSubjectDN();
        String keyAlgorithm = preopConfig.getString("cert." + tag + ".keyalgorithm");
        String extOID = preopConfig.getString("cert." + tag + ".ext.oid", null);
        String extData = preopConfig.getString("cert." + tag + ".ext.data", null);
        boolean extCritical = preopConfig.getBoolean("cert." + tag + ".ext.critical", false);

        Boolean clone = request.isClone();
        URL masterURL = request.getMasterURL();
        InstallToken installToken = request.getInstallToken();

        byte[] binCertRequest = createCertRequest(
                tag,
                keyPair,
                subjectDN,
                keyAlgorithm,
                extOID,
                extData,
                extCritical);

        cert.setRequest(binCertRequest);

        X509CertImpl certImpl;

        if (type.equals("CA")
                && !(clone && tag.equals("sslserver"))
                && (certType.equals("selfsign") || certType.equals("local"))) {

            String certRequestType = "pkcs10";
            X500Name subjectName = null;
            X509Key x509key = CryptoUtil.createX509Key(keyPair.getPublic());

            boolean installAdjustValidity = !tag.equals("signing");

            String issuerDN;
            CertificateIssuerName issuerName;
            PrivateKey signingPrivateKey;
            String signingAlgorithm;

            if (certType.equals("selfsign")) {
                issuerDN = subjectDN;
                signingPrivateKey = keyPair.getPrivate();
                signingAlgorithm = preopConfig.getString("cert.signing.keyalgorithm", "SHA256withRSA");
            } else { //local
                issuerDN = null;
                signingPrivateKey = null;
                signingAlgorithm = preopConfig.getString("cert.signing.signingalgorithm", "SHA256withRSA");
            }

            certImpl = createLocalCert(
                    subjectDN,
                    keyAlgorithm,
                    x509key,
                    profileID,
                    dnsNames,
                    installAdjustValidity,
                    issuerDN,
                    signingPrivateKey,
                    signingAlgorithm,
                    certRequestType,
                    binCertRequest,
                    subjectName);

        } else {

            certImpl = createCert(
                    tag,
                    keyPair,
                    binCertRequest,
                    certType,
                    profileID,
                    dnsNames,
                    clone,
                    masterURL,
                    installToken);
        }

        byte[] binCert = certImpl.getEncoded();
        cert.setCert(binCert);

        if (tag.equals("sslserver")) {
            logger.info("Configurator: temporary SSL server cert will be replaced on restart");
            return cert;
        }

        if (x509Cert != null) {
            logger.debug("Configurator: deleting existing " + tag + " cert");
            CertUtil.deleteCert(tokenName, x509Cert);
        }

        logger.debug("Configurator: importing " + tag + " cert");
        x509Cert = CryptoUtil.importUserCertificate(binCert, nickname);

        trustCert(type, tag, x509Cert);

        return cert;
    }

    public X509CertImpl createAdminCertificate(AdminSetupRequest request) throws Exception {
        return null;
    }
}
