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
package org.dogtagpki.server.rest;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.AdminSetupResponse;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.ConfigurationResponse;
import com.netscape.certsrv.system.KeyBackupRequest;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.certsrv.system.SystemConfigResource;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.Cert;
import com.netscape.cms.servlet.csadmin.ConfigurationUtils;
import com.netscape.cms.servlet.csadmin.ReplicationUtil;
import com.netscape.cms.servlet.csadmin.SystemCertDataFactory;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.SubsystemInfo;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.IPasswordStore;
import org.mozilla.jss.netscape.security.util.Utils;

import org.mozilla.jss.netscape.security.x509.X509CertImpl;

/**
 * @author alee
 *
 */
public class SystemConfigService extends PKIService implements SystemConfigResource {

    public final static Logger logger = LoggerFactory.getLogger(SystemConfigService.class);

    public static final String ECC_INTERNAL_ADMIN_CERT_PROFILE = "caECAdminCert";
    public static final String RSA_INTERNAL_ADMIN_CERT_PROFILE = "caAdminCert";

    public IConfigStore cs;
    public String csType;
    public String csSubsystem;
    public String csState;
    public boolean isMasterCA = false;
    public String instanceRoot;

    public SystemConfigService() throws EBaseException {
        cs = CMS.getConfigStore();
        csType = cs.getString("cs.type");
        csSubsystem = csType.toLowerCase();
        csState = cs.getString("cs.state");
        String domainType = cs.getString("securitydomain.select", "existingdomain");
        if (csType.equals("CA") && domainType.equals("new")) {
            isMasterCA = true;
        }
        instanceRoot = cs.getString("instanceRoot");
    }

    /* (non-Javadoc)
     * @see com.netscape.cms.servlet.csadmin.SystemConfigurationResource#configure(com.netscape.cms.servlet.csadmin.data.ConfigurationData)
     */
    @Override
    public ConfigurationResponse configure(ConfigurationRequest request) throws Exception {

        logger.debug("SystemConfigService: configure()");

        try {
            ConfigurationResponse response = new ConfigurationResponse();
            configure(request, response);
            return response;

        } catch (PKIException e) { // normal responses
            logger.error("Configuration failed: " + e.getMessage()); // log the response
            throw e;

        } catch (Exception e) { // unexpected exceptions
            logger.error("Configuration failed: " + e.getMessage(), e); // show stack trace for troubleshooting
            throw e;

        } catch (Error e) { // system errors
            logger.error("Configuration failed: " + e.getMessage(), e); // show stack trace for troubleshooting
            throw e;
        }
    }

    public void configure(ConfigurationRequest data, ConfigurationResponse response) throws Exception {

        validatePin(data.getPin());

        if (csState.equals("1")) {
            throw new BadRequestException("System already configured");
        }

        logger.debug("SystemConfigService: request: " + data);
        validateRequest(data);

        logger.debug("=== Token Configuration ===");
        String token = data.getToken();
        configureToken(data, token);

        // configure security domain
        logger.debug("=== Security Domain Configuration ===");
        String domainXML = configureSecurityDomain(data);

        // configure subsystem
        logger.debug("=== Subsystem Configuration ===");
        configureSubsystem(data, token, domainXML);

        // configure hierarchy
        logger.debug("=== Hierarchy Configuration ===");
        configureHierarchy(data);

        logger.debug("=== Configure CA Cert Chain ===");
        configureCACertChain(data, domainXML);
    }

    @Override
    public void setupDatabase(ConfigurationRequest request) throws Exception {

        logger.debug("SystemConfigService: setupDatabase()");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            configureDatabase(request);
            cs.commit(false);

            initializeDatabase(request);
            reinitSubsystems();

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public ConfigurationResponse configureCerts(ConfigurationRequest request) throws Exception {

        logger.debug("SystemConfigService: configureCerts()");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            ConfigurationResponse response = new ConfigurationResponse();

            logger.debug("=== Process Certs ===");
            Collection<Cert> certs = new ArrayList<Cert>();
            processCerts(request, certs);

            response.setSystemCerts(SystemCertDataFactory.create(certs));

            return response;

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public AdminSetupResponse setupAdmin(AdminSetupRequest request) throws Exception {

        logger.debug("SystemConfigService: setupAdmin()");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            if (StringUtils.isEmpty(request.getAdminUID())) {
                throw new BadRequestException("Missing admin UID");
            }

            if (StringUtils.isEmpty(request.getAdminPassword())) {
                throw new BadRequestException("Missing admin password");
            }

            if (StringUtils.isEmpty(request.getAdminEmail())) {
                throw new BadRequestException("Missing admin email");
            }

            if (StringUtils.isEmpty(request.getAdminName())) {
                throw new BadRequestException("Missing admin name");
            }

            boolean importAdminCert = Boolean.parseBoolean(request.getImportAdminCert());

            if (importAdminCert) {
                if (StringUtils.isEmpty(request.getAdminCert())) {
                    throw new BadRequestException("Missing admin certificate");
                }

            } else {
                if (StringUtils.isEmpty(request.getAdminCertRequest())) {
                    throw new BadRequestException("Missing admin certificate request");
                }

                if (StringUtils.isEmpty(request.getAdminCertRequestType())) {
                    throw new BadRequestException("Missing admin certificate request type");
                }

                if (StringUtils.isEmpty(request.getAdminSubjectDN())) {
                    throw new BadRequestException("Missing admin subject DN");
                }
            }

            AdminSetupResponse response = new AdminSetupResponse();

            createAdminUser(request);

            X509CertImpl cert = createAdminCert(request);
            updateAdminUserCert(request, cert);

            String b64cert = Utils.base64encodeSingleLine(cert.getEncoded());
            logger.debug("SystemConfigService: admin cert: " + b64cert);

            SystemCertData adminCert = response.getAdminCert();
            adminCert.setCert(b64cert);

            return response;

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void finalizeConfiguration(ConfigurationRequest request) throws Exception {

        logger.debug("SystemConfigService: finalizeConfiguration()");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            cs.putInteger("cs.state", 1);
            ConfigurationUtils.removePreopConfigEntries();

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void setupDatabaseUser(ConfigurationRequest request) throws Exception {

        logger.debug("SystemConfigService: setupDatabaseUser()");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            if (!request.getSharedDB()) ConfigurationUtils.setupDBUser();

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void setupSecurityDomain(ConfigurationRequest request) throws Exception {

        logger.debug("SystemConfigService: setupSecurityDomain()");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            String securityDomainType = request.getSecurityDomainType();
            if (securityDomainType.equals(ConfigurationRequest.NEW_DOMAIN)) {
                logger.debug("Creating new security domain");
                ConfigurationUtils.createSecurityDomain();
            } else if (securityDomainType.equals(ConfigurationRequest.NEW_SUBDOMAIN)) {
                logger.debug("Creating subordinate CA security domain");

                // switch out security domain parameters from issuing CA security domain
                // to subordinate CA hosted security domain
                cs.putString("securitydomain.name", request.getSubordinateSecurityDomainName());
                cs.putString("securitydomain.host", CMS.getEENonSSLHost());
                cs.putString("securitydomain.httpport", CMS.getEENonSSLPort());
                cs.putString("securitydomain.httpsagentport", CMS.getAgentPort());
                cs.putString("securitydomain.httpseeport", CMS.getEESSLPort());
                cs.putString("securitydomain.httpsadminport", CMS.getAdminPort());
                ConfigurationUtils.createSecurityDomain();
            } else {
                logger.debug("Updating existing security domain");
                ConfigurationUtils.updateSecurityDomain();
            }
            cs.putString("service.securityDomainPort", CMS.getAgentPort());
            cs.putString("securitydomain.store", "ldap");
            cs.commit(false);

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    public void processCerts(
            ConfigurationRequest request,
            Collection<Cert> certs) throws Exception {

        CMSEngine engine = (CMSEngine) CMS.getCMSEngine();

        boolean generateServerCert = !request.getGenerateServerCert().equalsIgnoreCase("false");
        boolean generateSubsystemCert = request.getGenerateSubsystemCert();

        String value = cs.getString("preop.cert.list");
        String[] certList = value.split(",");

        for (String tag : certList) {

            logger.debug("=== Processing " + tag + " cert ===");

            boolean enable = cs.getBoolean("preop.cert." + tag + ".enable", true);
            if (!enable) continue;

            SystemCertData certData = request.getSystemCert(tag);

            if (certData == null) {
                logger.error("No data for '" + tag + "' was found!");
                throw new BadRequestException("No data for '" + tag + "' was found!");
            }

            if (!generateServerCert && tag.equals("sslserver")) {
                updateConfiguration(request, certData, "sslserver");
                continue;
            }

            if (!generateSubsystemCert && tag.equals("subsystem")) {
                // update the details for the shared subsystem cert here.
                updateConfiguration(request, certData, "subsystem");

                // get parameters needed for cloning
                updateCloneConfiguration(request, certData, "subsystem");
                continue;
            }

            processKeyPair(
                    request,
                    certData);

            Cert cert = processCert(
                    request,
                    certData);

            certs.add(cert);

            String subsystem = cert.getSubsystem();
            ConfigurationUtils.handleCert(cert);

            if (tag.equals("signing") && subsystem.equals("ca")) {
                engine.reinit(ICertificateAuthority.ID);
            }
        }

        // make sure to commit changes here for step 1
        cs.commit(false);

        if (request.isClone()) {
            ConfigurationUtils.updateCloneConfig();
        }
    }

    public void processKeyPair(
            ConfigurationRequest request,
            SystemCertData certData
            ) throws Exception {

        String tag = certData.getTag();
        logger.debug("SystemConfigService.processKeyPair(" + tag + ")");

        String tokenName = certData.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = request.getToken();
        }

        logger.debug("SystemConfigService: token: " + tokenName);
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        String keytype = certData.getKeyType() != null ? certData.getKeyType() : "rsa";

        String keyalgorithm = certData.getKeyAlgorithm();
        if (keyalgorithm == null) {
            keyalgorithm = keytype.equals("ecc") ? "SHA256withEC" : "SHA256withRSA";
        }

        String signingalgorithm = certData.getSigningAlgorithm() != null ? certData.getSigningAlgorithm() : keyalgorithm;

        cs.putString("preop.cert." + tag + ".keytype", keytype);
        cs.putString("preop.cert." + tag + ".keyalgorithm", keyalgorithm);
        cs.putString("preop.cert." + tag + ".signingalgorithm", signingalgorithm);

        // support injecting SAN into server cert
        if (tag.equals("sslserver") && certData.getServerCertSAN() != null) {
            logger.debug("SystemConfigService: san_server_cert found");
            cs.putString("service.injectSAN", "true");
            cs.putString("service.sslserver.san", certData.getServerCertSAN());

        } else {
            if (tag.equals("sslserver")) {
                logger.debug("SystemConfigService: san_server_cert not found");
            }
        }
        cs.commit(false);

        try {

            logger.debug("SystemConfigService: loading existing key pair from NSS database");
            KeyPair pair = ConfigurationUtils.loadKeyPair(certData.getNickname(), tokenName);

            logger.debug("SystemConfigService: storing key pair into CS.cfg");
            ConfigurationUtils.storeKeyPair(cs, tag, pair);

        } catch (ObjectNotFoundException e) {

            logger.debug("SystemConfigService: key pair not found, generating new key pair");

            KeyPair pair;
            if (keytype.equals("ecc")) {
                String curvename = certData.getKeySize() != null ?
                        certData.getKeySize() : cs.getString("keys.ecc.curve.default");
                cs.putString("preop.cert." + tag + ".curvename.name", curvename);
                pair = ConfigurationUtils.createECCKeyPair(token, curvename, cs, tag);

            } else {
                String keysize = certData.getKeySize() != null ? certData.getKeySize() : cs
                        .getString("keys.rsa.keysize.default");
                cs.putString("preop.cert." + tag + ".keysize.size", keysize);
                pair = ConfigurationUtils.createRSAKeyPair(token, Integer.parseInt(keysize), cs, tag);
            }

            logger.debug("SystemConfigService: storing key pair into CS.cfg");
            ConfigurationUtils.storeKeyPair(cs, tag, pair);
        }
    }

    public Cert processCert(
            ConfigurationRequest request,
            SystemCertData certData) throws Exception {

        String tag = certData.getTag();
        String tokenName = certData.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = request.getToken();
        }

        logger.debug("SystemConfigService.processCert(" + tag + ")");

        String nickname = cs.getString("preop.cert." + tag + ".nickname");
        String dn = cs.getString("preop.cert." + tag + ".dn");
        String subsystem = cs.getString("preop.cert." + tag + ".subsystem");

        Cert cert = new Cert(tokenName, nickname, tag);
        cert.setDN(dn);
        cert.setSubsystem(subsystem);
        cert.setType(cs.getString("preop.cert." + tag + ".type"));

        String fullName;
        if (!CryptoUtil.isInternalToken(tokenName)) {
            fullName = tokenName + ":" + nickname;
        } else {
            fullName = nickname;
        }

        logger.debug("SystemConfigService: loading " + tag + " cert: " + fullName);

        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate x509Cert;
        try {
            x509Cert = cm.findCertByNickname(fullName);
        } catch (ObjectNotFoundException e) {
            logger.warn("SystemConfigService: cert not found: " + fullName);
            x509Cert = null;
        }

        // For external/existing CA case, some/all system certs may be provided.
        // The SSL server cert will always be generated for the current host.

        // For external/standalone KRA/OCSP case, all system certs will be provided.
        // No system certs will be generated including the SSL server cert.

        if (request.isExternal() && "ca".equals(subsystem) && !tag.equals("sslserver") && x509Cert != null
                || request.getStandAlone()
                || request.isExternal() && ("kra".equals(subsystem) || "ocsp".equals(subsystem))) {

            logger.debug("SystemConfigService: loading existing " + tag + " cert");
            byte[] bytes = x509Cert.getEncoded();
            String b64 = CryptoUtil.base64Encode(bytes);
            String certStr = CryptoUtil.normalizeCertStr(b64);
            logger.debug("SystemConfigService: cert: " + certStr);

            cert.setCert(bytes);

            ConfigurationUtils.updateConfig(cs, cert);

            logger.debug("SystemConfigService: loading existing cert request");
            byte[] binRequest = ConfigurationUtils.loadCertRequest(cs, subsystem, tag);
            String b64Request = CryptoUtil.base64Encode(binRequest);

            logger.debug("SystemConfigService: request: " + b64Request);

            cert.setRequest(binRequest);

            // When importing existing self-signed CA certificate, create a
            // certificate record to reserve the serial number. Otherwise it
            // might conflict with system certificates to be created later.
            // Also create the certificate request record for renewals.

            logger.debug("SystemConfigService: subsystem: " + subsystem);
            if (!subsystem.equals("ca")) {
                // not a CA -> done
                return cert;
            }

            // checking whether the cert was generated by the current CA

            logger.debug("SystemConfigService: issuer DN: " + x509Cert.getIssuerDN());

            // getting CA signing cert
            SystemCertData caSigningData = request.getSystemCert("signing");
            String caSigningNickname = caSigningData.getNickname();
            X509Certificate caSigningCert = cm.findCertByNickname(caSigningNickname);
            Principal caSigningDN = caSigningCert.getSubjectDN();

            logger.debug("SystemConfigService: CA signing DN: " + caSigningDN);

            if (!x509Cert.getIssuerDN().equals(caSigningDN)) {
                // cert was issued by an external CA -> done
                return cert;
            }

            logger.debug("SystemConfigService: creating cert record for " + tag + " cert");
            ConfigurationUtils.createCertRecord(cs, cert);

            return cert;
        }

        // create and configure other system certificate
        ConfigurationUtils.configCert(request, null, null, cert);

        String certStr = cs.getString(subsystem + "." + tag + ".cert" );
        cert.setCert(CryptoUtil.base64Decode(certStr));

        logger.debug("SystemConfigService: cert: " + certStr);

        // generate certificate request for the system certificate
        ConfigurationUtils.generateCertRequest(cs, tag, cert);

        return cert;
    }

    private void updateCloneConfiguration(
            ConfigurationRequest request,
            SystemCertData cdata,
            String tag) throws NotInitializedException,
            ObjectNotFoundException, TokenException {

        String tokenName = cdata.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = request.getToken();
        }

        // TODO - some of these parameters may only be valid for RSA
        CryptoManager cryptoManager = CryptoManager.getInstance();
        String nickname;
        if (!CryptoUtil.isInternalToken(tokenName)) {
            logger.debug("SystemConfigService:updateCloneConfiguration: tokenName=" + tokenName);
            nickname = tokenName + ":" + cdata.getNickname();
        } else {
            logger.debug("SystemConfigService:updateCloneConfiguration: tokenName empty; using internal");
            nickname = cdata.getNickname();
        }

        boolean isECC = false;
        String keyType = cdata.getKeyType();

        logger.debug("SystemConfigService:updateCloneConfiguration: keyType: " + keyType);
        if("ecc".equalsIgnoreCase(keyType)) {
            isECC = true;
        }
        X509Certificate cert = cryptoManager.findCertByNickname(nickname);
        PublicKey pubk = cert.getPublicKey();
        byte[] exponent = null;
        byte[] modulus = null;

        if (isECC == false) {
            exponent = CryptoUtil.getPublicExponent(pubk);
            modulus = CryptoUtil.getModulus(pubk);
            cs.putString("preop.cert." + tag + ".pubkey.modulus", CryptoUtil.byte2string(modulus));
            cs.putString("preop.cert." + tag + ".pubkey.exponent", CryptoUtil.byte2string(exponent));
        }

        PrivateKey privk = cryptoManager.findPrivKeyByCert(cert);

        cs.putString("preop.cert." + tag + ".privkey.id", CryptoUtil.encodeKeyID(privk.getUniqueID()));
        cs.putString("preop.cert." + tag + ".keyalgorithm", cdata.getKeyAlgorithm());
        cs.putString("preop.cert." + tag + ".keytype", cdata.getKeyType());
    }

    private void updateConfiguration(ConfigurationRequest data, SystemCertData cdata, String tag) {
        String tokenName = cdata.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = data.getToken();
        }

        if (CryptoUtil.isInternalToken(tokenName)) {
            cs.putString(csSubsystem + ".cert." + tag + ".nickname", cdata.getNickname());
        } else {
            cs.putString(csSubsystem + ".cert." + tag + ".nickname", tokenName +
                    ":" + cdata.getNickname());
        }

        cs.putString(csSubsystem + "." + tag + ".nickname", cdata.getNickname());
        cs.putString(csSubsystem + "." + tag + ".tokenname", StringUtils.defaultString(tokenName));
        cs.putString(csSubsystem + "." + tag + ".dn", cdata.getSubjectDN());
    }

    @Override
    public void backupKeys(KeyBackupRequest request) throws Exception {

        logger.debug("SystemConfigService: backupKeys()");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            if (request.getBackupFile() == null || request.getBackupFile().length() <= 0) {
                //TODO: also check for valid path, perhaps by touching file there
                throw new BadRequestException("Invalid key backup file name");
            }

            if (request.getBackupPassword() == null || request.getBackupPassword().length() < 8) {
                throw new BadRequestException("Key backup password must be at least 8 characters");
            }

            ConfigurationUtils.backupKeys(request.getBackupPassword(), request.getBackupFile());

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    public X509CertImpl createAdminCert(AdminSetupRequest data) throws Exception {

        if (data.getImportAdminCert().equalsIgnoreCase("true")) {

            String cert = data.getAdminCert();
            logger.info("SystemConfigService: Importing admin cert: " + cert);
            // standalone admin cert is already stored into CS.cfg by configuration.py

            String b64 = CryptoUtil.stripCertBrackets(cert.trim());
            b64 = CryptoUtil.normalizeCertStr(b64);
            byte[] b = CryptoUtil.base64Decode(b64);

            return new X509CertImpl(b);
        }

        String adminSubjectDN = data.getAdminSubjectDN();
        cs.putString("preop.cert.admin.dn", adminSubjectDN);

        if (csType.equals("CA")) {

            logger.info("SystemConfigService: Generating admin cert");

            ConfigurationUtils.createAdminCertificate(data.getAdminCertRequest(),
                    data.getAdminCertRequestType(), adminSubjectDN);

            String serialno = cs.getString("preop.admincert.serialno.0");
            ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(ICertificateAuthority.ID);
            ICertificateRepository repo = ca.getCertificateRepository();

            return repo.getX509Certificate(new BigInteger(serialno, 16));
        }

        logger.info("SystemConfigService: Requesting admin cert from CA");

        String type = cs.getString("preop.ca.type", "");
        String ca_hostname = "";
        int ca_port = -1;

        if (type.equals("sdca")) {
            ca_hostname = cs.getString("preop.ca.hostname");
            ca_port = cs.getInteger("preop.ca.httpsport");
        } else {
            ca_hostname = cs.getString("securitydomain.host", "");
            ca_port = cs.getInteger("securitydomain.httpseeport");
        }

        String keyType = data.getAdminKeyType();
        String profileID;

        if ("ecc".equalsIgnoreCase(keyType)) {
            profileID = ECC_INTERNAL_ADMIN_CERT_PROFILE;
        } else { // rsa
            profileID = RSA_INTERNAL_ADMIN_CERT_PROFILE;
        }

        logger.debug("SystemConfigService: profile: " + profileID);

        String b64 = ConfigurationUtils.submitAdminCertRequest(ca_hostname, ca_port,
                profileID, data.getAdminCertRequestType(),
                data.getAdminCertRequest(), adminSubjectDN);

        b64 = CryptoUtil.stripCertBrackets(b64.trim());
        byte[] b = CryptoUtil.base64Decode(b64);

        return new X509CertImpl(b);
    }

    public void createAdminUser(AdminSetupRequest request) throws Exception {

        ConfigurationUtils.createAdmin(request.getAdminUID(), request.getAdminEmail(),
                request.getAdminName(), request.getAdminPassword());

        CMSEngine engine = (CMSEngine) CMS.getCMSEngine();
        engine.reinit(IUGSubsystem.ID);
    }

    public void updateAdminUserCert(AdminSetupRequest request, X509CertImpl adminCert) throws Exception {

        X509CertImpl[] adminCerts = new X509CertImpl[] { adminCert };

        IUGSubsystem ug = (IUGSubsystem) CMS.getSubsystem(IUGSubsystem.ID);
        IUser user = ug.getUser(request.getAdminUID());
        user.setX509Certificates(adminCerts);
        ug.addUserCert(user);
    }

    public void configureDatabase(ConfigurationRequest data) {
        cs.putString("internaldb.ldapconn.host", data.getDsHost());
        cs.putString("internaldb.ldapconn.port", data.getDsPort());
        cs.putString("internaldb.database", data.getDatabase());
        cs.putString("internaldb.basedn", data.getBaseDN());
        cs.putString("internaldb.ldapauth.bindDN", data.getBindDN());
        cs.putBoolean("internaldb.ldapconn.secureConn", data.getSecureConn().equals("true"));
        cs.putString("preop.database.removeData", data.getRemoveData());
        cs.putBoolean("preop.database.createNewDB", data.getCreateNewDB());
        cs.putBoolean("preop.database.setupReplication", data.getSetupReplication());
        cs.putBoolean("preop.database.reindexData", data.getReindexData());
    }

    public void initializeDatabase(ConfigurationRequest data) throws EBaseException {

        if (data.isClone() && data.getSetupReplication()) {
            String masterhost = "";
            String masterport = "";
            String masterbasedn = "";
            String realhostname = "";
            try {
                masterhost = cs.getString("preop.internaldb.master.ldapconn.host", "");
                masterport = cs.getString("preop.internaldb.master.ldapconn.port", "");
                masterbasedn = cs.getString("preop.internaldb.master.basedn", "");
                realhostname = cs.getString("machineName", "");
            } catch (Exception e) {
            }

            if (masterhost.equals(realhostname) && masterport.equals(data.getDsPort())) {
                throw new BadRequestException("Master and clone must not share the same internal database");
            }

            if (!masterbasedn.equals(data.getBaseDN())) {
                throw new BadRequestException("Master and clone should have the same base DN");
            }

            String masterReplicationPort = data.getMasterReplicationPort();
            if ((masterReplicationPort != null) && (!masterReplicationPort.equals(""))) {
                cs.putString("internaldb.ldapconn.masterReplicationPort", masterReplicationPort);
            } else {
                cs.putString("internaldb.ldapconn.masterReplicationPort", masterport);
            }

            String cloneReplicationPort = data.getCloneReplicationPort();
            if ((cloneReplicationPort == null) || (cloneReplicationPort.length() == 0)) {
                cloneReplicationPort = data.getDsPort();
            }
            cs.putString("internaldb.ldapconn.cloneReplicationPort", cloneReplicationPort);

            String replicationSecurity = data.getReplicationSecurity();
            if ((cloneReplicationPort == data.getDsPort()) && (data.getSecureConn().equals("true"))) {
                replicationSecurity = "SSL";
            } else if (replicationSecurity == null) {
                replicationSecurity = "None";
            }
            cs.putString("internaldb.ldapconn.replicationSecurity", replicationSecurity);

            cs.putString("preop.internaldb.replicateSchema", data.getReplicateSchema());
        }

        try {
            /* BZ 430745 create password for replication manager */
            // use user-provided password if specified
            String replicationPassword = data.getReplicationPassword();

            if (StringUtils.isEmpty(replicationPassword)) {
                // generate random password

                JssSubsystem jssSubsystem = (JssSubsystem) CMS.getSubsystem(JssSubsystem.ID);
                SecureRandom random = jssSubsystem.getRandomNumberGenerator();
                replicationPassword = Integer.toString(random.nextInt());
            }

            IPasswordStore psStore = null;
            psStore = CMS.getPasswordStore();
            psStore.putPassword("internaldb", data.getBindpwd());
            if (StringUtils.isEmpty(psStore.getPassword("replicationdb", 0))) {
                psStore.putPassword("replicationdb", replicationPassword);
            }
            psStore.commit();

            ConfigurationUtils.enableUSNPlugin();
            ConfigurationUtils.populateDB();

            cs.putString("preop.internaldb.replicationpwd", replicationPassword);
            cs.putString("preop.database.removeData", "false");
            if (data.getSharedDB()) {
                cs.putString("preop.internaldb.dbuser", data.getSharedDBUserDN());
            }
            cs.commit(false);

            if (data.isClone() && data.getSetupReplication()) {
                ReplicationUtil.setupReplication();
            }

            ConfigurationUtils.populateDBManager();
            ConfigurationUtils.populateVLVIndexes();

        } catch (Exception e) {
            logger.error("Unable to populate database: " + e.getMessage(), e);
            throw new PKIException("Unable to populate database: " + e.getMessage(), e);
        }
    }

    public void reinitSubsystems() throws EBaseException {

        // Enable subsystems after database initialization.
        CMSEngine engine = (CMSEngine) CMS.getCMSEngine();

        SubsystemInfo si = engine.staticSubsystems.get(UGSubsystem.ID);
        si.enabled = true;

        engine.reinit(DBSubsystem.ID);
        engine.reinit(UGSubsystem.ID);
        engine.reinit(AuthSubsystem.ID);
        engine.reinit(AuthzSubsystem.ID);
    }

    public void configureHierarchy(ConfigurationRequest data) {
        if (csType.equals("CA") && !data.isClone()) {
            if (data.getHierarchy().equals("root")) {
                cs.putString("preop.hierarchy.select", "root");
                cs.putString("hierarchy.select", "Root");
                cs.putString("preop.ca.type", "sdca");
            } else if (data.getHierarchy().equals("join")) {
                cs.putString("preop.cert.signing.type", "remote");
                cs.putString("preop.hierarchy.select", "join");
                cs.putString("hierarchy.select", "Subordinate");
            } else {
                throw new BadRequestException("Invalid hierarchy provided");
            }
        }
    }

    public void configureCACertChain(ConfigurationRequest data, String domainXML) {
        if (data.getHierarchy() == null || data.getHierarchy().equals("join")) {
            try {
                String url = data.getIssuingCA();
                if (url.equals("External CA")) {
                    logger.debug("external CA selected");
                    cs.putString("preop.ca.type", "otherca");
                    cs.putString("preop.ca.pkcs7", "");
                    cs.putInteger("preop.ca.certchain.size", 0);
                    if (csType.equals("CA")) {
                        cs.putString("preop.cert.signing.type", "remote");
                    }

                } else {
                    logger.debug("local CA selected");
                    url = url.substring(url.indexOf("https"));
                    cs.putString("preop.ca.url", url);
                    URL urlx = new URL(url);
                    String host = urlx.getHost();
                    int port = urlx.getPort();

                    int admin_port = ConfigurationUtils.getPortFromSecurityDomain(domainXML,
                            host, port, "CA", "SecurePort", "SecureAdminPort");

                    cs.putString("preop.ca.type", "sdca");
                    cs.putString("preop.ca.hostname", host);
                    cs.putInteger("preop.ca.httpsport", port);
                    cs.putInteger("preop.ca.httpsadminport", admin_port);

                    if (!data.isClone() && !data.getSystemCertsImported()) {
                        String certchain = ConfigurationUtils.getCertChain(host, admin_port, "/ca/admin/ca/getCertChain");
                        ConfigurationUtils.importCertChain(certchain, "ca");
                    }

                    if (csType.equals("CA")) {
                        cs.putString("preop.cert.signing.type", "remote");
                        cs.putString("preop.cert.signing.profile","caInstallCACert");
                    }
                }
            } catch (Exception e) {
                throw new PKIException("Error in obtaining certificate chain from issuing CA: " + e);
            }
        }
    }

    private void configureClone(ConfigurationRequest data, String token, String domainXML) throws Exception {

        String value = cs.getString("preop.cert.list");
        String[] certList = value.split(",");

        for (String tag : certList) {
            if (tag.equals("sslserver")) {
                cs.putBoolean("preop.cert." + tag + ".enable", true);
            } else {
                cs.putBoolean("preop.cert." + tag + ".enable", false);
            }
        }

        String cloneUri = data.getCloneUri();
        URL url = new URL(cloneUri);
        String masterHost = url.getHost();
        int masterPort = url.getPort();

        logger.debug("SystemConfigService: validate clone URI: " + url);
        boolean validCloneUri = ConfigurationUtils.isValidCloneURI(domainXML, masterHost, masterPort);

        if (!validCloneUri) {
            throw new BadRequestException(
                    "Clone URI does not match available subsystems: " + url);
        }

        if (csType.equals("CA") && !data.getSystemCertsImported()) {
            logger.debug("SystemConfigService: import certificate chain from master");
            int masterAdminPort = ConfigurationUtils.getPortFromSecurityDomain(domainXML,
                    masterHost, masterPort, "CA", "SecurePort", "SecureAdminPort");

            String certchain = ConfigurationUtils.getCertChain(masterHost, masterAdminPort,
                    "/ca/admin/ca/getCertChain");
            ConfigurationUtils.importCertChain(certchain, "clone");
        }

        logger.debug("SystemConfigService: get configuration entries from master");
        ConfigurationUtils.getConfigEntriesFromMaster();

        if (CryptoUtil.isInternalToken(token)) {
            if (!data.getSystemCertsImported()) {
                logger.debug("SystemConfigService: restore certificates from P12 file");
                String p12File = data.getP12File();
                String p12Pass = data.getP12Password();
                ConfigurationUtils.restoreCertsFromP12(p12File, p12Pass);
            }

        } else {
            logger.debug("SystemConfigService: import certificates from HSM and set permission");
            ConfigurationUtils.importAndSetCertPermissionsFromHSM();
        }

        logger.debug("SystemConfigService: verify certificates");
        ConfigurationUtils.verifySystemCertificates();
    }

    public String configureSecurityDomain(ConfigurationRequest data) throws Exception {

        String domainXML = null;

        String securityDomainType = data.getSecurityDomainType();
        String securityDomainName = data.getSecurityDomainName();

        if (securityDomainType.equals(ConfigurationRequest.NEW_DOMAIN)) {
            configureNewSecurityDomain(data, securityDomainName);
        } else if (securityDomainType.equals(ConfigurationRequest.NEW_SUBDOMAIN)){
            logger.debug("Configuring new subordinate root CA");
            configureNewSecurityDomain(data, data.getSubordinateSecurityDomainName());
            String securityDomainURL = data.getSecurityDomainUri();
            domainXML = logIntoSecurityDomain(data, securityDomainURL);
        } else {
            logger.debug("Joining existing security domain");
            cs.putString("preop.securitydomain.select", "existing");
            cs.putString("securitydomain.select", "existing");
            cs.putString("preop.cert.subsystem.type", "remote");
            cs.putString("preop.cert.subsystem.profile", data.getSystemCertProfileID("subsystem", "caInternalAuthSubsystemCert"));
            String securityDomainURL = data.getSecurityDomainUri();
            domainXML = logIntoSecurityDomain(data, securityDomainURL);
        }
        return domainXML;
    }

    private void configureNewSecurityDomain(ConfigurationRequest data, String securityDomainName) {
        logger.debug("Creating new security domain");
        cs.putString("preop.securitydomain.select", "new");
        cs.putString("securitydomain.select", "new");
        cs.putString("preop.securitydomain.name", securityDomainName);
        cs.putString("securitydomain.name", securityDomainName);
        cs.putString("securitydomain.host", CMS.getEENonSSLHost());
        cs.putString("securitydomain.httpport", CMS.getEENonSSLPort());
        cs.putString("securitydomain.httpsagentport", CMS.getAgentPort());
        cs.putString("securitydomain.httpseeport", CMS.getEESSLPort());
        cs.putString("securitydomain.httpsadminport", CMS.getAdminPort());

        cs.putString("preop.cert.subsystem.type", "local");
        cs.putString("preop.cert.subsystem.profile", "subsystemCert.profile");
    }

    private String logIntoSecurityDomain(ConfigurationRequest data, String securityDomainURL) throws Exception {
        URL secdomainURL;
        String host;
        int port;
        try {
            logger.debug("Resolving security domain URL " + securityDomainURL);
            secdomainURL = new URL(securityDomainURL);
            host = secdomainURL.getHost();
            port = secdomainURL.getPort();
            cs.putString("securitydomain.host", host);
            cs.putInteger("securitydomain.httpsadminport",port);
        } catch (Exception e) {
            logger.error("Failed to resolve security domain URL: " + e.getMessage(), e);
            throw new PKIException("Failed to resolve security domain URL: " + e, e);
        }

        if (!data.getSystemCertsImported()) {
            logger.debug("Getting security domain cert chain");
            String certchain = ConfigurationUtils.getCertChain(host, port, "/ca/admin/ca/getCertChain");
            ConfigurationUtils.importCertChain(certchain, "securitydomain");
        }

        getInstallToken(data, host, port);

        String domainXML = getDomainXML(host, port);

        /* Sleep for a bit to allow security domain session to replicate
         * to other clones.  In the future we can use signed tokens
         * (ticket https://pagure.io/dogtagpki/issue/2831) but we need to
         * be mindful of working with older versions, too.
         *
         * The default sleep time is 5s.
         */
        Long d = data.getSecurityDomainPostLoginSleepSeconds();
        if (null == d || d <= 0)
            d = new Long(5);
        logger.debug("Logged into security domain; sleeping for " + d + "s");
        Thread.sleep(d * 1000);

        return domainXML;
    }

    private String getDomainXML(String host, int port) {
        logger.debug("Getting domain XML");
        String domainXML = null;
        try {
            domainXML = ConfigurationUtils.getDomainXML(host, port, true);
            ConfigurationUtils.getSecurityDomainPorts(domainXML, host, port);
        } catch (Exception e) {
            logger.error("Failed to obtain security domain decriptor from security domain master: " + e.getMessage(), e);
            throw new PKIException("Failed to obtain security domain decriptor from security domain master: " + e, e);
        }
        return domainXML;
    }

    private void getInstallToken(ConfigurationRequest data, String host, int port) {

        logger.debug("Getting installation token from security domain");

        String user = data.getSecurityDomainUser();
        String pass = data.getSecurityDomainPassword();
        String installToken;

        try {
            installToken = ConfigurationUtils.getInstallToken(host, port, user, pass);
        } catch (Exception e) {
            logger.error("Unable to get installation token: " + e.getMessage(), e);
            throw new PKIException("Unable to get installation token: " + e.getMessage(), e);
        }

        if (installToken == null) {
            logger.error("Missing installation token");
            throw new PKIException("Missing installation token");
        }

        CMS.setConfigSDSessionId(installToken);
    }

    public void configureSubsystem(ConfigurationRequest request,
            String token, String domainXML) throws Exception {

        cs.putString("preop.subsystem.name", request.getSubsystemName());

        // is this a clone of another subsystem?
        if (!request.isClone()) {
            cs.putString("preop.subsystem.select", "new");
            cs.putString("subsystem.select", "New");

        } else {
            cs.putString("preop.subsystem.select", "clone");
            cs.putString("subsystem.select", "Clone");
            configureClone(request, token, domainXML);
        }
    }

    public void configureToken(ConfigurationRequest data, String token) {
        cs.putString("preop.module.token", StringUtils.defaultString(token));
    }

    private void validatePin(String pin) throws Exception {

        if (pin == null) {
            throw new BadRequestException("Missing configuration PIN");
        }

        String preopPin = cs.getString("preop.pin");
        if (!preopPin.equals(pin)) {
            throw new BadRequestException("Invalid configuration PIN");
        }
    }

    private void validateRequest(ConfigurationRequest data) throws Exception {

        // validate legal stand-alone PKI subsystems
        if (data.getStandAlone()) {
            // ADD checks for valid types of Stand-alone PKI subsystems here
            // AND to the 'checkStandalonePKI()' Python method of
            // the 'ConfigurationFile' Python class in the Python file called
            // 'pkihelper.py'
            if (!csType.equals("KRA") && !csType.equals("OCSP")) {
                throw new BadRequestException("Stand-alone PKI " + csType + " subsystems are currently NOT supported!");
            }
            if (data.isClone()) {
                throw new BadRequestException("A stand-alone PKI subsystem cannot be a clone");
            }
        }

        // validate security domain settings
        String domainType = data.getSecurityDomainType();
        if (domainType == null) {
            throw new BadRequestException("Security Domain Type not provided");
        }

        if (domainType.equals(ConfigurationRequest.NEW_DOMAIN)) {
            if (!(data.getStandAlone() || csType.equals("CA"))) {
                throw new BadRequestException("New Domain is only valid for stand-alone PKI or CA subsytems");
            }
            if (data.getSecurityDomainName() == null) {
                throw new BadRequestException("Security Domain Name is not provided");
            }

        } else if (domainType.equals(ConfigurationRequest.EXISTING_DOMAIN) ||
                   domainType.equals(ConfigurationRequest.NEW_SUBDOMAIN)) {
            if (data.getStandAlone()) {
                throw new BadRequestException("Existing security domains are not valid for stand-alone PKI subsytems");
            }

            String domainURI = data.getSecurityDomainUri();
            if (domainURI == null) {
                throw new BadRequestException("Existing security domain requested, but no security domain URI provided");
            }

            try {
                new URL(domainURI);
            } catch (MalformedURLException e) {
                throw new BadRequestException("Invalid security domain URI: " + domainURI, e);
            }

            if ((data.getSecurityDomainUser() == null) || (data.getSecurityDomainPassword() == null)) {
                throw new BadRequestException("Security domain user or password not provided");
            }

        } else {
            throw new BadRequestException("Invalid security domain URI provided");
        }

        // validate subordinate CA security domain settings
        if (domainType.equals(ConfigurationRequest.NEW_SUBDOMAIN)) {
            if (StringUtils.isEmpty(data.getSubordinateSecurityDomainName())) {
                throw new BadRequestException("Subordinate CA security domain name not provided");
            }
        }

        if ((data.getSubsystemName() == null) || (data.getSubsystemName().length() ==0)) {
            throw new BadRequestException("Invalid or no subsystem name provided");
        }

        if (data.isClone()) {
            String cloneUri = data.getCloneUri();
            if (cloneUri == null) {
                throw new BadRequestException("Clone selected, but no clone URI provided");
            }
            try {
                URL url = new URL(cloneUri);
                // confirm protocol is https
                if (!"https".equals(url.getProtocol())) {
                    throw new BadRequestException("Clone URI must use HTTPS protocol: " + cloneUri);
                }
            } catch (MalformedURLException e) {
                throw new BadRequestException("Invalid clone URI: " + cloneUri, e);
            }

            if (CryptoUtil.isInternalToken(data.getToken())) {
                if (!data.getSystemCertsImported()) {
                    if (data.getP12File() == null) {
                        throw new BadRequestException("P12 filename not provided");
                    }

                    if (data.getP12Password() == null) {
                        throw new BadRequestException("P12 password not provided");
                    }
                }
            } else {
                if (data.getP12File() != null) {
                    throw new BadRequestException("P12 filename should not be provided since HSM clones must share their HSM master's private keys");
                }

                if (data.getP12Password() != null) {
                    throw new BadRequestException("P12 password should not be provided since HSM clones must share their HSM master's private keys");
                }
            }

        } else {
            data.setClone("false");
        }

        String dsHost = data.getDsHost();
        if (dsHost == null || dsHost.length() == 0) {
            throw new BadRequestException("Internal database host not provided");
        }

        try {
            Integer.parseInt(data.getDsPort());  // check for errors
        } catch (NumberFormatException e) {
            throw new BadRequestException("Internal database port is invalid: " + data.getDsPort(), e);
        }

        String basedn = data.getBaseDN();
        if (basedn == null || basedn.length() == 0) {
            throw new BadRequestException("Internal database basedn not provided");
        }

        String binddn = data.getBindDN();
        if (binddn == null || binddn.length() == 0) {
            throw new BadRequestException("Internal database basedn not provided");
        }

        String database = data.getDatabase();
        if (database == null || database.length() == 0) {
            throw new BadRequestException("Internal database database name not provided");
        }

        String bindpwd = data.getBindpwd();
        if (bindpwd == null || bindpwd.length() == 0) {
            throw new BadRequestException("Internal database database name not provided");
        }

        String masterReplicationPort = data.getMasterReplicationPort();
        if (masterReplicationPort != null && masterReplicationPort.length() > 0) {
            try {
                Integer.parseInt(masterReplicationPort); // check for errors
            } catch (NumberFormatException e) {
                throw new BadRequestException("Master replication port is invalid: " + masterReplicationPort, e);
            }
        }

        String cloneReplicationPort = data.getCloneReplicationPort();
        if (cloneReplicationPort != null && cloneReplicationPort.length() > 0) {
            try {
                Integer.parseInt(cloneReplicationPort); // check for errors
            } catch (NumberFormatException e) {
                throw new BadRequestException("Clone replication port is invalid: " + cloneReplicationPort, e);
            }
        }

        if ((data.getReplicateSchema() != null) && (data.getReplicateSchema().equalsIgnoreCase("false"))) {
            data.setReplicateSchema("false");
        } else {
            data.setReplicateSchema("true");
        }

        if (csType.equals("CA") && (data.getHierarchy() == null)) {
            throw new BadRequestException("Hierarchy is required for CA, not provided");
        }

        if (data.getGenerateServerCert() == null) {
            data.setGenerateServerCert("true");
        }

        if (! data.getGenerateSubsystemCert()) {
            // No subsystem cert to be generated.  All interactions use a shared subsystem cert.
            if (data.getSharedDB() && StringUtils.isEmpty(data.getSharedDBUserDN())) {
                throw new BadRequestException("Shared db user DN not provided");
            }
        } else {
            // if the subsystem cert is not shared, we do not need to worry about sharing the db
            data.setSharedDB("false");
        }

        if (csType.equals("TPS")) {
            if (data.getCaUri() == null) {
                throw new BadRequestException("CA URI not provided");
            }

            if (data.getTksUri() == null) {
                throw new BadRequestException("TKS URI not provided");
            }

            if (data.getEnableServerSideKeyGen().equalsIgnoreCase("true")) {
                if (data.getKraUri() == null) {
                    throw new BadRequestException("KRA URI required if server-side key generation requested");
                }
            }

            if ((data.getAuthdbBaseDN()==null) || data.getAuthdbBaseDN().isEmpty()) {
                throw new BadRequestException("Authentication Database baseDN not provided");
            }
            if ((data.getAuthdbHost()==null) || data.getAuthdbHost().isEmpty()) {
                throw new BadRequestException("Authentication Database hostname not provided");
            }
            if ((data.getAuthdbPort()==null) || data.getAuthdbPort().isEmpty()) {
                throw new BadRequestException("Authentication Database port not provided");
            }
            if ((data.getAuthdbSecureConn()==null) || data.getAuthdbSecureConn().isEmpty()) {
                throw new BadRequestException("Authentication Database secure conn not provided");
            }

            try {
                Integer.parseInt(data.getAuthdbPort()); // check for errors
            } catch (NumberFormatException e) {
                throw new BadRequestException("Authentication Database port is invalid: " + data.getAuthdbPort(), e);
            }

            // TODO check connection with authdb

            if (data.getImportSharedSecret().equalsIgnoreCase("true")) {
                data.setImportSharedSecret("true");
            } else {
                data.setImportSharedSecret("false");
            }
        }
    }
}
