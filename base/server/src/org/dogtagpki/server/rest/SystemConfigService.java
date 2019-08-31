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

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PublicKey;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.AdminSetupResponse;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.DatabaseSetupRequest;
import com.netscape.certsrv.system.DatabaseUserSetupRequest;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.certsrv.system.KeyBackupRequest;
import com.netscape.certsrv.system.SecurityDomainSetupRequest;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.certsrv.system.SystemConfigResource;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.Cert;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cms.servlet.csadmin.SystemCertDataFactory;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author alee
 *
 */
public class SystemConfigService extends PKIService implements SystemConfigResource {

    public final static Logger logger = LoggerFactory.getLogger(SystemConfigService.class);

    public Configurator configurator;

    public EngineConfig cs;
    public String csType;
    public String csSubsystem;
    public String csState;
    public boolean isMasterCA = false;
    public String instanceRoot;

    public SystemConfigService() throws Exception {

        CMSEngine engine = CMS.getCMSEngine();
        cs = engine.getConfig();

        csType = cs.getString("cs.type");
        csSubsystem = csType.toLowerCase();
        csState = cs.getState() + "";

        String domainType = cs.getString("securitydomain.select", "existingdomain");
        if (csType.equals("CA") && domainType.equals("new")) {
            isMasterCA = true;
        }

        instanceRoot = cs.getString("instanceRoot");

        configurator = engine.createConfigurator();
    }

    /* (non-Javadoc)
     * @see com.netscape.cms.servlet.csadmin.SystemConfigurationResource#configure(com.netscape.cms.servlet.csadmin.data.ConfigurationData)
     */
    @Override
    public void configure(ConfigurationRequest request) throws Exception {

        logger.info("SystemConfigService: configuring subsystem");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            logger.debug("SystemConfigService: request: " + request);
            validateRequest(request);

            // configure security domain
            logger.debug("=== Security Domain Configuration ===");
            DomainInfo domainInfo = configurator.configureSecurityDomain(request);

            // configure subsystem
            logger.debug("=== Subsystem Configuration ===");
            configurator.configureSubsystem(request, domainInfo);

            logger.debug("=== Configure CA Cert Chain ===");
            configurator.configureCACertChain(request, domainInfo);

            cs.commit(false);

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

    @Override
    public void setupDatabase(DatabaseSetupRequest request) throws Exception {

        logger.info("SystemConfigService: setting up database");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            configurator.initializeDatabase(request);
            configurator.reinitSubsystems();

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public SystemCertData setupCert(CertificateSetupRequest request) throws Exception {

        String tag = request.getTag();
        logger.info("SystemConfigService: setting up " + tag + " certificate");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            boolean enable = cs.getBoolean("preop.cert." + tag + ".enable", true);
            if (!enable) {
                logger.info("SystemConfigService: " + tag + " certificate is disabled");
                return null;
            }

            SystemCertData certData = request.getSystemCert(tag);

            if (certData == null) {
                logger.error("SystemConfigService: missing certificate: " + tag);
                throw new BadRequestException("Missing certificate: " + tag);
            }

            boolean generateServerCert = !request.getGenerateServerCert().equalsIgnoreCase("false");
            if (!generateServerCert && tag.equals("sslserver")) {
                logger.info("SystemConfigService: not generating " + tag + " certificate");
                updateConfiguration(certData, "sslserver");
                return null;
            }

            boolean generateSubsystemCert = request.getGenerateSubsystemCert();
            if (!generateSubsystemCert && tag.equals("subsystem")) {
                logger.info("SystemConfigService: not generating " + tag + " certificate");

                // update the details for the shared subsystem cert here.
                updateConfiguration(certData, "subsystem");

                // get parameters needed for cloning
                updateCloneConfiguration(certData, "subsystem");
                return null;
            }

            processKeyPair(certData);

            Cert cert = processCert(request, certData);

            String subsystem = cert.getSubsystem();
            configurator.handleCert(cert);

            // make sure to commit changes here for step 1
            cs.commit(false);

            if (tag.equals("signing") && subsystem.equals("ca")) {
                CMSEngine engine = CMS.getCMSEngine();
                engine.reinit(ICertificateAuthority.ID);
            }

            return SystemCertDataFactory.create(cert);

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

        logger.info("SystemConfigService: setting up admin");

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

            configurator.setupAdmin(request, response);

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
    public void setupSecurityDomain(SecurityDomainSetupRequest request) throws Exception {

        logger.info("SystemConfigService: setting up security domain");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            configurator.setupSecurityDomain(request.getSecurityDomainType());

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void setupDatabaseUser(DatabaseUserSetupRequest request) throws Exception {

        logger.info("SystemConfigService: setting up database user");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            configurator.setupDatabaseUser();

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void finalizeConfiguration(FinalizeConfigRequest request) throws Exception {

        logger.info("SystemConfigService: finalizing configuration");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            configurator.finalizeConfiguration(request);

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    public void processKeyPair(SystemCertData certData) throws Exception {

        String tag = certData.getTag();
        logger.debug("SystemConfigService.processKeyPair(" + tag + ")");

        String tokenName = certData.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = cs.getString("preop.module.token", null);
        }

        logger.debug("SystemConfigService: token: " + tokenName);
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        String keytype = cs.getString("preop.cert." + tag + ".keytype");
        String keyalgorithm = cs.getString("preop.cert." + tag + ".keyalgorithm");
        String signingalgorithm = cs.getString("preop.cert." + tag + ".signingalgorithm");

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
            KeyPair pair = configurator.loadKeyPair(certData.getNickname(), tokenName);
            logger.info("SystemConfigService: loaded existing key pair for " + tag + " certificate");

            logger.debug("SystemConfigService: storing key pair into CS.cfg");
            configurator.storeKeyPair(tag, pair);

        } catch (ObjectNotFoundException e) {

            logger.debug("SystemConfigService: key pair not found, generating new key pair");
            logger.info("SystemConfigService: generating new key pair for " + tag + " certificate");

            KeyPair pair;
            if (keytype.equals("ecc")) {
                String curvename = certData.getKeySize() != null ?
                        certData.getKeySize() : cs.getString("keys.ecc.curve.default");
                cs.putString("preop.cert." + tag + ".curvename.name", curvename);
                pair = configurator.createECCKeyPair(token, curvename, tag);

            } else {
                String keysize = certData.getKeySize() != null ? certData.getKeySize() : cs
                        .getString("keys.rsa.keysize.default");
                cs.putString("preop.cert." + tag + ".keysize.size", keysize);
                pair = configurator.createRSAKeyPair(token, Integer.parseInt(keysize), tag);
            }

            logger.debug("SystemConfigService: storing key pair into CS.cfg");
            configurator.storeKeyPair(tag, pair);
        }
    }

    public Cert processCert(
            CertificateSetupRequest request,
            SystemCertData certData) throws Exception {

        String tag = certData.getTag();
        String tokenName = certData.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = cs.getString("preop.module.token", null);
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
            logger.debug("SystemConfigService: cert not found: " + fullName);
            x509Cert = null;
        }

        // For external/existing CA case, some/all system certs may be provided.
        // The SSL server cert will always be generated for the current host.

        // For external/standalone KRA/OCSP case, all system certs will be provided.
        // No system certs will be generated including the SSL server cert.

        if ("ca".equals(subsystem) && request.isExternal() && !tag.equals("sslserver") && x509Cert != null
                || "kra".equals(subsystem) && (request.isExternal() || request.getStandAlone())
                || "ocsp".equals(subsystem) && (request.isExternal()  || request.getStandAlone())) {

            logger.info("SystemConfigService: loading existing " + tag + " certificate");

            byte[] bytes = x509Cert.getEncoded();
            String b64 = CryptoUtil.base64Encode(bytes);
            String certStr = CryptoUtil.normalizeCertStr(b64);
            logger.debug("SystemConfigService: cert: " + certStr);

            cert.setCert(bytes);

            configurator.updateConfig(cert);

            logger.debug("SystemConfigService: loading existing cert request");
            byte[] binRequest = configurator.loadCertRequest(subsystem, tag);
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

            // checking whether the cert was issued by existing CA
            logger.debug("SystemConfigService: issuer DN: " + x509Cert.getIssuerDN());

            String caSigningNickname = cs.getString("ca.signing.nickname");
            X509Certificate caSigningCert = cm.findCertByNickname(caSigningNickname);
            Principal caSigningDN = caSigningCert.getSubjectDN();

            logger.debug("SystemConfigService: CA signing DN: " + caSigningDN);

            if (!x509Cert.getIssuerDN().equals(caSigningDN)) {
                logger.debug("SystemConfigService: cert issued by external CA, don't create record");
                return cert;
            }

            logger.debug("SystemConfigService: cert issued by existing CA, create record");
            configurator.createCertRecord(cert);

            return cert;
        }

        // generate and configure other system certificate
        logger.info("SystemConfigService: generating new " + tag + " certificate");
        configurator.configCert(cert);

        String certStr = cs.getString(subsystem + "." + tag + ".cert" );
        cert.setCert(CryptoUtil.base64Decode(certStr));

        logger.debug("SystemConfigService: cert: " + certStr);

        // generate certificate request for the system certificate
        configurator.generateCertRequest(tag, cert);

        return cert;
    }

    private void updateCloneConfiguration(
            SystemCertData cdata,
            String tag) throws Exception {

        String tokenName = cdata.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = cs.getString("preop.module.token", null);
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
        String keyType = cs.getString("preop.cert." + tag + ".keytype");

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
    }

    private void updateConfiguration(SystemCertData cdata, String tag) throws Exception {

        String tokenName = cdata.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = cs.getString("preop.module.token", null);
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

        logger.info("SystemConfigService: backing up keys into " + request.getBackupFile());

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

            configurator.backupKeys(request.getBackupPassword(), request.getBackupFile());

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
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

        } else if (domainType.equals(ConfigurationRequest.NEW_SUBDOMAIN)) {
            if (!csType.equals("CA")) {
                throw new BadRequestException("New Subdomain is only valid for CA subsytems");
            }

        } else if (domainType.equals(ConfigurationRequest.EXISTING_DOMAIN)) {
            if (data.getStandAlone()) {
                throw new BadRequestException("Existing security domains are not valid for stand-alone PKI subsytems");
            }

        } else {
            throw new BadRequestException("Invalid security domain type: " + domainType);
        }

        if (domainType.equals(ConfigurationRequest.NEW_SUBDOMAIN) ||
                domainType.equals(ConfigurationRequest.EXISTING_DOMAIN)) {

            if (data.getSecurityDomainUri() == null) {
                throw new BadRequestException("Missing security domain URI");
            }

            if (data.getSecurityDomainUser() == null) {
                throw new BadRequestException("Missing security domain user");
            }

            if (data.getSecurityDomainPassword() == null) {
                throw new BadRequestException("Missing security domain password");
            }
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

        } else {
            data.setClone("false");
        }

        if (csType.equals("CA") && (data.getHierarchy() == null)) {
            throw new BadRequestException("Hierarchy is required for CA, not provided");
        }
    }
}
