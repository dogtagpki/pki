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

import java.security.KeyPair;
import java.security.Principal;

import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.AdminSetupResponse;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.CloneSetupRequest;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.DatabaseSetupRequest;
import com.netscape.certsrv.system.DatabaseUserSetupRequest;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.certsrv.system.SecurityDomainSetupRequest;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.certsrv.system.SystemConfigResource;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.Cert;
import com.netscape.cms.servlet.csadmin.CertInfoProfile;
import com.netscape.cms.servlet.csadmin.CertUtil;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cms.servlet.csadmin.SystemCertDataFactory;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
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

        csType = cs.getType();
        csSubsystem = csType.toLowerCase();
        csState = cs.getState() + "";

        String domainType = cs.getString("securitydomain.select", "existingdomain");
        if (csType.equals("CA") && domainType.equals("new")) {
            isMasterCA = true;
        }

        instanceRoot = cs.getInstanceDir();

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

            // configure security domain
            logger.debug("=== Security Domain Configuration ===");
            configurator.configureSecurityDomain(request);

            logger.debug("=== Configure CA Cert Chain ===");
            configurator.configureCACertChain(request);

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
    public void setupClone(CloneSetupRequest request) throws Exception {

        logger.info("SystemConfigService: setting up clone");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            configurator.setupClone(request);

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
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

            configurator.setupDatabase(request);

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

            SystemCertData certData = request.getSystemCert();

            if (certData == null) {
                logger.error("SystemConfigService: missing certificate: " + tag);
                throw new BadRequestException("Missing certificate: " + tag);
            }

            KeyPair keyPair = processKeyPair(certData);

            Cert cert = processCert(request, keyPair, certData);

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

            X509CertImpl cert = configurator.createAdminCertificate(request);
            String b64cert = Utils.base64encodeSingleLine(cert.getEncoded());
            logger.debug("SystemConfigService: admin cert: " + b64cert);

            configurator.setupAdminUser(request, cert);

            AdminSetupResponse response = new AdminSetupResponse();
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
    public void setupSecurityDomain(SecurityDomainSetupRequest request) throws Exception {

        logger.info("SystemConfigService: setting up security domain");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            configurator.setupSecurityDomain(request);

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

    public KeyPair processKeyPair(SystemCertData certData) throws Exception {

        String tag = certData.getTag();
        logger.debug("SystemConfigService.processKeyPair(" + tag + ")");

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String tokenName = certData.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = preopConfig.getString("module.token", null);
        }

        logger.debug("SystemConfigService: token: " + tokenName);
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        String keytype = preopConfig.getString("cert." + tag + ".keytype");

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

        KeyPair pair;

        try {
            logger.debug("SystemConfigService: loading existing key pair from NSS database");
            pair = configurator.loadKeyPair(certData.getNickname(), tokenName);
            logger.info("SystemConfigService: loaded existing key pair for " + tag + " certificate");

        } catch (ObjectNotFoundException e) {

            logger.debug("SystemConfigService: key pair not found, generating new key pair");
            logger.info("SystemConfigService: generating new key pair for " + tag + " certificate");

            if (keytype.equals("ecc")) {
                String curvename = certData.getKeySize() != null ?
                        certData.getKeySize() : cs.getString("keys.ecc.curve.default");
                preopConfig.putString("cert." + tag + ".curvename.name", curvename);
                pair = configurator.createECCKeyPair(token, curvename, tag);

            } else {
                String keysize = certData.getKeySize() != null ? certData.getKeySize() : cs
                        .getString("keys.rsa.keysize.default");
                preopConfig.putString("cert." + tag + ".keysize.size", keysize);
                pair = configurator.createRSAKeyPair(token, Integer.parseInt(keysize), tag);
            }
        }

        return pair;
    }

    public Cert processCert(
            CertificateSetupRequest request,
            KeyPair keyPair,
            SystemCertData certData) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String tag = certData.getTag();
        String tokenName = certData.getToken();
        if (StringUtils.isEmpty(tokenName)) {
            tokenName = preopConfig.getString("module.token", null);
        }

        logger.debug("SystemConfigService.processCert(" + tag + ")");

        String nickname = preopConfig.getString("cert." + tag + ".nickname");
        String dn = preopConfig.getString("cert." + tag + ".dn");
        String subsystem = preopConfig.getString("cert." + tag + ".subsystem");

        Cert cert = new Cert(tokenName, nickname, tag);
        cert.setDN(dn);
        cert.setSubsystem(subsystem);
        cert.setType(preopConfig.getString("cert." + tag + ".type"));

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

            logger.info("SystemConfigService: Loading existing " + tag + " certificate");

            byte[] bytes = x509Cert.getEncoded();
            String b64 = CryptoUtil.base64Encode(bytes);
            String certStr = CryptoUtil.normalizeCertStr(b64);
            logger.debug("SystemConfigService: cert: " + certStr);

            cert.setCert(bytes);

            cs.commit(false);

            logger.info("SystemConfigService: Loading existing " + tag + " cert request");

            String certreqStr = cs.getString(subsystem + "." + tag + ".certreq");
            logger.debug("SystemConfigService: request: " + certreqStr);

            byte[] certreqBytes = CryptoUtil.base64Decode(certreqStr);
            cert.setRequest(certreqBytes);

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

            CMSEngine engine = CMS.getCMSEngine();
            ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);

            String profileName = preopConfig.getString("cert." + tag + ".profile");
            logger.debug("SystemConfigService: profile: " + profileName);

            String instanceRoot = cs.getInstanceDir();
            String configurationRoot = cs.getString("configurationRoot");
            CertInfoProfile profile = new CertInfoProfile(instanceRoot + configurationRoot + profileName);

            PKCS10 pkcs10 = new PKCS10(certreqBytes);
            X509Key x509key = pkcs10.getSubjectPublicKeyInfo();

            X509CertImpl certImpl = new X509CertImpl(bytes);
            X509CertInfo info = certImpl.getInfo();

            IRequest req = configurator.createRequest(tag, profile, x509key, info);

            req.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, certImpl);
            req.setExtData("cert_request", certreqBytes);
            req.setExtData("cert_request_type", "pkcs10");

            IRequestQueue queue = ca.getRequestQueue();
            queue.updateRequest(req);

            RequestId reqId = req.getRequestId();
            preopConfig.putString("cert." + tag + ".reqId", reqId.toString());

            CertUtil.createCertRecord(req, profile, certImpl);

            return cert;
        }

        // generate and configure other system certificate
        logger.info("SystemConfigService: generating new " + tag + " certificate");
        X509CertImpl certImpl = configurator.configCert(request, keyPair, cert);

        byte[] certBin = certImpl.getEncoded();
        String certStr = CryptoUtil.base64Encode(certBin);
        cert.setCert(certBin);

        String subsystemName = preopConfig.getString("cert." + tag + ".subsystem");
        cs.putString(subsystemName + "." + tag + ".cert", certStr);
        cs.commit(false);

        logger.debug("SystemConfigService: cert: " + certStr);

        // generate certificate request for the system certificate
        configurator.generateCertRequest(tag, keyPair, cert);

        return cert;
    }

    private void validatePin(String pin) throws Exception {

        if (pin == null) {
            throw new BadRequestException("Missing configuration PIN");
        }

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String preopPin = preopConfig.getString("pin");
        if (!preopPin.equals(pin)) {
            throw new BadRequestException("Invalid configuration PIN");
        }
    }
}
