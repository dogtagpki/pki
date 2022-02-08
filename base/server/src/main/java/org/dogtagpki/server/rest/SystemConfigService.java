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

import java.security.Principal;

import javax.ws.rs.POST;
import javax.ws.rs.Path;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author alee
 *
 */
@Path("installer")
public class SystemConfigService extends PKIService {

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

    @POST
    @Path("loadCert")
    public SystemCertData loadCert(CertificateSetupRequest request) throws Exception {

        String tag = request.getTag();
        logger.info("SystemConfigService: Loading existing " + tag + " certificate");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            SystemCertData certData = request.getSystemCert();

            String nickname = certData.getNickname();
            logger.info("SystemConfigService: - nickname: " + nickname);

            String tokenName = certData.getToken();
            logger.info("SystemConfigService: - token: " + tokenName);

            String fullName = nickname;
            if (!CryptoUtil.isInternalToken(tokenName)) {
                fullName = tokenName + ":" + nickname;
            }

            CryptoManager cm = CryptoManager.getInstance();

            String cert = certData.getCert();
            byte[] binCert = Utils.base64decode(cert);
            X509CertImpl certImpl = new X509CertImpl(binCert);
            Principal issuerDN = certImpl.getIssuerDN();
            logger.info("SystemConfigService: - issuer DN: " + issuerDN);

            String caSigningNickname = cs.getString("ca.signing.nickname");
            X509Certificate caSigningCert = cm.findCertByNickname(caSigningNickname);
            Principal caSigningSubjectDN = caSigningCert.getSubjectDN();
            logger.info("SystemConfigService: - signing subject DN: " + caSigningSubjectDN);

            if (!issuerDN.equals(caSigningSubjectDN)) {
                logger.info("SystemConfigService: " + tag + " cert issued by external CA, don't import into database");
                return certData;
            }

            String certRequestType = certData.getRequestType();
            logger.info("SystemConfigService: - request type: " + certRequestType);

            String profileID = certData.getProfile();
            logger.info("SystemConfigService: - profile: " + profileID);

            String[] dnsNames = certData.getDNSNames();
            if (dnsNames != null) {
                logger.info("SystemConfigService: - SAN extension: ");
                for (String dnsName : dnsNames) {
                    logger.info("SystemConfigService:   - " + dnsName);
                }
            }

            String certRequest = certData.getRequest();
            byte[] binCertRequest = Utils.base64decode(certRequest);
            PKCS10 pkcs10 = new PKCS10(binCertRequest);
            X509Key x509key = pkcs10.getSubjectPublicKeyInfo();

            boolean installAdjustValidity = !tag.equals("signing");
            X500Name subjectName = null;

            RequestId requestID = configurator.createRequestID();
            certData.setRequestID(requestID);

            configurator.importCert(
                    x509key,
                    certImpl,
                    profileID,
                    dnsNames,
                    installAdjustValidity,
                    certRequestType,
                    binCertRequest,
                    subjectName,
                    requestID);

            return certData;

        } catch (PKIException e) { // normal response
            logger.error("Unable to load " + tag + " certificate: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Unable to load " + tag + " certificate: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("setupCert")
    public SystemCertData setupCert(CertificateSetupRequest request) throws Exception {

        String tag = request.getTag();
        logger.info("SystemConfigService: setting up " + tag + " certificate");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            return configurator.setupCert(request);

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("initSubsystem")
    public void initSubsystem(CertificateSetupRequest request) throws Exception {

        logger.info("SystemConfigService: Initializing subsystem");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            configurator.initSubsystem();

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("setupAdmin")
    public SystemCertData setupAdmin(CertificateSetupRequest request) throws Exception {

        logger.info("SystemConfigService: setting up admin");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            X509CertImpl cert = configurator.createAdminCertificate(request);

            String b64cert = Utils.base64encodeSingleLine(cert.getEncoded());
            logger.debug("SystemConfigService: admin cert: " + b64cert);

            SystemCertData adminCert = new SystemCertData();
            adminCert.setCert(b64cert);

            return adminCert;

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

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String preopPin = preopConfig.getString("pin");
        if (!preopPin.equals(pin)) {
            throw new BadRequestException("Invalid configuration PIN");
        }
    }
}
