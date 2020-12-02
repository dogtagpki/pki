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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.Principal;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.servlet.csadmin.Cert;
import com.netscape.cms.servlet.csadmin.CertInfoProfile;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class CAConfigurator extends Configurator {

    public CAConfigurator(CMSEngine engine) {
        super(engine);
    }

    /**
     * Update local cert request with the actual request.
     */
    public void updateLocalRequest(
            IRequest req,
            byte[] certReq,
            String reqType,
            String subjectName
            ) throws Exception {

        logger.info("CAConfigurator: Updating request " + req.getRequestId());

        if (subjectName != null) {
            logger.debug("CAConfigurator: - subject: " + subjectName);
            req.setExtData("subject", subjectName);
            new X500Name(subjectName); // check for errors
        }

        logger.debug("CAConfigurator: - type:\n" + reqType);
        req.setExtData("cert_request_type", reqType);

        if (certReq != null) {
            String b64Certreq = CryptoUtil.base64Encode(certReq);
            String pemCertreq = CryptoUtil.reqFormat(b64Certreq);
            logger.debug("CAConfigurator: - request:\n" + pemCertreq);
            req.setExtData("cert_request", pemCertreq);
        }
    }

    @Override
    public void loadCert(
            String tag,
            byte[] certreq,
            org.mozilla.jss.crypto.X509Certificate x509Cert,
            String profileID,
            String[] dnsNames) throws Exception {

        // checking whether the cert was issued by existing CA
        logger.debug("CAConfigurator: issuer DN: " + x509Cert.getIssuerDN());

        String caSigningNickname = cs.getString("ca.signing.nickname");

        CryptoManager cm = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate caSigningCert = cm.findCertByNickname(caSigningNickname);
        Principal caSigningDN = caSigningCert.getSubjectDN();

        logger.debug("CAConfigurator: CA signing DN: " + caSigningDN);

        if (!x509Cert.getIssuerDN().equals(caSigningDN)) {
            logger.debug("Configurator: cert issued by external CA, don't create record");
            return;
        }

        // When importing existing self-signed CA certificate, create a
        // certificate record to reserve the serial number. Otherwise it
        // might conflict with system certificates to be created later.
        // Also create the certificate request record for renewals.

        logger.debug("CAConfigurator: cert issued by existing CA, create record");

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        IRequestQueue queue = ca.getRequestQueue();

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");

        IConfigStore profileConfig = engine.createFileConfigStore(instanceRoot + configurationRoot + profileID);
        CertInfoProfile profile = new CertInfoProfile(profileConfig);

        PKCS10 pkcs10 = new PKCS10(certreq);
        X509Key x509key = pkcs10.getSubjectPublicKeyInfo();

        byte[] bytes = x509Cert.getEncoded();
        X509CertImpl certImpl = new X509CertImpl(bytes);
        X509CertInfo info = certImpl.getInfo();

        boolean installAdjustValidity = !tag.equals("signing");

        IRequest req = queue.newRequest("enrollment");

        ca.initCertRequest(
                req,
                profile,
                info,
                x509key,
                dnsNames,
                installAdjustValidity);

        req.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, certImpl);

        // update the locally created request for renewal
        updateLocalRequest(req, certreq, "pkcs10", null);
        queue.updateRequest(req);

        ca.createCertRecord(req, profile, certImpl);
    }

    public X509CertImpl createLocalCert(
            String tag,
            KeyPair keyPair,
            String certType,
            String profileID,
            byte[] certreq,
            String[] dnsNames) throws Exception {

        logger.info("CAConfigurator: Creating local " + tag + " certificate");

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String dn = preopConfig.getString("cert." + tag + ".dn");
        logger.debug("CAConfigurator: subject: " + dn);

        String algorithm = preopConfig.getString("cert." + tag + ".keyalgorithm");
        logger.debug("CAConfigurator: algorithm: " + algorithm);

        String issuerDN = preopConfig.getString("cert.signing.dn", "");
        logger.debug("CAConfigurator: issuer DN: " + issuerDN);

        X509Key x509key = CryptoUtil.createX509Key(keyPair.getPublic());

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        java.security.PrivateKey signingPrivateKey;
        String signingAlgorithm;

        logger.debug("CAConfigurator: cert type: " + certType);

        if (certType.equals("selfsign")) {
            signingPrivateKey = keyPair.getPrivate();
            signingAlgorithm = preopConfig.getString("cert.signing.keyalgorithm", "SHA256withRSA");

        } else {
            signingPrivateKey = ca.getSigningUnit().getPrivateKey();
            signingAlgorithm = preopConfig.getString("cert.signing.signingalgorithm", "SHA256withRSA");
        }

        X509CertInfo info = ca.createCertInfo(dn, issuerDN, algorithm, x509key, certType);
        logger.info("CAConfigurator: Cert info:\n" + info);

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");

        IConfigStore profileConfig = engine.createFileConfigStore(instanceRoot + configurationRoot + profileID);
        CertInfoProfile profile = new CertInfoProfile(profileConfig);

        boolean installAdjustValidity = !tag.equals("signing");

        IRequestQueue queue = ca.getRequestQueue();
        IRequest req = queue.newRequest("enrollment");

        ca.initCertRequest(
                req,
                profile,
                info,
                x509key,
                dnsNames,
                installAdjustValidity);

        profile.populate(req, info);

        X509CertImpl cert = CryptoUtil.signCert(signingPrivateKey, info, signingAlgorithm);
        ca.createCertRecord(req, profile, cert);

        req.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);

        // update the locally created request for renewal
        updateLocalRequest(req, certreq, "pkcs10", null);
        queue.updateRequest(req);

        return cert;
    }

    @Override
    public X509CertImpl createCert(
            String tag,
            CertificateSetupRequest request,
            KeyPair keyPair,
            byte[] certreq,
            String certType,
            String profileID,
            String[] dnsNames) throws Exception {

        X509CertImpl certImpl;

        if (request.isClone() && tag.equals("sslserver")) {

            // For Cloned CA always use its Master CA to generate the
            // sslserver certificate to avoid any changes which may have
            // been made to the X500Name directory string encoding order.

            URL masterURL = request.getMasterURL();
            String hostname = masterURL.getHost();
            int port = masterURL.getPort();

            String sessionID = request.getInstallToken().getToken();

            certImpl = createRemoteCert(hostname, port, sessionID, profileID, certreq, dnsNames);

        } else if ("remote".equals(certType)) {
            // issue subordinate CA signing cert using remote CA signing cert
            certImpl = super.createCert(tag, request, keyPair, certreq, certType, profileID, dnsNames);

        } else { // selfsign or local
            // issue other system certs using self-signed or local CA signing cert
            certImpl = createLocalCert(tag, keyPair, certType, profileID, certreq, dnsNames);
        }

        if (tag.equals("subsystem")) {
            logger.debug("CAConfigurator: creating subsystem user");
            setupSubsystemUser(certImpl);
        }

        return certImpl;
    }

    public Cert setupCert(CertificateSetupRequest request) throws Exception {
        Cert cert = super.setupCert(request);

        String type = cs.getType();
        String tag = request.getTag();

        if (type.equals("CA") && tag.equals("signing")) {
            logger.info("CAConfigurator: Initializing CA with signing cert");

            CAEngine engine = CAEngine.getInstance();
            CAEngineConfig engineConfig = engine.getConfig();

            CertificateAuthority ca = engine.getCA();
            ca.setConfig(engineConfig.getCAConfig());
            ca.initCertSigningUnit();
        }

        return cert;
    }

    public X509CertImpl createLocalAdminCert(String certRequest, String certRequestType, String subject) throws Exception {

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
            logger.error("CAConfigurator: Missing admin key");
            throw new IOException("Missing admin key");
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String caType = preopConfig.getString("cert.admin.type", "local");
        String dn = preopConfig.getString("cert.admin.dn");
        String issuerDN = preopConfig.getString("cert.signing.dn", "");

        String caSigningKeyType = preopConfig.getString("cert.signing.keytype", "rsa");
        String profileFile = cs.getString("profile.caAdminCert.config");
        String defaultSigningAlgsAllowed = cs.getString(
                "ca.profiles.defaultSigningAlgsAllowed", "SHA256withRSA,SHA256withEC,SHA1withDSA");
        String keyAlgorithm = CertUtils.getAdminProfileAlgorithm(
                caSigningKeyType, profileFile, defaultSigningAlgsAllowed);

        X509CertInfo info = ca.createCertInfo(dn, issuerDN, keyAlgorithm, x509key, caType);
        logger.info("CAConfigurator: Cert info:\n" + info);

        IRequestQueue queue = ca.getRequestQueue();

        java.security.PrivateKey signingPrivateKey = ca.getSigningUnit().getPrivateKey();
        String signingAlgorithm;

        if (caType.equals("selfsign")) {
            signingAlgorithm = preopConfig.getString("cert.signing.keyalgorithm", "SHA256withRSA");
        } else {
            signingAlgorithm = preopConfig.getString("cert.signing.signingalgorithm", "SHA256withRSA");
        }

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");
        String profileName = preopConfig.getString("cert.admin.profile");
        logger.debug("CertUtil: profile: " + profileName);

        IConfigStore profileConfig = engine.createFileConfigStore(instanceRoot + configurationRoot + profileName);
        CertInfoProfile profile = new CertInfoProfile(profileConfig);

        IRequest req = queue.newRequest("enrollment");

        ca.initCertRequest(
                req,
                profile,
                info,
                x509key,
                null /* sanHostnames */,
                true /* installAdjustValidity */);

        profile.populate(req, info);

        X509CertImpl cert = CryptoUtil.signCert(signingPrivateKey, info, signingAlgorithm);
        ca.createCertRecord(req, profile, cert);

        req.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);

        // update the locally created request for renewal
        updateLocalRequest(req, binRequest, certRequestType, subject);
        queue.updateRequest(req);

        return cert;
    }

    public X509CertImpl createAdminCertificate(AdminSetupRequest request) throws Exception {

        logger.info("CAConfigurator: Generating admin cert");

        return createLocalAdminCert(
                request.getAdminCertRequest(),
                request.getAdminCertRequestType(),
                request.getAdminSubjectDN());
    }
}
