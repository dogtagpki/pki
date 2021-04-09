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
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.servlet.csadmin.BootstrapProfile;
import com.netscape.cms.servlet.csadmin.Cert;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;
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
    public void importCert(
            X509Key x509key,
            X509CertImpl cert,
            String profileID,
            String[] dnsNames,
            boolean installAdjustValidity,
            String certRequestType,
            byte[] certRequest,
            String subjectName) throws Exception {

        logger.info("CAConfigurator: Importing certificate and request into database");
        logger.info("CAConfigurator: - subject DN: " + cert.getSubjectDN());
        logger.info("CAConfigurator: - issuer DN: " + cert.getIssuerDN());

        CryptoManager cm = CryptoManager.getInstance();

        String caSigningNickname = cs.getString("ca.signing.nickname");
        org.mozilla.jss.crypto.X509Certificate caSigningCert = cm.findCertByNickname(caSigningNickname);
        Principal caSigningDN = caSigningCert.getSubjectDN();

        logger.info("CAConfigurator: - CA signing DN: " + caSigningDN);

        if (!cert.getIssuerDN().equals(caSigningDN)) {
            logger.info("Configurator: Cert issued by external CA, don't import");
            return;
        }

        // When importing existing self-signed CA certificate, create a
        // certificate record to reserve the serial number. Otherwise it
        // might conflict with system certificates to be created later.
        // Also create the certificate request record for renewals.

        CAEngine engine = CAEngine.getInstance();

        X509CertInfo info = cert.getInfo();
        logger.info("CAConfigurator: Cert info:\n" + info);

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");

        IConfigStore profileConfig = engine.createFileConfigStore(instanceRoot + configurationRoot + profileID);
        BootstrapProfile profile = new BootstrapProfile(profileConfig);

        RequestRepository requestRepository = engine.getRequestRepository();
        IRequest req = requestRepository.createRequest("enrollment");

        CertificateExtensions extensions = new CertificateExtensions();

        engine.initCertRequest(
                req,
                profile,
                info,
                x509key,
                dnsNames,
                installAdjustValidity,
                extensions);

        req.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);

        // update the locally created request for renewal
        updateLocalRequest(req, certRequest, certRequestType, subjectName);

        RequestQueue queue = engine.getRequestQueue();
        queue.updateRequest(req);

        CertificateRepository certificateRepository = engine.getCertificateRepository();
        CertRecord certRecord = certificateRepository.createCertRecord(
                req.getRequestId(),
                profile.getProfileIDMapping(),
                cert);
        certificateRepository.addCertificateRecord(certRecord);
    }

    public X509CertImpl createLocalCert(
            String certType,
            String dn,
            String issuerDN,
            String keyAlgorithm,
            KeyPair keyPair,
            X509Key x509key,
            String profileID,
            String[] dnsNames,
            boolean installAdjustValidity,
            String signingAlgorithm,
            String certRequestType,
            byte[] certRequest,
            String subjectName) throws Exception {

        logger.info("CAConfigurator: Creating local certificate");
        logger.info("CAConfigurator: - subject DN: " + dn);
        logger.info("CAConfigurator: - issuer DN: " + issuerDN);
        logger.info("CAConfigurator: - key algorithm: " + keyAlgorithm);

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        CertificateExtensions extensions = new CertificateExtensions();

        X509CertInfo info = ca.createCertInfo(
                dn,
                issuerDN,
                keyAlgorithm,
                x509key,
                certType,
                extensions);
        logger.info("CAConfigurator: Cert info:\n" + info);

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");

        IConfigStore profileConfig = engine.createFileConfigStore(instanceRoot + configurationRoot + profileID);
        BootstrapProfile profile = new BootstrapProfile(profileConfig);

        RequestRepository requestRepository = engine.getRequestRepository();
        IRequest req = requestRepository.createRequest("enrollment");

        engine.initCertRequest(
                req,
                profile,
                info,
                x509key,
                dnsNames,
                installAdjustValidity,
                extensions);

        profile.populate(req, info);

        java.security.PrivateKey signingPrivateKey;
        if (certType.equals("selfsign")) {
            signingPrivateKey = keyPair.getPrivate();
        } else {
            signingPrivateKey = ca.getSigningUnit().getPrivateKey();
        }

        X509CertImpl cert = CryptoUtil.signCert(signingPrivateKey, info, signingAlgorithm);

        req.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);

        // update the locally created request for renewal
        updateLocalRequest(req, certRequest, certRequestType, subjectName);

        RequestQueue queue = engine.getRequestQueue();
        queue.updateRequest(req);

        CertificateRepository certificateRepository = engine.getCertificateRepository();
        CertRecord certRecord = certificateRepository.createCertRecord(
                req.getRequestId(),
                profile.getProfileIDMapping(),
                cert);
        certificateRepository.addCertificateRecord(certRecord);

        return cert;
    }

    @Override
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

        if (clone && tag.equals("sslserver")) {

            // For Cloned CA always use its Master CA to generate the
            // sslserver certificate to avoid any changes which may have
            // been made to the X500Name directory string encoding order.

            String hostname = masterURL.getHost();
            int port = masterURL.getPort();

            return createRemoteCert(hostname, port, profileID, certreq, dnsNames, installToken);

        } else { // certType == "remote"

            // issue subordinate CA signing cert using remote CA signing cert
            return super.createCert(
                    tag,
                    keyPair,
                    certreq,
                    certType,
                    profileID,
                    dnsNames,
                    clone,
                    masterURL,
                    installToken);
        }
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

    public void loadCert(
            String type,
            String tag,
            X509Certificate x509Cert,
            String profileID,
            String[] dnsNames) throws Exception {

        super.loadCert(type, tag, x509Cert, profileID, dnsNames);

        if (type.equals("CA") && tag.equals("signing")) {
            logger.info("CAConfigurator: Initializing CA with existing signing cert");

            CAEngine engine = CAEngine.getInstance();
            CAEngineConfig engineConfig = engine.getConfig();

            CertificateAuthority ca = engine.getCA();
            ca.setConfig(engineConfig.getCAConfig());
            ca.initCertSigningUnit();
        }
    }

    public X509CertImpl createAdminCertificate(AdminSetupRequest request) throws Exception {

        logger.info("CAConfigurator: Generating admin cert");

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String certType = preopConfig.getString("cert.admin.type", "local");

        String dn = preopConfig.getString("cert.admin.dn");
        String issuerDN = preopConfig.getString("cert.signing.dn", "");

        String caSigningKeyType = preopConfig.getString("cert.signing.keytype", "rsa");
        String profileFile = cs.getString("profile.caAdminCert.config");
        String defaultSigningAlgsAllowed = cs.getString(
                "ca.profiles.defaultSigningAlgsAllowed",
                "SHA256withRSA,SHA256withEC,SHA1withDSA");
        String keyAlgorithm = CertUtils.getAdminProfileAlgorithm(
                caSigningKeyType, profileFile, defaultSigningAlgsAllowed);

        KeyPair keyPair = null;
        String certRequest = request.getAdminCertRequest();
        byte[] binRequest = Utils.base64decode(certRequest);

        String certRequestType = request.getAdminCertRequestType();
        String subjectName = request.getAdminSubjectDN();
        X509Key x509key;

        if (certRequestType.equals("crmf")) {
            SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(binRequest);
            subjectName = CryptoUtil.getSubjectName(crmfMsgs);
            x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);

        } else if (certRequestType.equals("pkcs10")) {
            PKCS10 pkcs10 = new PKCS10(binRequest);
            x509key = pkcs10.getSubjectPublicKeyInfo();

        } else {
            throw new Exception("Certificate request type not supported: " + certRequestType);
        }

        if (x509key == null) {
            logger.error("CAConfigurator: Missing certificate public key");
            throw new IOException("Missing certificate public key");
        }

        String profileID = preopConfig.getString("cert.admin.profile");
        logger.debug("CertUtil: profile: " + profileID);

        String[] dnsNames = null;
        boolean installAdjustValidity = false;

        String signingAlgorithm;
        if (certType.equals("selfsign")) {
            signingAlgorithm = preopConfig.getString("cert.signing.keyalgorithm", "SHA256withRSA");
        } else {
            signingAlgorithm = preopConfig.getString("cert.signing.signingalgorithm", "SHA256withRSA");
        }

        return createLocalCert(
                certType,
                dn,
                issuerDN,
                keyAlgorithm,
                keyPair,
                x509key,
                profileID,
                dnsNames,
                installAdjustValidity,
                signingAlgorithm,
                certRequestType,
                binRequest,
                subjectName);
    }
}
