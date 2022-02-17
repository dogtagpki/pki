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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Date;

import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attribute;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attributes;
import org.mozilla.jss.netscape.security.pkcs.PKCS9Attribute;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.servlet.csadmin.BootstrapProfile;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class CAConfigurator extends Configurator {

    public CAConfigurator(CMSEngine engine) {
        super(engine);
    }

    public RequestId createRequestID() throws Exception {
        CAEngine engine = CAEngine.getInstance();
        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        return requestRepository.createRequestID();
    }

    public CertId createCertID() throws Exception {
        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();
        BigInteger serialNumber = certificateRepository.getNextSerialNumber();
        return new CertId(serialNumber);
    }

    public void initRequest(
            Request request,
            String certRequestType,
            byte[] certRequest,
            X500Name subjectName,
            String profileID,
            String profileIDMapping,
            String profileSetIDMapping,
            X509Key x509key,
            String[] sanHostnames,
            boolean installAdjustValidity,
            CertificateExtensions extensions) throws Exception {

        logger.info("CAConfigurator: Initialize cert request " + request.getRequestId().toHexString());

        request.setExtData("profile", "true");
        request.setExtData("requestversion", "1.0.0");
        request.setExtData("req_seq_num", "0");

        request.setExtData(EnrollProfile.REQUEST_EXTENSIONS, extensions);

        request.setExtData("requesttype", "enrollment");
        request.setExtData("requestor_name", "");
        request.setExtData("requestor_email", "");
        request.setExtData("requestor_phone", "");
        request.setExtData("profileRemoteHost", "");
        request.setExtData("profileRemoteAddr", "");
        request.setExtData("requestnotes", "");
        request.setExtData("isencryptioncert", "false");
        request.setExtData("profileapprovedby", "system");

        logger.debug("CAConfigurator: - type: " + certRequestType);
        request.setExtData("cert_request_type", certRequestType);

        if (certRequest != null) {
            String b64CertRequest = CryptoUtil.base64Encode(certRequest);
            String pemCertRequest = CryptoUtil.reqFormat(b64CertRequest);
            logger.debug("CAConfigurator: - request:\n" + pemCertRequest);
            request.setExtData("cert_request", pemCertRequest);
        }

        if (subjectName != null) {
            logger.debug("CAConfigurator: - subject: " + subjectName);
            request.setExtData("subject", subjectName.toString());
        }

        if (sanHostnames != null) {

            logger.info("CAConfigurator: Injecting SAN extension:");

            // Dynamically inject the SubjectAlternativeName extension to a
            // local/self-signed master CA's request for its SSL Server Certificate.
            //
            // Since this information may vary from instance to
            // instance, obtain the necessary information from the
            // 'service.sslserver.san' value(s) in the instance's
            // CS.cfg, process these values converting each item into
            // its individual SubjectAlternativeName components, and
            // inject these values into the local request.

            int i = 0;
            for (String sanHostname : sanHostnames) {
                logger.info("CAConfigurator: - " + sanHostname);
                request.setExtData("req_san_pattern_" + i, sanHostname);
                i++;
            }
        }

        request.setExtData("req_key", x509key.toString());

        String origProfileID = profileID;
        int idx = origProfileID.lastIndexOf('.');
        if (idx > 0) {
            origProfileID = origProfileID.substring(0, idx);
        }

        // store original profile ID in cert request
        request.setExtData("origprofileid", origProfileID);

        // store mapped profile ID for renewal
        request.setExtData("profileid", profileIDMapping);
        request.setExtData("profilesetid", profileSetIDMapping);

        if (installAdjustValidity) {
            // (applies to non-CA-signing cert only)
            // installAdjustValidity tells ValidityDefault to adjust the
            // notAfter value to that of the CA's signing cert if needed
            request.setExtData("installAdjustValidity", "true");
        }
    }

    public void updateRequest(
            Request request,
            X509CertImpl cert) throws Exception {

        request.setExtData(EnrollProfile.REQUEST_CERTINFO, cert.getInfo());
        request.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);

        request.setRequestStatus(RequestStatus.COMPLETE);
    }

    @Override
    public void importCert(
            byte[] binCert,
            String profileID,
            String[] dnsNames,
            boolean installAdjustValidity,
            String certRequestType,
            byte[] binCertRequest,
            X500Name subjectName,
            RequestId requestID) throws Exception {

        // When importing existing self-signed CA certificate, create a
        // certificate record to reserve the serial number. Otherwise it
        // might conflict with system certificates to be created later.
        // Also create the certificate request record for renewals.

        logger.info("CAConfigurator: Parsing " + certRequestType + " request");

        PKCS10 pkcs10 = new PKCS10(binCertRequest);
        X509Key x509key = pkcs10.getSubjectPublicKeyInfo();
        PKCS10Attributes attrs = pkcs10.getAttributes();
        PKCS10Attribute extsAttr = attrs.getAttribute(CertificateExtensions.NAME);

        CertificateExtensions extensions;

        if (extsAttr != null && extsAttr.getAttributeId().equals(PKCS9Attribute.EXTENSION_REQUEST_OID)) {

            Extensions exts = (Extensions) extsAttr.getAttributeValue();

            // convert Extensions into CertificateExtensions
            DerOutputStream os = new DerOutputStream();
            exts.encode(os);
            DerInputStream is = new DerInputStream(os.toByteArray());

            extensions = new CertificateExtensions(is);

        } else {
            extensions = new CertificateExtensions();
        }

        X509CertImpl cert = new X509CertImpl(binCert);
        X509CertInfo info = cert.getInfo();
        logger.info("CAConfigurator: Cert info:\n" + info);

        if (dnsNames != null) {
            logger.info("CAConfigurator: SAN extension: ");
            for (String dnsName : dnsNames) {
                logger.info("CAConfigurator: - " + dnsName);
            }
        }

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");
        String profilePath = instanceRoot + configurationRoot + profileID;
        logger.info("CAConfigurator: Loading " + profilePath);

        CAEngine engine = CAEngine.getInstance();
        IConfigStore profileConfig = engine.createFileConfigStore(profilePath);

        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        Request request = requestRepository.createRequest(requestID, "enrollment");

        initRequest(
                request,
                certRequestType,
                binCertRequest,
                subjectName,
                profileConfig.getString("id"),
                profileConfig.getString("profileIDMapping"),
                profileConfig.getString("profileSetIDMapping"),
                x509key,
                dnsNames,
                installAdjustValidity,
                extensions);

        logger.info("CAConfigurator: Creating request record " + requestID.toHexString());
        logger.info("CAConfigurator: - cert serial number: 0x" + cert.getSerialNumber().toString(16));

        updateRequest(request, cert);

        RequestQueue queue = engine.getRequestQueue();
        queue.updateRequest(request);

        logger.info("CAConfigurator: Creating cert record 0x" + cert.getSerialNumber().toString(16));
        logger.info("CAConfigurator: - subject: " + cert.getSubjectX500Principal());
        logger.info("CAConfigurator: - issuer: " + cert.getIssuerX500Principal());

        CertificateRepository certificateRepository = engine.getCertificateRepository();
        CertRecord certRecord = certificateRepository.createCertRecord(
                request.getRequestId(),
                profileConfig.getString("profileIDMapping"),
                cert);
        certificateRepository.addCertificateRecord(certRecord);
    }

    @Override
    public X509CertImpl createLocalCert(
            String keyAlgorithm,
            X509Key x509key,
            String profileID,
            String[] dnsNames,
            boolean installAdjustValidity,
            PrivateKey signingPrivateKey,
            String signingAlgorithm,
            String certRequestType,
            byte[] certRequest,
            X500Name issuerName,
            X500Name subjectName,
            RequestId requestID) throws Exception {

        logger.info("CAConfigurator: Creating local certificate");

        Date date = new Date();
        CAEngine engine = CAEngine.getInstance();

        CertId certID = createCertID();
        logger.info("CAConfigurator: - serial number: " + certID.toHexString());

        CertificateIssuerName certIssuerName;
        if (issuerName != null) {
            // create new issuer object
            certIssuerName = new CertificateIssuerName(issuerName);
            // signingPrivateKey should be provided by caller

        } else {
            // use CA's issuer object to preserve DN encoding
            CertificateAuthority ca = engine.getCA();
            certIssuerName = ca.getIssuerObj();
            signingPrivateKey = ca.getSigningUnit().getPrivateKey();
        }

        logger.info("CAConfigurator: - subject: " + subjectName);
        logger.info("CAConfigurator: - issuer: " + certIssuerName);

        CertificateExtensions extensions = new CertificateExtensions();

        X509CertInfo info = CryptoUtil.createX509CertInfo(
                x509key,
                certID.toBigInteger(),
                certIssuerName,
                subjectName,
                date,
                date,
                keyAlgorithm,
                extensions);

        logger.info("CAConfigurator: Cert info:\n" + info);

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");

        IConfigStore profileConfig = engine.createFileConfigStore(instanceRoot + configurationRoot + profileID);

        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        Request request = requestRepository.createRequest(requestID, "enrollment");

        initRequest(
                request,
                certRequestType,
                certRequest,
                subjectName,
                profileConfig.getString("id"),
                profileConfig.getString("profileIDMapping"),
                profileConfig.getString("profileSetIDMapping"),
                x509key,
                dnsNames,
                installAdjustValidity,
                extensions);

        logger.info("CAConfigurator: Creating cert " + certID.toHexString());

        BootstrapProfile profile = new BootstrapProfile(profileConfig);
        profile.populate(request, info);
        X509CertImpl cert = CryptoUtil.signCert(signingPrivateKey, info, signingAlgorithm);

        logger.info("CAConfigurator: Creating request record " + requestID.toHexString());
        logger.info("CAConfigurator: - cert serial number: 0x" + cert.getSerialNumber().toString(16));

        updateRequest(request, cert);

        RequestQueue queue = engine.getRequestQueue();
        queue.updateRequest(request);

        logger.info("CAConfigurator: Creating cert record 0x" + cert.getSerialNumber().toString(16));
        logger.info("CAConfigurator: - subject: " + cert.getSubjectX500Principal());
        logger.info("CAConfigurator: - issuer: " + cert.getIssuerX500Principal());

        CertificateRepository certificateRepository = engine.getCertificateRepository();
        CertRecord certRecord = certificateRepository.createCertRecord(
                request.getRequestId(),
                profileConfig.getString("profileIDMapping"),
                cert);
        certificateRepository.addCertificateRecord(certRecord);

        return cert;
    }

    @Override
    public void initSubsystem() throws Exception {

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig engineConfig = engine.getConfig();

        CertificateAuthority ca = engine.getCA();
        ca.setConfig(engineConfig.getCAConfig());
        ca.initCertSigningUnit();
    }

    @Override
    public void createAdminCertificate(SystemCertData certData) throws Exception {

        logger.info("CAConfigurator: Generating admin cert");

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String certRequestType = certData.getRequestType();
        logger.info("CAConfigurator: - request type: " + certRequestType);

        String profileID = certData.getProfile();
        logger.info("CAConfigurator: - profile: " + profileID);

        // cert type is selfsign, local, or remote
        String certType = certData.getType();
        logger.info("CAConfigurator: - cert type: " + certType);

        String subjectDN = certData.getSubjectDN();
        logger.info("CAConfigurator: - subject: " + subjectDN);

        String caSigningKeyType = preopConfig.getString("cert.signing.keytype", "rsa");
        String profileFile = cs.getString("profile.caAdminCert.config");
        String defaultSigningAlgsAllowed = cs.getString(
                "ca.profiles.defaultSigningAlgsAllowed",
                "SHA256withRSA,SHA256withEC");
        String keyAlgorithm = CertUtils.getAdminProfileAlgorithm(
                caSigningKeyType, profileFile, defaultSigningAlgsAllowed);

        KeyPair keyPair = null;
        String certRequest = certData.getRequest();
        byte[] binCertRequest = Utils.base64decode(certRequest);

        X500Name subjectName;
        X509Key x509key;

        if (certRequestType.equals("crmf")) {
            SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(binCertRequest);
            subjectName = CryptoUtil.getSubjectName(crmfMsgs);
            x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);

        } else if (certRequestType.equals("pkcs10")) {
            PKCS10 pkcs10 = new PKCS10(binCertRequest);
            subjectName = pkcs10.getSubjectName();
            x509key = pkcs10.getSubjectPublicKeyInfo();

        } else {
            throw new Exception("Certificate request type not supported: " + certRequestType);
        }

        if (x509key == null) {
            logger.error("CAConfigurator: Missing certificate public key");
            throw new IOException("Missing certificate public key");
        }

        String[] dnsNames = null;
        boolean installAdjustValidity = false;

        X500Name issuerName;
        PrivateKey signingPrivateKey;
        String signingAlgorithm;

        if (certType.equals("selfsign")) {
            issuerName = subjectName;
            signingPrivateKey = keyPair.getPrivate();
            signingAlgorithm = preopConfig.getString("cert.signing.keyalgorithm", "SHA256withRSA");
        } else { // local
            issuerName = null;
            signingPrivateKey = null;
            signingAlgorithm = preopConfig.getString("cert.signing.signingalgorithm", "SHA256withRSA");
        }

        RequestId requestID = createRequestID();
        certData.setRequestID(requestID);

        X509CertImpl certImpl = createLocalCert(
                keyAlgorithm,
                x509key,
                profileID,
                dnsNames,
                installAdjustValidity,
                signingPrivateKey,
                signingAlgorithm,
                certRequestType,
                binCertRequest,
                issuerName,
                subjectName,
                requestID);

        byte[] binCert = certImpl.getEncoded();
        certData.setCert(CryptoUtil.base64Encode(binCert));
    }
}
