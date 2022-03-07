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

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;

import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attribute;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attributes;
import org.mozilla.jss.netscape.security.pkcs.PKCS9Attribute;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.ca.CASigningUnit;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.servlet.csadmin.BootstrapProfile;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRepository;
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

    public void createRequestRecord(
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
            CertificateExtensions requestExtensions) throws Exception {

        logger.info("CAConfigurator: Creating request record " + request.getRequestId().toHexString());

        CAEngine engine = CAEngine.getInstance();
        RequestRepository repository = engine.getRequestRepository();

        request.setExtData("profile", "true");
        request.setExtData("requestversion", "1.0.0");
        request.setExtData("req_seq_num", "0");

        request.setExtData(EnrollProfile.REQUEST_EXTENSIONS, requestExtensions);

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

        repository.updateRequest(request);
    }

    public void updateRequestRecord(
            Request request,
            X509CertImpl cert) throws Exception {

        logger.info("CAConfigurator: Updating request record " + request.getRequestId().toHexString());
        logger.info("CAConfigurator: - cert serial number: 0x" + cert.getSerialNumber().toString(16));

        CAEngine engine = CAEngine.getInstance();
        RequestRepository repository = engine.getRequestRepository();

        request.setExtData(EnrollProfile.REQUEST_CERTINFO, cert.getInfo());
        request.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);

        request.setRequestStatus(RequestStatus.COMPLETE);

        repository.updateRequest(request);
    }

    public void createCertRecord(X509CertImpl cert, RequestId requestID, String profileID) throws Exception {

        logger.info("CAConfigurator: Creating cert record 0x" + cert.getSerialNumber().toString(16));
        logger.info("CAConfigurator: - subject: " + cert.getSubjectDN());
        logger.info("CAConfigurator: - issuer: " + cert.getIssuerDN());

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();

        CertRecord certRecord = certificateRepository.createCertRecord(
                requestID,
                profileID,
                cert);

        certificateRepository.addCertificateRecord(certRecord);
    }

    public CertificateExtensions createRequestExtensions(PKCS10 pkcs10) throws Exception {

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

        return extensions;
    }

    @Override
    public void importRequest(
            RequestId requestID,
            String profileID,
            String[] dnsNames,
            boolean installAdjustValidity,
            String certRequestType,
            byte[] binCertRequest) throws Exception {

        logger.info("CAConfigurator: Importing " + certRequestType + " request");

        X500Name subjectName;
        X509Key x509key;
        CertificateExtensions requestExtensions;

        if (certRequestType.equals("crmf")) {
            SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(binCertRequest);
            subjectName = CryptoUtil.getSubjectName(crmfMsgs);
            x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);
            requestExtensions = new CertificateExtensions();

        } else if (certRequestType.equals("pkcs10")) {
            PKCS10 pkcs10 = new PKCS10(binCertRequest);
            subjectName = pkcs10.getSubjectName();
            x509key = pkcs10.getSubjectPublicKeyInfo();
            requestExtensions = createRequestExtensions(pkcs10);

        } else {
            throw new Exception("Certificate request type not supported: " + certRequestType);
        }

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");
        String profilePath = instanceRoot + configurationRoot + profileID;

        logger.info("CAConfigurator: Loading " + profilePath);
        CAEngine engine = CAEngine.getInstance();
        IConfigStore profileConfig = engine.createFileConfigStore(profilePath);

        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        Request request = requestRepository.createRequest(requestID, "enrollment");

        createRequestRecord(
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
                requestExtensions);
    }

    public void importCert(
            byte[] binCert,
            RequestId requestID,
            String profileID) throws Exception {

        X509CertImpl cert = new X509CertImpl(binCert);

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");
        String profilePath = instanceRoot + configurationRoot + profileID;
        logger.info("CAConfigurator: Loading " + profilePath);

        CAEngine engine = CAEngine.getInstance();
        IConfigStore profileConfig = engine.createFileConfigStore(profilePath);

        createCertRecord(
                cert,
                requestID,
                profileConfig.getString("profileIDMapping"));

        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        Request request = requestRepository.readRequest(requestID);

        updateRequestRecord(request, cert);
    }

    @Override
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

        logger.info("CAConfigurator: Loading request record " + requestID.toHexString());

        CAEngine engine = CAEngine.getInstance();
        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        Request request = requestRepository.readRequest(requestID);

        CertId certID = createCertID();
        logger.info("CAConfigurator: Creating cert " + certID.toHexString());

        logger.info("CAConfigurator: - subject: " + subjectName);

        if (issuerName == null) { // local (not selfsign) cert

            CAEngineConfig engineConfig = engine.getConfig();
            CAConfig caConfig = engineConfig.getCAConfig();
            IConfigStore caSigningCfg = caConfig.getSubStore("signing");

            // create CA signing unit
            CASigningUnit signingUnit = new CASigningUnit();
            signingUnit.init(caSigningCfg, null);

            X509CertImpl caCertImpl = signingUnit.getCertImpl();
            CertificateSubjectName certSubjectName = caCertImpl.getSubjectObj();

            // use CA's issuer object to preserve DN encoding
            issuerName = (X500Name) certSubjectName.get(CertificateIssuerName.DN_NAME);
            signingPrivateKey = signingUnit.getPrivateKey();
        }

        CertificateIssuerName certIssuerName = new CertificateIssuerName(issuerName);
        logger.info("CAConfigurator: - issuer: " + certIssuerName);

        CertificateExtensions extensions = new CertificateExtensions();

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");
        String profilePath = instanceRoot + configurationRoot + profileID;

        logger.info("CAConfigurator: Loading " + profilePath);
        IConfigStore profileConfig = engine.createFileConfigStore(profilePath);
        BootstrapProfile profile = new BootstrapProfile(profileConfig);

        Date date = new Date();
        X509CertInfo info = CryptoUtil.createX509CertInfo(
                x509key,
                certID.toBigInteger(),
                certIssuerName,
                subjectName,
                date,
                date,
                keyAlgorithm,
                extensions);

        profile.populate(request, info);

        X509CertImpl cert = CryptoUtil.signCert(signingPrivateKey, info, signingAlgorithm);
        logger.info("CAConfigurator: Cert info:\n" + info);

        createCertRecord(
                cert,
                request.getRequestId(),
                profileConfig.getString("profileIDMapping"));

        updateRequestRecord(request, cert);

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
}
