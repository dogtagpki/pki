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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.request;

import java.security.SecureRandom;

import org.dogtagpki.util.cert.CRMFUtil;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class CertRequestRepository extends RequestRepository {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRequestRepository.class);

    public CertRequestRepository(
            SecureRandom secureRandom,
            DBSubsystem dbSubsystem) {

        super(secureRandom, dbSubsystem, "(requeststate=*)");
    }

    @Override
    public Request createRequest(RequestId requestID, String requestType) throws EBaseException {

        logger.debug("CertRequestRepository: Creating request " + requestID.toHexString());
        Request request = super.createRequest(requestID, requestType);

        request.setExtData("profile", "true");
        request.setExtData("requestversion", "1.0.0");
        request.setExtData("req_seq_num", "0");
        request.setExtData("requesttype", "enrollment");
        request.setExtData("requestor_name", "");
        request.setExtData("requestor_email", "");
        request.setExtData("requestor_phone", "");
        request.setExtData("profileRemoteHost", "");
        request.setExtData("profileRemoteAddr", "");
        request.setExtData("requestnotes", "");
        request.setExtData("isencryptioncert", "false");
        request.setExtData("profileapprovedby", "system");

        return request;
    }

    public void updateRequest(
            Request request,
            String requestType,
            byte[] binRequest,
            String[] dnsNames) throws Exception {

        logger.debug("CertRequestRepository: Updating request " + request.getRequestId().toHexString());

        logger.debug("CertRequestRepository: - type: " + requestType);
        request.setExtData("cert_request_type", requestType);

        String b64CertRequest = CryptoUtil.base64Encode(binRequest);
        String pemCertRequest = CryptoUtil.reqFormat(b64CertRequest);
        logger.debug("CertRequestRepository: - request:\n" + pemCertRequest);
        request.setExtData("cert_request", pemCertRequest);

        X500Name subjectName;
        X509Key x509key;
        CertificateExtensions requestExtensions;

        if (requestType.equals("crmf")) {
            SEQUENCE crmfMsgs = CRMFUtil.parseCRMFMsgs(binRequest);
            subjectName = CryptoUtil.getSubjectName(crmfMsgs);
            x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);
            requestExtensions = new CertificateExtensions();

        } else if (requestType.equals("pkcs10")) {
            PKCS10 pkcs10 = new PKCS10(binRequest);
            subjectName = pkcs10.getSubjectName();
            x509key = pkcs10.getSubjectPublicKeyInfo();
            requestExtensions = CertUtil.createRequestExtensions(pkcs10);

        } else {
            throw new Exception("Unsupported certificate request type: " + requestType);
        }

        logger.debug("CertRequestRepository: - subject: " + subjectName);
        request.setExtData("subject", subjectName.toString());

        request.setExtData("req_key", x509key.toString());

        request.setExtData(Request.REQUEST_EXTENSIONS, requestExtensions);

        if (dnsNames != null) {

            logger.debug("CertRequestRepository: - DNS names:");

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
            for (String dnsName : dnsNames) {
                logger.debug("CertRequestRepository:   - " + dnsName);
                request.setExtData("req_san_pattern_" + i, dnsName);
                i++;
            }
        }
    }

    public void updateRequest(
            Request request,
            String profileID,
            String profileIDMapping,
            String profileSetIDMapping,
            boolean installAdjustValidity) throws Exception {

        logger.debug("CertRequestRepository: Updating profile for request " + request.getRequestId().toHexString());
        logger.debug("CertRequestRepository: - profile: " + profileID);
        logger.debug("CertRequestRepository: - adjust validity: " + installAdjustValidity);

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

        logger.debug("CertRequestRepository: Updating cert for request " + request.getRequestId().toHexString());
        logger.debug("CertRequestRepository: - cert serial number: 0x" + cert.getSerialNumber().toString(16));

        request.setExtData(Request.REQUEST_CERTINFO, cert.getInfo());
        request.setExtData(Request.REQUEST_ISSUED_CERT, cert);
    }
}
