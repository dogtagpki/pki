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

import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class CertRequestRepository extends RequestRepository {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRequestRepository.class);

    public CertRequestRepository(DBSubsystem dbSubsystem) throws EBaseException {
        super(dbSubsystem, "(requeststate=*)");
    }

    public void initRequest(
            IRequest request,
            String profileID,
            String profileIDMapping,
            String profileSetIDMapping,
            X509CertInfo info,
            X509Key x509key,
            String[] sanHostnames,
            boolean installAdjustValidity,
            CertificateExtensions extensions) throws Exception {

        logger.info("CertRequestRepository: Initialize cert request " + request.getRequestId());

        request.setExtData("profile", "true");
        request.setExtData("requestversion", "1.0.0");
        request.setExtData("req_seq_num", "0");

        request.setExtData(EnrollProfile.REQUEST_CERTINFO, info);
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

        if (sanHostnames != null) {

            logger.info("CertRequestRepository: Injecting SAN extension:");

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
                logger.info("CertRequestRepository: - " + sanHostname);
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

        request.setRequestStatus(RequestStatus.COMPLETE);
    }

    public void updateRequest(
            IRequest request,
            String certRequestType,
            byte[] certRequest,
            X500Name subjectName,
            X509CertImpl cert) throws Exception {

        logger.info("CertRequestRepository: Updating cert request " + request.getRequestId());

        logger.debug("CertRequestRepository: - type: " + certRequestType);
        request.setExtData("cert_request_type", certRequestType);

        if (certRequest != null) {
            String b64CertRequest = CryptoUtil.base64Encode(certRequest);
            String pemCertRequest = CryptoUtil.reqFormat(b64CertRequest);
            logger.debug("CertRequestRepository: - request:\n" + pemCertRequest);
            request.setExtData("cert_request", pemCertRequest);
        }

        if (subjectName != null) {
            logger.debug("CertRequestRepository: - subject: " + subjectName);
            request.setExtData("subject", subjectName.toString());
        }

        request.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);
    }
}
