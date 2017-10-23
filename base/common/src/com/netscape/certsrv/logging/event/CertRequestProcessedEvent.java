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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.logging.event;

import java.security.cert.CertificateEncodingException;

import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.SignedAuditEvent;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmsutil.util.Utils;

import netscape.security.x509.X509CertImpl;

public class CertRequestProcessedEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    private final static String LOGGING_PROPERTY =
            "LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED";

    public final static String SIGNED_AUDIT_CERT_REQUEST_REASON = "requestNotes";

    public CertRequestProcessedEvent() {
        super(LOGGING_PROPERTY);
    }

    public static CertRequestProcessedEvent createSuccessEvent(
            String subjectID,
            String requesterID,
            String infoName,
            String infoValue) {

        CertRequestProcessedEvent event = new CertRequestProcessedEvent();

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("ReqID", requesterID);
        event.setAttribute("InfoName", infoName);
        event.setAttribute("InfoValue", infoValue);

        return event;
    }

    public static CertRequestProcessedEvent createSuccessEvent(
            String subjectID,
            String requesterID,
            String infoName,
            X509CertImpl x509cert) {

        CertRequestProcessedEvent event = new CertRequestProcessedEvent();

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("ReqID", requesterID);
        event.setAttribute("CertSerialNum", x509cert.getSerialNumber());

        return event;
    }

    public static CertRequestProcessedEvent createFailureEvent(
            String subjectID,
            String requesterID,
            String infoName,
            String infoValue) {

        CertRequestProcessedEvent event = new CertRequestProcessedEvent();

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.FAILURE);
        event.setAttribute("ReqID", requesterID);
        event.setAttribute("InfoName", infoName);
        event.setAttribute("InfoValue", infoValue);

        return event;
    }

    public static CertRequestProcessedEvent createFailureEvent(
            String subjectID,
            String requesterID,
            String infoName,
            IRequest request) {

        CertRequestProcessedEvent event = new CertRequestProcessedEvent();


        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.FAILURE);
        event.setAttribute("ReqID", requesterID);
        event.setAttribute("InfoName", infoName);
        event.setAttribute("InfoValue", auditInfoValue(request));

        return event;
    }

    /**
     * Signed Audit Log Info Certificate Value
     *
     * This method is called to obtain the certificate from the passed in
     * "X509CertImpl" for a signed audit log message.
     * <P>
     *
     * @param x509cert an X509CertImpl
     * @return cert string containing the certificate
     */
    static String auditInfoCertValue(X509CertImpl x509cert) {

        if (x509cert == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        byte rawData[] = null;

        try {
            rawData = x509cert.getEncoded();
        } catch (CertificateEncodingException e) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        String cert = null;

        // convert "rawData" into "base64Data"
        if (rawData != null) {
            String base64Data = Utils.base64encode(rawData, true).trim();

            // concatenate lines
            cert = base64Data.replace("\r", "").replace("\n", "");
        }

        if (cert != null) {
            cert = cert.trim();

            if (cert.equals("")) {
                return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            } else {
                return cert;
            }
        } else {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }
    }

    /**
     * Signed Audit Log Info Value
     *
     * This method is called to obtain the "reason" for
     * a signed audit log message.
     * <P>
     *
     * @param request the actual request
     * @return reason string containing the signed audit log message reason
     */
    static String auditInfoValue(IRequest request) {

        String reason = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        if (request != null) {
            // overwrite "reason" if and only if "info" != null
            String info =
                    request.getExtDataInString(SIGNED_AUDIT_CERT_REQUEST_REASON);

            if (info != null) {
                reason = info.trim();

                // overwrite "reason" if and only if "reason" is empty
                if (reason.equals("")) {
                    reason = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
                }
            }
        }

        return reason;
    }
}
